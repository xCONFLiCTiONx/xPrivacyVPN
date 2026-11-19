package com.xconflictionx.xprivacyvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import com.xconflictionx.xprivacyvpn.MainActivity
import com.xconflictionx.xprivacyvpn.R
import com.xconflictionx.xprivacyvpn.config.WireGuardConfig
import com.xconflictionx.xprivacyvpn.dns.ZeroTrustDnsConfig
import com.xconflictionx.xprivacyvpn.dns.ZeroTrustDnsResolver
import com.xconflictionx.xprivacyvpn.packet.PacketAction
import com.xconflictionx.xprivacyvpn.packet.PacketInspector
import com.xconflictionx.xprivacyvpn.wireguard.WireGuardCrypto
import com.xconflictionx.xprivacyvpn.wireguard.WireGuardSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class XPrivacyVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.xconflictionx.xprivacyvpn.START"
        const val ACTION_STOP = "com.xconflictionx.xprivacyvpn.STOP"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "xprivacy_vpn_channel"
        private const val REKEY_AFTER_TIME_MS = 120_000L
        private const val REJECT_AFTER_TIME_MS = 175_000L
        private const val STALE_RX_REHANDSHAKE_MS = 30_000L
        private const val HANDSHAKE_BASE_RETRY_MS = 2_000L
        private const val HANDSHAKE_MAX_BACKOFF_MS = 15_000L
        private const val MAX_PENDING_PACKETS = 32
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val dnsConcurrencyLimiter = Semaphore(16)
    private val pendingOutboundPackets = ConcurrentLinkedQueue<ByteArray>()
    private val isRebindingSocket = AtomicBoolean(false)

    private var tunnelJob: Job? = null
    private var udpRxJob: Job? = null
    private var firewallReloadJob: Job? = null
    private var keepaliveWatchdogJob: Job? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private var tunInterface: ParcelFileDescriptor? = null

    @Volatile
    private var appliedBypassPackages: Set<String> = emptySet()

    @Volatile
    private var appliedTunDnsServers: List<String> = emptyList()


    @Volatile
    private var udpSocket: DatagramSocket? = null

    @Volatile
    private var activeWgSession: WireGuardSession? = null

    @Volatile
    private var activePeerAddress: InetSocketAddress? = null

    @Volatile
    private var activeConfig: WireGuardConfig? = null

    @Volatile
    private var currentPhysicalNetwork: Network? = null

    private var tunOutStream: FileOutputStream? = null
    private val tunWriteLock = Any()
    private val socketSwapLock = Any()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private val hasPhysicalNetwork = AtomicBoolean(true)
    private val unansweredHandshakeCount = AtomicInteger(0)
    private val lastTxEpochMs = AtomicLong(0L)
    private val lastRxEpochMs = AtomicLong(0L)
    private val lastHandshakeAttemptEpochMs = AtomicLong(0L)

    override fun onCreate() {
        super.onCreate()
        registerScreenStateReceiver()
    }

    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action == SERVICE_INTERFACE) {
            ensureTunnelRunning()
        }
        return super.onBind(intent)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                ensureTunnelRunning()
                return START_STICKY
            }
        }
    }

    private fun computeAllowedTunnelPackages(): Set<String> {
        val selectedTunnelPackages = VpnStateManager.resolveEffectiveBypassPackages(applicationContext)
        val pm = applicationContext.packageManager
        val installedPackages = runCatching {
            pm.getInstalledApplications(PackageManager.MATCH_DIRECT_BOOT_AWARE or PackageManager.MATCH_DIRECT_BOOT_UNAWARE)
                .mapNotNull { it.packageName }
                .toSet()
        }.getOrDefault(emptySet())
        return com.xconflictionx.xprivacyvpn.firewall.FirewallManager.buildAllowedPackages(
            selectedPackages = selectedTunnelPackages,
            ownPackage = applicationContext.packageName,
            installedPackages = installedPackages
        )
    }

    /**
     * Computes the DNS servers advertised on Android's TUN interface.
     * When a private LAN DNS server (e.g. AdGuard Home) is configured, advertise ONLY
     * that server on TUN. Advertising public DoH-capable IPs like 1.1.1.1 alongside it causes
     * Android's DnsResolver (in opportunistic Private DNS mode) to auto-upgrade 1.1.1.1 to DoH
     * over QUIC/UDP:443, bypassing xPrivacyVPN's UDP:53 interceptor and breaking Split DNS.
     * ZeroTrustDnsResolver still uses config.dnsServers / DoT / DoH internally as fallbacks.
     */
    private fun computeTunDnsServers(
        ztDns: ZeroTrustDnsConfig,
        config: WireGuardConfig?
    ): List<String> {
        val privateServer = ztDns.privateDnsServer.trim()
        if (privateServer.isNotEmpty()) {
            return listOf(privateServer)
        }
        return (config?.dnsServers ?: emptyList())
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .ifEmpty { ZeroTrustDnsResolver.getSystemDnsServers(applicationContext) }
    }

    private fun ensureTunnelRunning() {
        VpnStateManager.activeVpnService = this
        VpnStateManager.ensureInitialized(applicationContext)
        startForegroundWithNotification("Connecting to Zero Trust...")

        val expectedAllowed = computeAllowedTunnelPackages()
        val currentZtDns = VpnStateManager.state.value.zeroTrustDns
        val expectedTunDns = computeTunDnsServers(currentZtDns, activeConfig)
        if (tunnelJob?.isActive == true &&
            tunInterface != null &&
            appliedBypassPackages == expectedAllowed &&
            appliedTunDnsServers == expectedTunDns
        ) {
            val session = activeWgSession
            val sock = udpSocket
            val peer = activePeerAddress
            if (session != null && sock != null && peer != null && !session.isEstablished) {
                serviceScope.launch(Dispatchers.IO) {
                    triggerHandshakeIfAllowed(session, sock, peer, force = true)
                }
            }
        } else {
            startVpnTunnel()
        }
    }

    /**
     * Immediately rebuilds the TUN interface with the updated disallowed app list when the
     * user toggles any app in the Firewall tab while the VPN is connected.
     * Closes the previous TUN descriptor first so Android's ConnectivityService & netd
     * tear down any existing VPN-bound QUIC/TCP sockets for newly bypassed apps.
     */
    fun onFirewallBypassChanged() {
        firewallReloadJob?.cancel()
        firewallReloadJob = serviceScope.launch {
            delay(150L)
            if (tunnelJob?.isActive == true || tunInterface != null) {
                runCatching { tunInterface?.close() }
                tunInterface = null
                startVpnTunnel()
            }
        }
    }

    /**
     * Called when the underlying physical network (Wi-Fi / 5G) connects or switches.
     * Recreates the protected UDP socket when the physical network changes so packets
     * never stay bound to a dead Wi-Fi or stale cell interface.
     */
    private fun onPhysicalNetworkChanged(newNetwork: Network?, forceSocketRecreate: Boolean) {
        serviceScope.launch {
            VpnStateManager.ensureInitialized(applicationContext)
            ZeroTrustDnsResolver.closePersistentConnections()
            val session = activeWgSession ?: return@launch
            val cfg = activeConfig ?: return@launch

            if (forceSocketRecreate || udpSocket == null || udpSocket?.isClosed == true) {
                rebindUdpSocketAndReceiver(cfg, session)
            } else {
                udpSocket?.let { runCatching { protect(it) } }
            }

            unansweredHandshakeCount.set(0)
            lastHandshakeAttemptEpochMs.set(0L)
            val sock = udpSocket ?: return@launch
            val peer = activePeerAddress ?: return@launch
            triggerHandshakeIfAllowed(session, sock, peer, force = true)
        }
    }

    private fun rebindUdpSocketAndReceiver(config: WireGuardConfig, wgSession: WireGuardSession) {
        val resolvedPeer = runCatching {
            val ztDns = VpnStateManager.state.value.zeroTrustDns
            val ip = ZeroTrustDnsResolver.resolveHostnameToIp(
                context = applicationContext,
                hostname = config.endpointHost,
                config = ztDns,
                vpnService = this@XPrivacyVpnService
            ) ?: config.endpointHost
            InetSocketAddress(InetAddress.getByName(ip), config.endpointPort)
        }.getOrNull()

        synchronized(socketSwapLock) {
            val oldSocket = udpSocket
            udpRxJob?.cancel()

            val newSocket = DatagramSocket()
            protect(newSocket)
            runCatching {
                newSocket.receiveBufferSize = 512 * 1024
                newSocket.sendBufferSize = 512 * 1024
                newSocket.trafficClass = 0x10
            }
            newSocket.soTimeout = 0
            udpSocket = newSocket
            runCatching { oldSocket?.close() }

            if (resolvedPeer != null && !resolvedPeer.isUnresolved) {
                activePeerAddress = resolvedPeer
            }

            udpRxJob = launchUdpReceiverLoop(newSocket, wgSession)
        }
    }

    private fun launchUdpReceiverLoop(
        socket: DatagramSocket,
        wgSession: WireGuardSession
    ): Job = serviceScope.launch(Dispatchers.IO) {
        val rxBuf = ByteArray(65535)
        val decryptedIpBuf = ByteArray(65535)
        val packet = DatagramPacket(rxBuf, rxBuf.size)

        while (isActive && !socket.isClosed) {
            val received = try {
                socket.receive(packet)
                true
            } catch (_: Exception) {
                if (!isActive || socket.isClosed) break
                delay(500L)
                false
            }

            if (!received) continue
            val len = packet.length
            if (len < 4) continue
            val now = System.currentTimeMillis()
            lastRxEpochMs.set(now)
            unansweredHandshakeCount.set(0)
            VpnStateManager.addRxBytes(len)

            val msgType = (rxBuf[0].toInt() and 0xFF) or
                ((rxBuf[1].toInt() and 0xFF) shl 8) or
                ((rxBuf[2].toInt() and 0xFF) shl 16) or
                ((rxBuf[3].toInt() and 0xFF) shl 24)

            when (msgType) {
                2 -> {
                    if (wgSession.processHandshakeResponse(rxBuf, len)) {
                        lastRxEpochMs.set(now)
                        unansweredHandshakeCount.set(0)
                        ZeroTrustDnsResolver.resetPrivateDnsCooldown()
                        VpnStateManager.updateStatus(
                            status = TunnelStatus.CONNECTED,
                            message = "Connected • Handshake Verified (${VpnStateManager.state.value.zeroTrustDns.activeModeSummary()})",
                            handshakeEstablished = true,
                            lastHandshakeMs = wgSession.lastHandshakeEpochMs
                        )
                        val peer = activePeerAddress
                        if (peer != null) {
                            // Send keepalive confirmation
                            val kaBuf = ByteArray(32)
                            val kaLen = wgSession.encryptTransportPacketInto(WireGuardCrypto.EMPTY_BYTES, 0, kaBuf)
                            if (kaLen > 0) {
                                runCatching {
                                    socket.send(DatagramPacket(kaBuf, kaLen, peer))
                                    lastTxEpochMs.set(System.currentTimeMillis())
                                    VpnStateManager.addTxBytes(kaLen)
                                }
                            }
                            startContinuousKeepaliveAndWatchdog(wgSession)
                            // Flush any packets queued during handshake
                            val flushWgBuf = ByteArray(65535)
                            while (true) {
                                val queuedIp = pendingOutboundPackets.poll() ?: break
                                val paddedCap = ((queuedIp.size + 15) / 16) * 16
                                val paddedIn = if (queuedIp.size >= paddedCap) queuedIp else queuedIp.copyOf(paddedCap)
                                val encLen = wgSession.encryptTransportPacketInto(paddedIn, queuedIp.size, flushWgBuf)
                                if (encLen > 0) {
                                    runCatching {
                                        socket.send(DatagramPacket(flushWgBuf, encLen, peer))
                                        lastTxEpochMs.set(System.currentTimeMillis())
                                        VpnStateManager.addTxBytes(encLen)
                                    }
                                }
                            }
                        }
                    }
                }
                4 -> {
                    val plainLen = wgSession.decryptTransportPacketInto(rxBuf, len, decryptedIpBuf)
                    if (plainLen > 0) {
                        val out = tunOutStream
                        if (out != null) {
                            synchronized(tunWriteLock) {
                                runCatching {
                                    out.write(decryptedIpBuf, 0, plainLen)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun registerPhysicalNetworkCallback() {
        unregisterPhysicalNetworkCallback()
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
                val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                    hasPhysicalNetwork.set(true)
                    val oldNetwork = currentPhysicalNetwork
                    currentPhysicalNetwork = network
                    runCatching { setUnderlyingNetworks(arrayOf(network)) }
                    val networkChanged = oldNetwork == null || oldNetwork != network
                    if (networkChanged) {
                        onPhysicalNetworkChanged(network, forceSocketRecreate = true)
                    }
                }

                override fun onLost(network: Network) {
                    if (currentPhysicalNetwork == network) {
                        currentPhysicalNetwork = null
                    }
                }
            }
            cm.registerNetworkCallback(req, callback)
            networkCallback = callback
        }
    }

    private fun unregisterPhysicalNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
        }
    }

    private suspend fun waitForValidWireGuardConfig(): WireGuardConfig {
        while (true) {
            VpnStateManager.ensureInitialized(applicationContext)
            val confText = VpnStateManager.loadWireGuardConfText(applicationContext)
            val parsed = WireGuardConfig.parse(confText).getOrNull()
            if (parsed != null) return parsed

            VpnStateManager.updateStatus(
                status = TunnelStatus.CONNECTING,
                message = "Waiting for device unlock / WireGuard config..."
            )
            delay(2000L)
        }
    }

    private suspend fun resolvePeerSocketAddressWithRetry(
        config: WireGuardConfig,
        ztDns: ZeroTrustDnsConfig
    ): InetSocketAddress {
        while (true) {
            val resolvedAddr = runCatching {
                val ip = ZeroTrustDnsResolver.resolveHostnameToIp(
                    context = applicationContext,
                    hostname = config.endpointHost,
                    config = ztDns,
                    vpnService = this@XPrivacyVpnService
                ) ?: config.endpointHost
                InetSocketAddress(InetAddress.getByName(ip), config.endpointPort)
            }.getOrNull()

            if (resolvedAddr != null && !resolvedAddr.isUnresolved) {
                return resolvedAddr
            }

            VpnStateManager.updateStatus(
                status = TunnelStatus.CONNECTING,
                message = "Waiting for physical network to resolve ${config.endpointHost}..."
            )
            delay(3000L)
        }
    }

    private fun startVpnTunnel() {
        tunnelJob?.cancel()
        registerPhysicalNetworkCallback()

        tunnelJob = serviceScope.launch {
            try {
                VpnStateManager.updateStatus(
                    status = TunnelStatus.CONNECTING,
                    message = "Establishing TUN & WireGuard session..."
                )

                val config = waitForValidWireGuardConfig()
                activeConfig = config
                val ztDns = VpnStateManager.state.value.zeroTrustDns

                runCatching { udpSocket?.close() }
                runCatching { tunInterface?.close() }

                if (ztDns.isPrivateDnsConfigured && !config.routesAddress(ztDns.privateDnsServer)) {
                    throw IllegalStateException("WireGuard AllowedIPs does not include the configured private DNS server.")
                }

                // 1. Build Android VpnService TUN interface
                val builder = Builder()
                    .setSession("xPrivacyVPN Zero Trust")
                    .setMtu(config.mtu)

                for (addr in config.addresses) {
                    runCatching {
                        builder.addAddress(addr.address, addr.prefixLength)
                    }
                }

                val tunDnsList = computeTunDnsServers(ztDns, config)

                for (dns in tunDnsList) {
                    runCatching {
                        builder.addDnsServer(dns)
                    }
                }
                if (ztDns.privateDomain.isNotBlank()) {
                    runCatching {
                        builder.addSearchDomain(ztDns.privateDomain.trim().trim('.'))
                    }
                }

                for (route in config.allowedIps) {
                    runCatching {
                        builder.addRoute(route.address, route.prefixLength)
                    }
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }

                val allowedPackages = computeAllowedTunnelPackages()
                for (pkg in allowedPackages) {
                    runCatching {
                        builder.addAllowedApplication(pkg)
                    }
                }
                appliedBypassPackages = allowedPackages
                appliedTunDnsServers = tunDnsList

                val establishedTun = builder.establish()
                    ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
                tunInterface = establishedTun
                currentPhysicalNetwork?.let { runCatching { setUnderlyingNetworks(arrayOf(it)) } }

                val tunIn = FileInputStream(establishedTun.fileDescriptor)
                val tunOut = FileOutputStream(establishedTun.fileDescriptor)
                tunOutStream = tunOut

                val wgSession = WireGuardSession(config)
                activeWgSession = wgSession

                // 2. Open protected UDP socket & resolve endpoint
                val peerAddress = resolvePeerSocketAddressWithRetry(config, ztDns)
                activePeerAddress = peerAddress
                rebindUdpSocketAndReceiver(config, wgSession)

                // 3. Initiate WireGuard Handshake
                udpSocket?.let { sock ->
                    triggerHandshakeIfAllowed(wgSession, sock, peerAddress, force = true)
                }

                VpnStateManager.updateStatus(
                    status = TunnelStatus.CONNECTED,
                    message = "Connected • Handshaking (${ztDns.activeModeSummary()})",
                    handshakeEstablished = false
                )
                updateNotification("Zero Trust + Filters Active (${VpnStateManager.state.value.filterStats.totalRules} rules)")

                // 4. Continuous keepalive and connection watchdog (maintains 24/7 NAT hole punching & auto-healing)
                startContinuousKeepaliveAndWatchdog(wgSession)

                // 5. Zero-allocation Outbound TUN loop
                // Pre-allocate buffers once for the lifetime of the tunnel to eliminate GC churn
                val tunBuf = ByteArray(65535)
                val wgTxBuf = ByteArray(65535)
                val reusableTxDatagram = DatagramPacket(wgTxBuf, wgTxBuf.size)

                while (isActive) {
                    val readLen = try {
                        tunIn.read(tunBuf)
                    } catch (_: Exception) {
                        -1
                    }
                    if (readLen <= 0) {
                        if (readLen < 0) {
                            if (isActive && tunInterface != null) {
                                delay(500L)
                                throw IllegalStateException("TUN descriptor closed or EOF encountered")
                            }
                            break
                        }
                        continue
                    }

                    val currentState = VpnStateManager.state.value
                    val activeDnsCfg = currentState.zeroTrustDns
                    val forwarderIps = buildSet {
                        addAll(config.dnsServers)
                        if (activeDnsCfg.privateDnsServer.isNotBlank()) add(activeDnsCfg.privateDnsServer.trim())
                        addAll(activeDnsCfg.configuredIpv4List())
                        addAll(activeDnsCfg.configuredIpv6List())
                        add("1.1.1.1")
                        add("1.0.0.1")
                    }
                    val action = PacketInspector.inspectOutboundPacket(
                        packet = tunBuf,
                        length = readLen,
                        filterEngine = VpnStateManager.filterEngine,
                        dnsFilteringEnabled = currentState.dnsFilteringEnabled,
                        deepInspectionEnabled = currentState.deepInspectionEnabled,
                        useNxDomain = currentState.useNxDomain,
                        bypassedPackages = emptySet(),
                        dnsForwarderIps = forwarderIps,
                        dnsForwarderSourcePorts = ZeroTrustDnsResolver.activeUpstreamSourcePorts()
                    )

                    when (action) {
                        is PacketAction.DropAndReply -> {
                            if (action.replyPacket.isNotEmpty()) {
                                synchronized(tunWriteLock) {
                                    runCatching {
                                        tunOut.write(action.replyPacket)
                                    }
                                }
                            }
                            if (action.logEvent) {
                                VpnStateManager.recordTrafficEvent(
                                    target = action.targetHost,
                                    protocol = action.protocol,
                                    blocked = true,
                                    matchedRule = action.decision.matchedRule,
                                    sourceName = action.decision.sourceName
                                )
                            }
                        }
                        is PacketAction.ForwardLogged -> {
                            VpnStateManager.recordTrafficEvent(
                                target = action.targetHost,
                                protocol = action.protocol,
                                blocked = false,
                                matchedRule = action.decision.matchedRule,
                                sourceName = action.decision.sourceName
                            )

                            val dnsPayload = action.dnsQueryPayload
                            if (dnsPayload != null) {
                                val cachedDnsResp = ZeroTrustDnsResolver.getCachedDnsResponse(dnsPayload)
                                if (cachedDnsResp != null) {
                                    val ipUdpReply = PacketInspector.buildDnsReplyFromUpstream(
                                        originalPacket = tunBuf,
                                        length = readLen,
                                        dnsResponsePayload = cachedDnsResp
                                    )
                                    if (ipUdpReply != null) {
                                        synchronized(tunWriteLock) {
                                            runCatching { tunOut.write(ipUdpReply) }
                                        }
                                        VpnStateManager.addRxBytes(ipUdpReply.size)
                                    }
                                } else {
                                    val reqCopy = tunBuf.copyOf(readLen)
                                    val activeDnsCfg = currentState.zeroTrustDns
                                    launch(Dispatchers.IO) {
                                        dnsConcurrencyLimiter.withPermit {
                                            val dnsResp = ZeroTrustDnsResolver.resolveRawDnsQuery(
                                                context = applicationContext,
                                                dnsQueryPayload = dnsPayload,
                                                config = activeDnsCfg,
                                                vpnService = this@XPrivacyVpnService,
                                                wireGuardDnsServers = config.dnsServers
                                            )
                                            if (dnsResp != null) {
                                                val ipUdpReply = PacketInspector.buildDnsReplyFromUpstream(
                                                    originalPacket = reqCopy,
                                                    length = reqCopy.size,
                                                    dnsResponsePayload = dnsResp
                                                )
                                                if (ipUdpReply != null) {
                                                    synchronized(tunWriteLock) {
                                                        runCatching { tunOut.write(ipUdpReply) }
                                                    }
                                                    VpnStateManager.addRxBytes(ipUdpReply.size)
                                                }
                                            } else {
                                                val asyncWgBuf = ByteArray(reqCopy.size + 64)
                                                forwardPacketOverWireGuard(
                                                    wgSession = wgSession,
                                                    ipPacket = reqCopy,
                                                    length = reqCopy.size,
                                                    wgTxBuf = asyncWgBuf,
                                                    txDatagram = null
                                                )
                                            }
                                        }
                                    }
                                }
                            } else {
                                forwardPacketOverWireGuard(
                                    wgSession = wgSession,
                                    ipPacket = tunBuf,
                                    length = readLen,
                                    wgTxBuf = wgTxBuf,
                                    txDatagram = reusableTxDatagram
                                )
                            }
                        }
                        PacketAction.ForwardToWireGuard -> {
                            forwardPacketOverWireGuard(
                                wgSession = wgSession,
                                ipPacket = tunBuf,
                                length = readLen,
                                wgTxBuf = wgTxBuf,
                                txDatagram = reusableTxDatagram
                            )
                        }
                    }
                }

                keepaliveWatchdogJob?.cancel()
                udpRxJob?.cancel()
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Exception) {
                VpnStateManager.updateStatus(
                    status = TunnelStatus.CONNECTING,
                    message = "VPN Reconnecting: ${e.message ?: "Recovering..."}",
                    handshakeEstablished = false
                )
                delay(3000L)
                if (isActive) {
                    startVpnTunnel()
                } else {
                    stopVpnTunnel(resetStatus = false)
                }
            }
        }
    }

    private fun triggerHandshakeIfAllowed(
        wgSession: WireGuardSession,
        socket: DatagramSocket,
        peerAddress: InetSocketAddress,
        force: Boolean = false
    ) {
        if (!hasPhysicalNetwork.get() && !force) return

        val now = System.currentTimeMillis()
        val failures = unansweredHandshakeCount.get()
        // Exponential backoff (4s -> 8s -> 16s -> 30s max) so unreachable networks never spin CPU/radio
        val backoffMs = (HANDSHAKE_BASE_RETRY_MS shl failures.coerceAtMost(3))
            .coerceAtMost(HANDSHAKE_MAX_BACKOFF_MS)

        val prevAttempt = lastHandshakeAttemptEpochMs.get()
        if (!force && now - prevAttempt < backoffMs) return
        if (!lastHandshakeAttemptEpochMs.compareAndSet(prevAttempt, now) && !force) return
        lastHandshakeAttemptEpochMs.set(now)

        val currentFailures = unansweredHandshakeCount.incrementAndGet()
        // If 2 consecutive handshakes went unanswered, recreate the UDP socket asynchronously so we never block the TUN loop
        if (currentFailures >= 2 && activeConfig != null && isRebindingSocket.compareAndSet(false, true)) {
            val cfg = activeConfig!!
            serviceScope.launch(Dispatchers.IO) {
                try {
                    rebindUdpSocketAndReceiver(cfg, wgSession)
                } finally {
                    isRebindingSocket.set(false)
                }
            }
        }
        val activeSock = udpSocket ?: socket

        val targetPeer = activePeerAddress ?: peerAddress
        runCatching {
            protect(activeSock)
            val initPkt = wgSession.createHandshakeInitiation()
            activeSock.send(DatagramPacket(initPkt, initPkt.size, targetPeer))
            lastTxEpochMs.set(now)
            VpnStateManager.addTxBytes(initPkt.size)
        }
    }

    private fun forwardPacketOverWireGuard(
        wgSession: WireGuardSession,
        ipPacket: ByteArray,
        length: Int,
        wgTxBuf: ByteArray,
        txDatagram: DatagramPacket?
    ) {
        val socket = udpSocket ?: return
        val peerAddress = activePeerAddress ?: return
        val now = System.currentTimeMillis()
        val rxAge = now - lastRxEpochMs.get()
        val hsAge = now - wgSession.lastHandshakeEpochMs

        if (!wgSession.isEstablished || hsAge > REJECT_AFTER_TIME_MS) {
            if (pendingOutboundPackets.size >= MAX_PENDING_PACKETS) {
                pendingOutboundPackets.poll()
            }
            pendingOutboundPackets.offer(ipPacket.copyOf(length))
            triggerHandshakeIfAllowed(wgSession, socket, peerAddress, force = hsAge > REJECT_AFTER_TIME_MS)
            return
        }

        if (hsAge > REKEY_AFTER_TIME_MS || (rxAge > STALE_RX_REHANDSHAKE_MS && hsAge > STALE_RX_REHANDSHAKE_MS)) {
            triggerHandshakeIfAllowed(wgSession, socket, peerAddress)
        }

        val encryptedLen = wgSession.encryptTransportPacketInto(ipPacket, length, wgTxBuf)
        if (encryptedLen <= 0) return

        runCatching {
            if (txDatagram != null) {
                txDatagram.setData(wgTxBuf, 0, encryptedLen)
                txDatagram.socketAddress = peerAddress
                socket.send(txDatagram)
            } else {
                socket.send(DatagramPacket(wgTxBuf, encryptedLen, peerAddress))
            }
            lastTxEpochMs.set(now)
            VpnStateManager.addTxBytes(encryptedLen)
        }
    }

    private fun stopVpnTunnel(resetStatus: Boolean = true) {
        unregisterPhysicalNetworkCallback()
        firewallReloadJob?.cancel()
        firewallReloadJob = null
        keepaliveWatchdogJob?.cancel()
        keepaliveWatchdogJob = null
        udpRxJob?.cancel()
        udpRxJob = null
        tunnelJob?.cancel()
        tunnelJob = null
        activeWgSession = null
        activePeerAddress = null
        activeConfig = null
        tunOutStream = null
        appliedBypassPackages = emptySet()
        appliedTunDnsServers = emptyList()
        pendingOutboundPackets.clear()
        ZeroTrustDnsResolver.closePersistentConnections()
        runCatching { udpSocket?.close() }
        udpSocket = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        if (VpnStateManager.activeVpnService === this) {
            VpnStateManager.activeVpnService = null
        }

        VpnStateManager.flushTelemetryNow()
        if (resetStatus) {
            VpnStateManager.updateStatus(
                status = TunnelStatus.DISCONNECTED,
                message = "Disconnected",
                handshakeEstablished = false
            )
        }
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    override fun onRevoke() {
        stopVpnTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        screenStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
            screenStateReceiver = null
        }
        stopVpnTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun registerScreenStateReceiver() {
        if (screenStateReceiver != null) return
        screenStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON,
                    Intent.ACTION_USER_PRESENT -> {
                        VpnStateManager.updateScreenState(true)
                        val sock = udpSocket
                        val peer = activePeerAddress
                        val session = activeWgSession
                        if (sock != null && peer != null && session != null) {
                            serviceScope.launch(Dispatchers.IO) {
                                val now = System.currentTimeMillis()
                                val hsAge = now - session.lastHandshakeEpochMs
                                val rxAge = now - lastRxEpochMs.get()
                                if (!session.isEstablished ||
                                    hsAge > REKEY_AFTER_TIME_MS ||
                                    rxAge > STALE_RX_REHANDSHAKE_MS
                                ) {
                                    unansweredHandshakeCount.set(0)
                                    lastHandshakeAttemptEpochMs.set(0L)
                                    triggerHandshakeIfAllowed(session, sock, peer, force = true)
                                } else if ((activeConfig?.persistentKeepalive ?: 0) > 0) {
                                    sendWireGuardKeepalive(sock, peer, session)
                                }
                            }
                        }
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        VpnStateManager.updateScreenState(false)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        registerReceiver(screenStateReceiver, filter)
    }

    /**
     * Continuous 24/7 keep-alive and connection health watchdog.
     * Maintains router / carrier UDP NAT hole punching every 25 seconds regardless of screen state,
     * and automatically triggers a rehandshake if traffic goes stale or network drops.
     */
    /**
     * Low-overhead recovery. Keepalives are sent only when explicitly requested
     * by the imported profile; otherwise idle traffic does not wake the radio.
     */
    private fun startContinuousKeepaliveAndWatchdog(wgSession: WireGuardSession) {
        keepaliveWatchdogJob?.cancel()
        keepaliveWatchdogJob = serviceScope.launch(Dispatchers.IO) {
            val keepaliveSec = activeConfig?.persistentKeepalive?.takeIf { it > 0 } ?: 0
            while (isActive) {
                val intervalMs = when {
                    !wgSession.isEstablished -> 5_000L
                    keepaliveSec > 0 -> (keepaliveSec * 1000L).coerceAtMost(30_000L)
                    else -> 30_000L
                }
                delay(intervalMs)
                if (!isActive) break

                val sock = udpSocket ?: continue
                val peer = activePeerAddress ?: continue
                val now = System.currentTimeMillis()

                if (wgSession.isEstablished) {
                    val txAge = now - lastTxEpochMs.get()
                    val rxAge = now - lastRxEpochMs.get()
                    val hsAge = now - wgSession.lastHandshakeEpochMs
                    if (keepaliveSec > 0 && txAge >= keepaliveSec * 1000L) {
                        sendWireGuardKeepalive(sock, peer, wgSession)
                    }
                    if (hsAge > REKEY_AFTER_TIME_MS ||
                        (rxAge > STALE_RX_REHANDSHAKE_MS && hsAge > STALE_RX_REHANDSHAKE_MS)
                    ) {
                        triggerHandshakeIfAllowed(wgSession, sock, peer)
                    }
                } else {
                    triggerHandshakeIfAllowed(wgSession, sock, peer)
                }
            }
        }
    }

    private fun sendWireGuardKeepalive(
        sock: DatagramSocket,
        peer: InetSocketAddress,
        session: WireGuardSession
    ) {
        if (!session.isEstablished) return
        val kaBuf = ByteArray(32)
        val kaLen = session.encryptTransportPacketInto(WireGuardCrypto.EMPTY_BYTES, 0, kaBuf)
        if (kaLen > 0) {
            runCatching {
                val kaPacket = DatagramPacket(kaBuf, kaLen, peer)
                sock.send(kaPacket)
                lastTxEpochMs.set(System.currentTimeMillis())
            }
        }
    }

    private fun startForegroundWithNotification(contentText: String) {
        createNotificationChannel()
        val notification = buildNotification(contentText)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
                )
            } catch (_: Exception) {
                runCatching {
                    startForeground(
                        NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    )
                }
            }
        } else {
            runCatching { startForeground(NOTIFICATION_ID, notification) }
        }
    }

    private fun updateNotification(contentText: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIFICATION_ID, buildNotification(contentText))
    }

    private fun buildNotification(contentText: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingOpen = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = Intent(this, XPrivacyVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("xPrivacyVPN • Cloudflare Zero Trust")
            .setContentText(contentText)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingOpen)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Disconnect",
                    pendingStop
                ).build()
            )
            .build()
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "xPrivacyVPN Tunnel Status",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Displays Cloudflare Zero Trust WireGuard & Privacy Filter status"
        }
        nm.createNotificationChannel(channel)
    }
}
