package com.xconflictionx.xprivacyvpn.ui

import android.content.pm.PackageManager
import android.os.Build
import android.util.LruCache
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.LocalFireDepartment
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.xconflictionx.xprivacyvpn.config.WireGuardConfig
import com.xconflictionx.xprivacyvpn.dns.ZeroTrustDnsConfig
import com.xconflictionx.xprivacyvpn.filter.FilterDecision
import com.xconflictionx.xprivacyvpn.filter.FilterSource
import com.xconflictionx.xprivacyvpn.firewall.FirewallManager
import com.xconflictionx.xprivacyvpn.firewall.InstalledAppInfo
import com.xconflictionx.xprivacyvpn.security.DeviceSecurityReport
import com.xconflictionx.xprivacyvpn.security.XSecuritySyncResult
import com.xconflictionx.xprivacyvpn.vpn.TrafficLogEntry
import com.xconflictionx.xprivacyvpn.vpn.TunnelStatus
import com.xconflictionx.xprivacyvpn.vpn.VpnRuntimeState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val appIconCache = LruCache<String, ImageBitmap>(256)

private val CyberDarkScheme = darkColorScheme(
    primary = Color(0xFF00E5A3),
    onPrimary = Color(0xFF041F16),
    secondary = Color(0xFF38BDF8),
    background = Color(0xFF0A0E17),
    surface = Color(0xFF131B2E),
    surfaceVariant = Color(0xFF1C2742),
    onBackground = Color(0xFFE2E8F0),
    onSurface = Color(0xFFE2E8F0),
    error = Color(0xFFEF4444)
)

@Composable
fun XPrivacyVpnApp(
    viewModel: MainViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onImportFilterFiles: () -> Unit,
    onImportWgConfFile: () -> Unit,
    onExportSettingsBackup: () -> Unit,
    onImportSettingsBackup: () -> Unit,
    onRequestDisableBatteryOptimization: () -> Unit,
    onOpenBatteryOptimizationList: () -> Unit,
    onRequestVpnPermissionOnly: () -> Unit,
    onRequestNotificationPermissionOnly: () -> Unit,
    onOpenAppDetailsSettings: () -> Unit
) {
    val vpnState by viewModel.vpnState.collectAsState()
    val filterSources by viewModel.filterSources.collectAsState()
    val wgConfText by viewModel.wgConfText.collectAsState()
    val ztDnsDraft by viewModel.ztDnsDraft.collectAsState()
    val banner by viewModel.statusBanner.collectAsState()
    val isSyncing by viewModel.isSyncingFilters.collectAsState()
    val permissionStatus by viewModel.permissionStatus.collectAsState()
    val installedApps by viewModel.installedApps.collectAsState()
    val isLoadingApps by viewModel.isLoadingApps.collectAsState()
    val xSecurityDomain by viewModel.xSecurityDomain.collectAsState()
    val xSecurityApiKey by viewModel.xSecurityApiKey.collectAsState()
    val deviceSecurityReport by viewModel.deviceSecurityReport.collectAsState()
    val xSecuritySyncResult by viewModel.xSecuritySyncResult.collectAsState()
    val isSyncingSecurity by viewModel.isSyncingSecurity.collectAsState()
    val context = LocalContext.current

    var selectedTab by remember { mutableIntStateOf(0) }

    MaterialTheme(colorScheme = CyberDarkScheme) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            bottomBar = {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface
                ) {
                    NavigationBarItem(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        icon = { Icon(Icons.Default.Shield, contentDescription = "Home") },
                        label = { Text("Home", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        icon = { Icon(Icons.Default.Security, contentDescription = "Filters") },
                        label = { Text("Filters", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 2,
                        onClick = { selectedTab = 2 },
                        icon = { Icon(Icons.Default.LocalFireDepartment, contentDescription = "Firewall") },
                        label = { Text("Firewall", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 3,
                        onClick = { selectedTab = 3 },
                        icon = { Icon(Icons.Default.SettingsEthernet, contentDescription = "Tunnel") },
                        label = { Text("Tunnel", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 4,
                        onClick = {
                            viewModel.refreshDeviceSecurityReport()
                            selectedTab = 4
                        },
                        icon = { Icon(Icons.Default.Lock, contentDescription = "Security") },
                        label = { Text("Security", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 5,
                        onClick = { selectedTab = 5 },
                        icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                        label = { Text("Settings", fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    )
                }
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (banner != null) {
                    Surface(
                        color = Color(0xFF1E3A5F),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { viewModel.dismissBanner() }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = banner.orEmpty(),
                                color = Color.White,
                                fontSize = 13.sp,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                text = "Dismiss",
                                color = MaterialTheme.colorScheme.primary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                when (selectedTab) {
                    0 -> DashboardScreen(
                        state = vpnState,
                        permissionStatus = permissionStatus,
                        onToggleConnect = {
                            val isActive = vpnState.status == TunnelStatus.CONNECTED ||
                                vpnState.status == TunnelStatus.CONNECTING
                            if (!isActive && !viewModel.hasValidWgConfig()) {
                                viewModel.showBanner("Please import or paste your WireGuard .conf file first.")
                                selectedTab = 3
                            } else {
                                onToggleVpn(!isActive)
                            }
                        },
                        onGoToSettings = { selectedTab = 5 },
                        onGoToWgConf = { selectedTab = 3 },
                        onGoToFirewall = { selectedTab = 2 }
                    )
                    1 -> FiltersScreen(
                        state = vpnState,
                        sources = filterSources,
                        isSyncing = isSyncing,
                        onImportFiles = onImportFilterFiles,
                        onAddUrls = { urlsText -> viewModel.addRemoteFilterUrls(urlsText) },
                        onRefreshRemote = { viewModel.refreshAllRemoteFilters() },
                        onAddCustomRule = { rule -> viewModel.addCustomRule(rule) },
                        onToggleSource = { id, enabled -> viewModel.toggleFilterSource(id, enabled) },
                        onDeleteSource = { id -> viewModel.deleteFilterSource(id) },
                        onTestQuery = { q -> viewModel.testFilterQuery(q) }
                    )
                    2 -> FirewallScreen(
                        state = vpnState,
                        installedApps = installedApps,
                        isLoadingApps = isLoadingApps,
                        onRefreshApps = { viewModel.refreshInstalledApps() },
                        onToggleAppBypass = { app, shouldBypass -> viewModel.toggleAppBypass(app, shouldBypass) },
                        onClearAllBypassed = { viewModel.clearAllBypassedApps() }
                    )
                    3 -> WireGuardAndDnsScreen(
                        confText = wgConfText,
                        ztDnsDraft = ztDnsDraft,
                        activeZtDns = vpnState.zeroTrustDns,
                        onConfTextChange = { viewModel.updateWgConfDraft(it) },
                        onSaveConf = { viewModel.saveWgConf(wgConfText) },
                        onImportConfFile = onImportWgConfFile,
                        onClearConf = { viewModel.clearWgConf() },
                        onZtDnsChange = { viewModel.updateZtDnsDraft(it) },
                        onSaveZtDns = { viewModel.saveZtDnsConfig() },
                        onResetZtDns = { viewModel.resetZtDnsToSystemDefault() },
                        onClearDnsCache = { viewModel.clearDnsCache() },
                        onLoadDefaultStaticWarp = { viewModel.loadDefaultStaticWarpConfig() },
                        onExportConfigFile = { viewModel.exportConfigFile() }
                    )
                    4 -> SecurityScreen(
                        report = deviceSecurityReport,
                        syncResult = xSecuritySyncResult,
                        domain = xSecurityDomain,
                        hasApiKey = xSecurityApiKey.isNotBlank(),
                        isSyncing = isSyncingSecurity,
                        onRefreshChecks = { viewModel.refreshDeviceSecurityReport() },
                        onSyncToXServer = { viewModel.syncDeviceSecurityToXServer() },
                        onGoToSettings = { selectedTab = 5 }
                    )
                    5 -> SettingsScreen(
                        state = vpnState,
                        permissionStatus = permissionStatus,
                        xSecurityDomain = xSecurityDomain,
                        xSecurityApiKey = xSecurityApiKey,
                        onSaveXSecuritySettings = { dom, key -> viewModel.saveXSecuritySettings(dom, key) },
                        onExportSettingsBackup = onExportSettingsBackup,
                        onImportSettingsBackup = onImportSettingsBackup,
                        onClearLogs = { viewModel.clearTrafficLogs() },
                        onChangeFilterSettings = { dns, deep, nx, boot ->
                            viewModel.setFilterSettings(dns, deep, nx, boot)
                        },
                        onRequestDisableBatteryOptimization = onRequestDisableBatteryOptimization,
                        onOpenBatteryOptimizationList = onOpenBatteryOptimizationList,
                        onRequestVpnPermissionOnly = onRequestVpnPermissionOnly,
                        onRequestNotificationPermissionOnly = onRequestNotificationPermissionOnly,
                        onOpenAppDetailsSettings = onOpenAppDetailsSettings
                    )
                }
            }
        }
    }
}

@Composable
private fun DashboardScreen(
    state: VpnRuntimeState,
    permissionStatus: SystemPermissionStatus,
    onToggleConnect: () -> Unit,
    onGoToSettings: () -> Unit,
    onGoToWgConf: () -> Unit,
    onGoToFirewall: () -> Unit
) {
    val isConnected = state.status == TunnelStatus.CONNECTED
    val isConnecting = state.status == TunnelStatus.CONNECTING
    val ringColor by animateColorAsState(
        targetValue = when (state.status) {
            TunnelStatus.CONNECTED -> Color(0xFF00E5A3)
            TunnelStatus.CONNECTING -> Color(0xFFF59E0B)
            TunnelStatus.ERROR -> Color(0xFFEF4444)
            TunnelStatus.DISCONNECTED -> Color(0xFF334155)
        },
        label = "ringColor"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "xPrivacyVPN • Zero Trust",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White
        )
        Text(
            text = "Cloudflare WireGuard Tunnel + Local Ad & Tracker Firewall",
            fontSize = 13.sp,
            color = Color(0xFF94A3B8)
        )

        if (!permissionStatus.batteryOptimizationIgnored) {
            Spacer(modifier = Modifier.height(12.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF2B2111)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onGoToSettings() }
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = Color(0xFFF59E0B),
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "Battery optimization is active. Tap here to disable it in Settings.",
                        fontSize = 12.sp,
                        color = Color(0xFFFDE68A),
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // Main Connect Shield Button
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(168.dp)
                .clip(CircleShape)
                .background(Color(0xFF131B2E))
                .border(4.dp, ringColor, CircleShape)
                .clickable { onToggleConnect() }
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = "Connect or Disconnect",
                    tint = ringColor,
                    modifier = Modifier.size(56.dp)
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = when {
                        isConnected -> "CONNECTED"
                        isConnecting -> "CONNECTING..."
                        else -> "TAP TO CONNECT"
                    },
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = ringColor
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = state.statusMessage,
            fontSize = 14.sp,
            fontWeight = FontWeight.Medium,
            color = ringColor
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Metrics Grid
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "Blocked Ads/Trackers",
                value = state.blockedCount.toString(),
                subtitle = "${state.allowedCount} allowed queries",
                accent = Color(0xFFEF4444)
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "Active Filter Rules",
                value = state.filterStats.totalRules.toString(),
                subtitle = "${state.filterStats.enabledSources} active list(s)",
                accent = Color(0xFF00E5A3)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "Tunnel Traffic",
                value = "↓ ${formatBytes(state.rxBytes)}",
                subtitle = "↑ ${formatBytes(state.txBytes)}",
                accent = Color(0xFF38BDF8)
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = "Zero Trust Endpoint",
                value = state.endpoint,
                subtitle = if (state.handshakeEstablished) "Noise_IKpsk2 Verified" else "WireGuard Endpoint",
                accent = Color(0xFFA78BFA)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Smart Keep-Alive & Screen State Card (Stateless Design)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = if (state.isScreenOn) Color(0xFF00E5A3) else Color(0xFF94A3B8),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Adaptive Tunnel Recovery",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color.White
                        )
                    }
                    Surface(
                        color = Color(0xFF064E3B),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = "ACTIVE",
                            color = Color(0xFF34D399),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                }
                Text(
                    text = if (state.isScreenOn) {
                        "Warm Keepalive = ${state.dynamicKeepaliveSec}s (Screen On) • Drops to 0s zero-drain idle when screen turns off."
                    } else {
                        "Ultra-Low-Power Idle = 0s (Screen Off) • Instant 1-RTT wake on screen-on or app traffic."
                    },
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Tunnel & DNS Interface Details
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onGoToWgConf() }
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "WireGuard & Zero Trust DNS",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    color = Color.White
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Assigned IPs: ${state.tunnelAddresses}",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8),
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "DNS Mode: ${state.tunnelDns}",
                    fontSize = 12.sp,
                    color = Color(0xFF00E5A3),
                    fontFamily = FontFamily.Monospace
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Per-app VPN tunnel selection summary
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onGoToFirewall() }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "App VPN Tunnel Selection",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                        color = Color.White
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (state.effectiveBypassedPackages.isEmpty()) {
                            "Only xPrivacyVPN uses the tunnel by default • Select apps below to route them through VPN"
                        } else {
                            "${state.bypassedPackages.size} selected (${state.effectiveBypassedPackages.size + 1} total packages using VPN)"
                        },
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                StatusBadge(
                    ok = state.effectiveBypassedPackages.isNotEmpty(),
                    okText = "${state.effectiveBypassedPackages.size + 1} TUNNELED",
                    warnText = "ALL OTHER APPS BYPASS"
                )
            }
        }
    }
}

@Composable
private fun FirewallScreen(
    state: VpnRuntimeState,
    installedApps: List<InstalledAppInfo>,
    isLoadingApps: Boolean,
    onRefreshApps: () -> Unit,
    onToggleAppBypass: (InstalledAppInfo, Boolean) -> Unit,
    onClearAllBypassed: () -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    // 0 = All User Apps, 1 = Tunneled, 2 = Bypassed
    var filterMode by remember { mutableIntStateOf(0) }

    val userApps = remember(installedApps) {
        installedApps.filter { FirewallManager.isUserApp(it) }
    }

    val tunneledAppsCount = remember(userApps, state.effectiveBypassedPackages) {
        userApps.count {
            state.effectiveBypassedPackages.contains(it.packageName) ||
                it.packageName == "com.xconflictionx.xprivacyvpn" ||
                FirewallManager.ALWAYS_TUNNELED_PACKAGES.contains(it.packageName)
        }
    }
    val bypassedAppsCount = (userApps.size - tunneledAppsCount).coerceAtLeast(0)

    val filteredApps = remember(userApps, searchQuery, filterMode, state.effectiveBypassedPackages) {
        userApps.filter { app ->
            val isTunneled = state.effectiveBypassedPackages.contains(app.packageName) ||
                app.packageName == "com.xconflictionx.xprivacyvpn" ||
                FirewallManager.ALWAYS_TUNNELED_PACKAGES.contains(app.packageName)
            val modeMatches = when (filterMode) {
                1 -> isTunneled
                2 -> !isTunneled
                else -> true
            }
            modeMatches && FirewallManager.matchesSearchQuery(app, searchQuery)
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Header Row
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Firewall • Choose Apps to Tunnel",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                    Text(
                        text = "${userApps.size} user apps • $tunneledAppsCount tunneled • $bypassedAppsCount bypassed",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                }
                if (state.bypassedPackages.isNotEmpty()) {
                    TextButton(onClick = onClearAllBypassed) {
                        Text("Clear", fontSize = 12.sp)
                    }
                }
                IconButton(onClick = onRefreshApps, enabled = !isLoadingApps) {
                    if (isLoadingApps) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh installed apps",
                            tint = Color(0xFF38BDF8)
                        )
                    }
                }
            }
        }

        // Search and Filter Chips
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    singleLine = true,
                    label = { Text("Search your apps...") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Default.Clear, contentDescription = "Clear search")
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = filterMode == 0,
                        onClick = { filterMode = 0 },
                        label = { Text("All (${userApps.size})") }
                    )
                    FilterChip(
                        selected = filterMode == 1,
                        onClick = { filterMode = 1 },
                        label = { Text("Tunneled ($tunneledAppsCount)") }
                    )
                    FilterChip(
                        selected = filterMode == 2,
                        onClick = { filterMode = 2 },
                        label = { Text("Bypassed ($bypassedAppsCount)") }
                    )
                }
            }
        }

        if (isLoadingApps && userApps.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 36.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "Scanning installed apps on your phone...",
                            color = Color(0xFF94A3B8),
                            fontSize = 13.sp
                        )
                    }
                }
            }
        } else if (filteredApps.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = if (searchQuery.isNotBlank()) {
                            "No matching user apps found for '${searchQuery.trim()}'."
                        } else {
                            "No user apps in this filter."
                        },
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        } else {
            items(filteredApps, key = { it.packageName }) { app ->
                val isAlwaysTunneled = app.packageName == "com.xconflictionx.xprivacyvpn" ||
                    FirewallManager.ALWAYS_TUNNELED_PACKAGES.contains(app.packageName)
                val isDirectlySelected = state.bypassedPackages.contains(app.packageName) || isAlwaysTunneled
                val isEffectivelyBypassed = state.effectiveBypassedPackages.contains(app.packageName) || isAlwaysTunneled

                AppFirewallItemCard(
                    app = app,
                    isDirectlySelected = isDirectlySelected,
                    isEffectivelyBypassed = isEffectivelyBypassed,
                    onToggleBypass = { shouldBypass -> onToggleAppBypass(app, shouldBypass) }
                )
            }
        }
    }
}

@Composable
private fun AppFirewallItemCard(
    app: InstalledAppInfo,
    isDirectlySelected: Boolean,
    isEffectivelyBypassed: Boolean,
    onToggleBypass: (Boolean) -> Unit
) {
    val context = LocalContext.current
    val iconBitmap by produceState<ImageBitmap?>(
        initialValue = appIconCache.get(app.packageName),
        key1 = app.packageName
    ) {
        if (value == null) {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    val drawable = context.packageManager.getApplicationIcon(app.packageName)
                    drawable.toBitmap(width = 96, height = 96).asImageBitmap()
                }.getOrNull()
            }
            if (loaded != null) {
                appIconCache.put(app.packageName, loaded)
                value = loaded
            }
        }
    }

    val isOwnApp = app.packageName == "com.xconflictionx.xprivacyvpn"
    val isSwitchChecked = isOwnApp || isEffectivelyBypassed

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = !isOwnApp) { onToggleBypass(!isSwitchChecked) }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (iconBitmap != null) {
                Image(
                    bitmap = iconBitmap!!,
                    contentDescription = app.appName,
                    modifier = Modifier
                        .size(42.dp)
                        .clip(RoundedCornerShape(10.dp))
                )
            } else {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFF1C2742)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Android,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8),
                        modifier = Modifier.size(24.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    text = app.appName,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = app.packageName,
                    fontSize = 11.sp,
                    color = Color(0xFF94A3B8),
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val statusText = when {
                        isOwnApp -> "ALWAYS TUNNELED (FILTER DOWNLOADS)"
                        isDirectlySelected -> "USING VPN"
                        isEffectivelyBypassed -> "AUTO-INCLUDED"
                        else -> "BYPASSED (NORMAL INTERNET)"
                    }
                    StatusBadge(
                        ok = isEffectivelyBypassed,
                        okText = statusText,
                        warnText = statusText
                    )
                }
            }

            Switch(
                checked = isSwitchChecked,
                onCheckedChange = { onToggleBypass(it) },
                enabled = !isOwnApp
            )
        }
    }
}

@Composable
private fun WireGuardAndDnsScreen(
    confText: String,
    ztDnsDraft: ZeroTrustDnsConfig,
    activeZtDns: ZeroTrustDnsConfig,
    onConfTextChange: (String) -> Unit,
    onSaveConf: () -> Unit,
    onImportConfFile: () -> Unit,
    onClearConf: () -> Unit,
    onZtDnsChange: (ZeroTrustDnsConfig) -> Unit,
    onSaveZtDns: () -> Unit,
    onResetZtDns: () -> Unit,
    onClearDnsCache: () -> Unit,
    onLoadDefaultStaticWarp: () -> Unit = {},
    onExportConfigFile: () -> Unit = {}
) {
    val parsedResult = remember(confText) { WireGuardConfig.parse(confText) }
    val parsed = parsedResult.getOrNull()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Section 1: Private split DNS
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Dns, contentDescription = null, tint = Color(0xFF38BDF8), modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Private Network DNS", fontWeight = FontWeight.Bold, fontSize = 17.sp, color = Color.White)
                    Spacer(modifier = Modifier.weight(1f))
                    StatusBadge(ok = activeZtDns.isPrivateDnsConfigured, okText = "SPLIT DNS", warnText = "WG DNS")
                }
                OutlinedTextField(
                    value = ztDnsDraft.privateDomain,
                    onValueChange = { onZtDnsChange(ztDnsDraft.copy(privateDomain = it)) },
                    label = { Text("Private DNS domain") },
                    placeholder = { Text("home.example.com") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = ztDnsDraft.privateDnsServer,
                    onValueChange = { onZtDnsChange(ztDnsDraft.copy(privateDnsServer = it)) },
                    label = { Text("Private DNS server IP") },
                    placeholder = { Text("DNS server reachable through WireGuard") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    "WireGuard [Peer] AllowedIPs must include the private DNS server's network. A full-tunnel 0.0.0.0/0 route already includes it.",
                    fontSize = 11.sp,
                    color = Color(0xFF94A3B8)
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onSaveZtDns) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Save DNS")
                    }
                    OutlinedButton(onClick = onResetZtDns) {
                        Icon(Icons.Default.Restore, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Clear Private DNS")
                    }
                }
                OutlinedButton(onClick = onClearDnsCache) {
                    Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Clear DNS Cache")
                }
            }
        }

        // Section 2: WireGuard Configuration (.conf)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "WireGuard Configuration (.conf)",
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Text(
                    text = "Import your WireGuard .conf file from your device or paste it below. Stored locally on your phone only.",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(onClick = onImportConfFile) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Import .conf File")
                    }
                    OutlinedButton(onClick = onExportConfigFile) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Export xPrivacyVPN.conf")
                    }
                    OutlinedButton(
                        onClick = onSaveConf,
                        enabled = confText.isNotBlank()
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Save Config")
                    }
                    if (confText.isNotBlank()) {
                        OutlinedButton(onClick = onClearConf) {
                            Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Clear")
                        }
                    }
                }

                if (parsed != null) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFF0A2E22))
                            .padding(12.dp)
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(
                                text = "WireGuard Config Valid • Endpoint: ${parsed.endpoint}",
                                color = Color(0xFF00E5A3),
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            Text(
                                text = "Addresses: ${parsed.addresses.joinToString(", ")} • MTU: ${parsed.mtu}",
                                fontSize = 11.sp,
                                color = Color(0xFFE2E8F0)
                            )
                        }
                    }
                } else if (confText.isNotBlank()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFF3B1219))
                            .padding(12.dp)
                    ) {
                        Text(
                            text = "Config Error: ${parsedResult.exceptionOrNull()?.message}",
                            color = Color(0xFFF87171),
                            fontSize = 12.sp
                        )
                    }
                }

                OutlinedTextField(
                    value = confText,
                    onValueChange = onConfTextChange,
                    label = { Text("WireGuard .conf") },
                    placeholder = {
                        Text(
                            "[Interface]\nPrivateKey = ...\nAddress = ...\nDNS = ...\n\n[Peer]\nPublicKey = ...\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = ...",
                            fontSize = 12.sp
                        )
                    },
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(260.dp)
                )
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    state: VpnRuntimeState,
    permissionStatus: SystemPermissionStatus,
    xSecurityDomain: String,
    xSecurityApiKey: String,
    onSaveXSecuritySettings: (String, String) -> Unit,
    onExportSettingsBackup: () -> Unit,
    onImportSettingsBackup: () -> Unit,
    onClearLogs: () -> Unit,
    onChangeFilterSettings: (Boolean, Boolean, Boolean, Boolean) -> Unit,
    onRequestDisableBatteryOptimization: () -> Unit,
    onOpenBatteryOptimizationList: () -> Unit,
    onRequestVpnPermissionOnly: () -> Unit,
    onRequestNotificationPermissionOnly: () -> Unit,
    onOpenAppDetailsSettings: () -> Unit
) {
    var domainDraft by remember(xSecurityDomain) { mutableStateOf(xSecurityDomain) }
    var apiKeyDraft by remember(xSecurityApiKey) { mutableStateOf(xSecurityApiKey) }
    var logFilterMode by remember { mutableIntStateOf(0) }
    val timeFormatter = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val filteredLogs = remember(state.recentLogs, logFilterMode) {
        when (logFilterMode) {
            1 -> state.recentLogs.filter { it.blocked }
            2 -> state.recentLogs.filter { !it.blocked }
            else -> state.recentLogs
        }
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "Settings & System Optimization",
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White
        )
        Text(
            text = "Configure startup auto-connect, disable Android battery throttling, and manage required permissions.",
            fontSize = 12.sp,
            color = Color(0xFF94A3B8)
        )

        // 1. Startup & Auto-Connect Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.PowerSettingsNew,
                        contentDescription = null,
                        tint = Color(0xFF00E5A3),
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Startup & Auto-Connect",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp,
                        color = Color.White
                    )
                }

                SettingToggleRow(
                    title = "Auto-Connect on Phone Boot / Update",
                    subtitle = "Automatically start xPrivacyVPN when your phone restarts",
                    checked = state.autoStartOnBoot,
                    onCheckedChange = {
                        onChangeFilterSettings(
                            state.dnsFilteringEnabled,
                            state.deepInspectionEnabled,
                            state.useNxDomain,
                            it
                        )
                    }
                )
            }
        }

        // 2. Battery Optimization Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.BatteryChargingFull,
                            contentDescription = null,
                            tint = if (permissionStatus.batteryOptimizationIgnored) Color(0xFF00E5A3) else Color(0xFFF59E0B),
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Battery Optimization",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 16.sp,
                            color = Color.White
                        )
                    }

                    StatusBadge(
                        ok = permissionStatus.batteryOptimizationIgnored,
                        okText = "UNRESTRICTED",
                        warnText = "RESTRICTED"
                    )
                }

                Text(
                    text = if (permissionStatus.batteryOptimizationIgnored) {
                        "Battery optimization is disabled for xPrivacyVPN. Android will not put the WireGuard tunnel to sleep."
                    } else {
                        "Disable battery optimization so Android Doze mode does not kill your WireGuard tunnel when the screen is off."
                    },
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onRequestDisableBatteryOptimization,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            if (permissionStatus.batteryOptimizationIgnored) "Verify Unrestricted"
                            else "Disable Battery Optimization"
                        )
                    }
                    OutlinedButton(onClick = onOpenBatteryOptimizationList) {
                        Text("All Apps List")
                    }
                }
            }
        }

        // 3. Required Permissions Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Required App Permissions",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    color = Color.White
                )

                PermissionItemRow(
                    icon = Icons.Default.VpnKey,
                    title = "VPN Service Tunnel Permission",
                    subtitle = "Allows xPrivacyVPN to create the local TUN interface",
                    granted = permissionStatus.vpnPermissionGranted,
                    actionText = if (permissionStatus.vpnPermissionGranted) "Granted" else "Grant VPN",
                    onAction = onRequestVpnPermissionOnly
                )

                PermissionItemRow(
                    icon = Icons.Default.Notifications,
                    title = "Foreground Service Notification",
                    subtitle = "Keeps the VPN service alive and shows live filter status",
                    granted = permissionStatus.notificationPermissionGranted,
                    actionText = if (permissionStatus.notificationPermissionGranted) "Settings" else "Grant",
                    onAction = onRequestNotificationPermissionOnly
                )

                OutlinedButton(
                    onClick = onOpenAppDetailsSettings,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Open Android App Info & Permissions")
                }
            }
        }

        // 4. Packet Filter Engine Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Packet Filter & DNS Engine",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    color = Color.White
                )
                Spacer(modifier = Modifier.height(8.dp))

                SettingToggleRow(
                    title = "DNS Sinkhole Blocking (UDP Port 53)",
                    subtitle = "Blocks ||domain^ and hosts rules before leaving device",
                    checked = state.dnsFilteringEnabled,
                    onCheckedChange = {
                        onChangeFilterSettings(
                            it,
                            state.deepInspectionEnabled,
                            state.useNxDomain,
                            state.autoStartOnBoot
                        )
                    }
                )

                SettingToggleRow(
                    title = "TLS SNI & HTTP Path Inspection (Ports 80/443)",
                    subtitle = "Enforces path rules (*/ads.js, ||domain/path^) & blocks direct-IP trackers",
                    checked = state.deepInspectionEnabled,
                    onCheckedChange = {
                        onChangeFilterSettings(
                            state.dnsFilteringEnabled,
                            it,
                            state.useNxDomain,
                            state.autoStartOnBoot
                        )
                    }
                )

                SettingToggleRow(
                    title = "Return NXDOMAIN instead of 0.0.0.0 / ::",
                    subtitle = "When disabled, returns 0.0.0.0 (A) and :: (AAAA) sinkhole responses",
                    checked = state.useNxDomain,
                    onCheckedChange = {
                        onChangeFilterSettings(
                            state.dnsFilteringEnabled,
                            state.deepInspectionEnabled,
                            it,
                            state.autoStartOnBoot
                        )
                    }
                )
            }
        }

        // xSecurity (xServer) Connection Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.VpnKey,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8),
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "xSecurity Server Connection",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp,
                        color = Color.White
                    )
                }
                Text(
                    text = "Set your xSecurity domain name (not IP) and an API key from your xServer /keys/ page.",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )
                OutlinedTextField(
                    value = domainDraft,
                    onValueChange = { domainDraft = it },
                    label = { Text("xSecurity Domain Name") },
                    placeholder = { Text("security.home.example.com") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = apiKeyDraft,
                    onValueChange = { apiKeyDraft = it },
                    label = { Text("xServer API Key") },
                    placeholder = { Text("xsk_...") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Button(
                    onClick = { onSaveXSecuritySettings(domainDraft, apiKeyDraft) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save xSecurity Settings")
                }
            }
        }

        // Backup & Restore Settings Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Save,
                        contentDescription = null,
                        tint = Color(0xFF00E5A3),
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Backup & Restore Settings",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp,
                        color = Color.White
                    )
                }
                Text(
                    text = "Export or import your WireGuard config, tunneled apps, Split/Zero Trust DNS, filter lists, toggles, and xSecurity settings as JSON. Only compatible settings are restored.",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = onExportSettingsBackup,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Export")
                    }
                    OutlinedButton(
                        onClick = onImportSettingsBackup,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Import")
                    }
                }
            }
        }

        // Terminal-style Activity Logs Card at the very bottom of Settings
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Activity Log Terminal",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 16.sp,
                            color = Color.White
                        )
                        Text(
                            text = "${state.blockedCount} blocked • ${state.allowedCount} allowed",
                            fontSize = 11.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }
                    OutlinedButton(onClick = onClearLogs) {
                        Text("Clear", fontSize = 12.sp)
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = logFilterMode == 0,
                        onClick = { logFilterMode = 0 },
                        label = { Text("All (${state.recentLogs.size})") }
                    )
                    FilterChip(
                        selected = logFilterMode == 1,
                        onClick = { logFilterMode = 1 },
                        label = { Text("Blocked") }
                    )
                    FilterChip(
                        selected = logFilterMode == 2,
                        onClick = { logFilterMode = 2 },
                        label = { Text("Allowed") }
                    )
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(240.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFF050810))
                        .border(1.dp, Color(0xFF1E293B), RoundedCornerShape(10.dp))
                        .padding(10.dp)
                ) {
                    if (filteredLogs.isEmpty()) {
                        Text(
                            text = "$ waiting for traffic logs...",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = Color(0xFF64748B)
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            items(filteredLogs.take(120), key = { it.id }) { entry ->
                                val ts = timeFormatter.format(Date(entry.timestampMs))
                                val tag = if (entry.blocked) "BLK" else "OK "
                                val color = if (entry.blocked) Color(0xFFF87171) else Color(0xFF34D399)
                                val ruleSuffix = if (entry.blocked && !entry.matchedRule.isNullOrBlank()) " [${entry.matchedRule}]" else ""
                                Text(
                                    text = "[$ts] $tag ${entry.protocol} ${entry.target}$ruleSuffix",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    color = color
                                )
                            }
                        }
                    }
                }
            }
        }

        val context = LocalContext.current
        val versionName = remember(context) {
            runCatching {
                val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    context.packageManager.getPackageInfo(
                        context.packageName,
                        PackageManager.PackageInfoFlags.of(0)
                    )
                } else {
                    @Suppress("DEPRECATION")
                    context.packageManager.getPackageInfo(context.packageName, 0)
                }
                pkgInfo.versionName ?: "Unknown"
            }.getOrDefault("Unknown")
        }

        Text(
            text = "Version $versionName",
            fontSize = 12.sp,
            color = Color(0xFF64748B),
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp, bottom = 12.dp)
        )
    }
}

@Composable
private fun PermissionItemRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
    granted: Boolean,
    actionText: String,
    onAction: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (granted) Color(0xFF00E5A3) else Color(0xFFF59E0B),
            modifier = Modifier.size(22.dp)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(text = title, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
            Text(text = subtitle, fontSize = 11.sp, color = Color(0xFF94A3B8))
        }
        if (granted) {
            OutlinedButton(onClick = onAction) {
                Text(actionText, fontSize = 12.sp)
            }
        } else {
            Button(onClick = onAction) {
                Text(actionText, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun StatusBadge(ok: Boolean, okText: String, warnText: String) {
    val bg = if (ok) Color(0xFF0A2E22) else Color(0xFF3B2412)
    val fg = if (ok) Color(0xFF34D399) else Color(0xFFFBBF24)
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Text(
            text = if (ok) okText else warnText,
            color = fg,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun MetricCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    subtitle: String,
    accent: Color
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(text = title, fontSize = 12.sp, color = Color(0xFF94A3B8))
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = accent,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = Color(0xFF64748B),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(text = title, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
            Text(text = subtitle, fontSize = 12.sp, color = Color(0xFF94A3B8))
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun FiltersScreen(
    state: VpnRuntimeState,
    sources: List<FilterSource>,
    isSyncing: Boolean,
    onImportFiles: () -> Unit,
    onAddUrls: (String) -> Unit,
    onRefreshRemote: () -> Unit,
    onAddCustomRule: (String) -> Unit,
    onToggleSource: (String, Boolean) -> Unit,
    onDeleteSource: (String) -> Unit,
    onTestQuery: (String) -> FilterDecision
) {
    var urlsInput by remember { mutableStateOf("") }
    var showAddRuleDialog by remember { mutableStateOf(false) }
    var inspectSource by remember { mutableStateOf<FilterSource?>(null) }

    var testInput by remember { mutableStateOf("") }
    var testResult by remember(testInput, state.filterStats) {
        mutableStateOf(onTestQuery(testInput))
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(
                text = "Privacy Filter Lists (filters.txt)",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
            Text(
                text = "${sources.size} list(s) • ${state.filterStats.domainBlockRules} domain rules • ${state.filterStats.pathBlockRules} path/wildcard rules • ${state.filterStats.exceptionRules} exceptions",
                fontSize = 12.sp,
                color = Color(0xFF94A3B8)
            )
        }

        // Multi-URL Paste Card — paste one or as many filters.txt URLs as desired
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Paste filters.txt URLs",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                        color = Color.White
                    )
                    Text(
                        text = "Paste one or multiple URLs (one per line). Uses your Zero Trust Location DNS (or System DNS) to resolve custom filter domains.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = urlsInput,
                        onValueChange = { urlsInput = it },
                        placeholder = {
                            Text(
                                "https://.../filters.txt\nhttps://.../more-filters.txt",
                                fontSize = 12.sp
                            )
                        },
                        minLines = 3,
                        maxLines = 8,
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                if (urlsInput.isNotBlank()) {
                                    val toSubmit = urlsInput
                                    urlsInput = ""
                                    onAddUrls(toSubmit)
                                }
                            },
                            enabled = !isSyncing && urlsInput.isNotBlank()
                        ) {
                            if (isSyncing) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Icon(
                                    Icons.Default.CloudDownload,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Add URL(s)")
                        }

                        OutlinedButton(onClick = onImportFiles) {
                            Icon(
                                Icons.Default.FolderOpen,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Import Local File(s)")
                        }

                        OutlinedButton(
                            onClick = onRefreshRemote,
                            enabled = !isSyncing && sources.isNotEmpty()
                        ) {
                            Icon(
                                Icons.Default.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Sync All")
                        }

                        OutlinedButton(onClick = { showAddRuleDialog = true }) {
                            Icon(
                                Icons.Default.Add,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Custom Rule")
                        }
                    }
                }
            }
        }

        // Interactive Rule Tester Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Live Rule Tester",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                        color = Color.White
                    )
                    Text(
                        text = "Test any domain or URL path against your active filter lists:",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = testInput,
                        onValueChange = {
                            testInput = it
                            testResult = onTestQuery(it)
                        },
                        singleLine = true,
                        label = { Text("Enter domain or URL to test") },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                        modifier = Modifier.fillMaxWidth()
                    )

                    if (testInput.isNotBlank()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        val badgeColor = if (testResult.blocked) Color(0xFF3B1219) else Color(0xFF0A2E22)
                        val textColor = if (testResult.blocked) Color(0xFFF87171) else Color(0xFF34D399)
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(badgeColor)
                                .padding(10.dp)
                        ) {
                            if (testResult.blocked) {
                                Text(
                                    text = "BLOCKED by rule '${testResult.matchedRule}' (${testResult.sourceName})",
                                    color = textColor,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold
                                )
                            } else {
                                Text(
                                    text = "ALLOWED • No blocking rule matched '${testInput.trim()}'",
                                    color = textColor,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }
            }
        }

        if (sources.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "No filter lists added yet. Paste one or more filters.txt URLs above or import local files.",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        }

        // List of loaded filters.txt sources
        items(sources, key = { it.id }) { source ->
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { inspectSource = source }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = source.name,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = Color.White
                        )
                        Text(
                            text = source.urlOrPath,
                            fontSize = 11.sp,
                            color = Color(0xFF38BDF8),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "${source.ruleCount} active rules • Tap to inspect",
                            fontSize = 12.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }

                    Switch(
                        checked = source.enabled,
                        onCheckedChange = { onToggleSource(source.id, it) }
                    )

                    IconButton(onClick = { onDeleteSource(source.id) }) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = "Delete filter list",
                            tint = Color(0xFFEF4444)
                        )
                    }
                }
            }
        }
    }

    if (showAddRuleDialog) {
        var ruleInput by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showAddRuleDialog = false },
            title = { Text("Add Custom Filter Rule(s)") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Supports ||domain.com^, @@||allow.com^, */path.js, or 0.0.0.0 domain.com (one per line):",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    OutlinedTextField(
                        value = ruleInput,
                        onValueChange = { ruleInput = it },
                        placeholder = { Text("||ads.example.com^") },
                        minLines = 2,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (ruleInput.isNotBlank()) {
                            onAddCustomRule(ruleInput)
                            showAddRuleDialog = false
                        }
                    }
                ) {
                    Text("Add Rule(s)")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddRuleDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    inspectSource?.let { src ->
        AlertDialog(
            onDismissRequest = { inspectSource = null },
            title = { Text(src.name) },
            text = {
                val previewLines = remember(src.content) {
                    src.content.lines().take(250).joinToString("\n")
                }
                Box(
                    modifier = Modifier
                        .height(340.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        text = previewLines,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { inspectSource = null }) {
                    Text("Close")
                }
            }
        )
    }
}

@Composable
private fun SecurityScreen(
    report: DeviceSecurityReport,
    syncResult: XSecuritySyncResult?,
    domain: String,
    hasApiKey: Boolean,
    isSyncing: Boolean,
    onRefreshChecks: () -> Unit,
    onSyncToXServer: () -> Unit,
    onGoToSettings: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Phone & xSecurity",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Text(
                    text = "${report.deviceModel} • Android ${report.androidVersion}",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )
            }
            IconButton(onClick = onRefreshChecks) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh Checks", tint = Color(0xFF38BDF8))
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Device Security Posture",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    color = Color.White
                )
                SecurityCheckRow("Security Patch Level", report.securityPatch, true, report.securityPatch, "Unknown")
                SecurityCheckRow("Screen Lock & Encryption", "KeyguardManager secure lock", report.deviceSecure, "Secured", "Not Set")
                if (report.autoBlockerEnabled != null) {
                    val abSubtitle = if (report.autoBlockerMaxRestrictions == true) {
                        "Samsung One UI (Maximum restrictions ON)"
                    } else {
                        "Samsung One UI sideload & USB guard"
                    }
                    SecurityCheckRow("Samsung Auto Blocker", abSubtitle, report.autoBlockerEnabled, "Enabled", "Disabled")
                }
                SecurityCheckRow("ADB Debugging", "USB / Wireless debugging", !report.adbEnabled, "Disabled", "Enabled")
                SecurityCheckRow("Developer Options", "Android developer mode", !report.developerOptionsEnabled, "Off", "On")
                SecurityCheckRow("xPrivacyVPN Tunnel", "DNS & SNI filtering active", report.vpnConnected, "Connected", "Disconnected")
                SecurityCheckRow("Verified Build Tags", report.verifiedBootTags, report.verifiedBootTags.contains("release-keys"), "Release", report.verifiedBootTags)
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "xServer Sync ($domain)",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    color = Color.White
                )
                if (syncResult != null) {
                    Text(
                        text = if (syncResult.ok) {
                            "${syncResult.message} • xSecurity Posture: ${syncResult.postureScore ?: "--"}/100 (${syncResult.openAlerts ?: 0} open alerts)"
                        } else {
                            syncResult.message
                        },
                        fontSize = 12.sp,
                        color = if (syncResult.ok) Color(0xFF34D399) else Color(0xFFF87171)
                    )
                } else {
                    Text(
                        text = if (hasApiKey) "Ready to report phone security status to xSecurity." else "Configure your xSecurity domain and API key in Settings.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = onSyncToXServer,
                        enabled = !isSyncing,
                        modifier = Modifier.weight(1f)
                    ) {
                        if (isSyncing) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(if (isSyncing) "Syncing…" else "Sync to xSecurity")
                    }
                    if (!hasApiKey) {
                        OutlinedButton(onClick = onGoToSettings) {
                            Text("Set API Key")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityCheckRow(
    title: String,
    subtitle: String,
    ok: Boolean,
    okText: String,
    warnText: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(text = title, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color.White)
            Text(text = subtitle, fontSize = 11.sp, color = Color(0xFF94A3B8))
        }
        StatusBadge(ok = ok, okText = okText, warnText = warnText)
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format(Locale.US, "%.2f MB", mb)
    val gb = mb / 1024.0
    return String.format(Locale.US, "%.2f GB", gb)
}
