# xPrivacyVPN

**xPrivacyVPN** is a lightweight, high-performance Android VPN client designed for **Cloudflare Zero Trust (WARP / WireGuard)** with an integrated multi-source **`filters.txt` Ad & Tracker Blocker** and **Zero Trust Location DNS** resolver—all operating together inside a single Android `VpnService`.

---

## Features

- **Cloudflare Zero Trust WireGuard Tunnel (per-app allowlist)**:
  - Import or paste any standard WireGuard `.conf` profile (`[Interface]` and `[Peer]`).
  - Full `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake, transport encryption, and persistent keepalive engine.
  - No bundled private key or default profile. Import your own WireGuard configuration; credentials remain in private app storage.
- **Zero Trust DNS Location & System DNS Fallback**:
  - **System DNS by Default**: Uses the device's underlying physical network System DNS out of the box until custom Location endpoints are configured.
  - **Zero Trust Location Endpoints**: Dedicated configuration for your Cloudflare Zero Trust DNS Location:
    - **IPv4 Primary & Secondary Endpoints** + optional **Source IPv4 Address**
    - **IPv6 Endpoint**
    - **DNS-over-TLS (DoT)** Endpoint (`tls://<gateway-id>.cloudflare-gateway.com:853`)
    - **DNS-over-HTTPS (DoH)** Endpoint (`https://<gateway-id>.cloudflare-gateway.com/dns-query`, RFC 8484 wire-format)
  - WireGuard transport and upstream DNS sockets are protected from routing loops. xPrivacyVPN itself is always included in the app allowlist so its remote filter downloads can reach xServer.
- **Multi-Source `filters.txt` Engine**:
  - Add **unlimited remote `filters.txt` URLs** (paste one or multiple URLs at once, with automatic GitLab/GitHub raw URL normalization) or import **local `filters.txt` files**.
  - Supports Adblock Plus / uBlock / AdGuard domain rules (`||example.com^`), exception rules (`@@||example.com^`), domain + path rules (`||example.com/path^`), wildcard script/path rules (`*/ads.js`, `*/analytics.js`), and hosts-file rules (`0.0.0.0 example.com`).
  - Toggle, refresh, or remove individual filter lists at any time.
- **Deep Packet Inspection (DPI) & Real-Time Activity Log**:
  - **DNS Interception (UDP Port 53)**: Blocks matching domains before queries leave the device (`0.0.0.0` / `::` or `NXDOMAIN` synthetic replies) and resolves allowed queries via your configured Zero Trust Location DNS or System DNS.
  - **TLS SNI Inspection (TCP Port 443)** & **HTTP Path Inspection (TCP Port 80)**: Inspects outbound TLS ClientHello SNI and HTTP `Host` + request paths against active filter rules.
  - Live telemetry dashboard and real-time packet log with filtering for **All**, **Blocked**, and **Allowed** events.
- **Per-App Routing & Battery-Aware Recovery**:\n  - All apps bypass the VPN by default. xPrivacyVPN itself remains included so it can fetch remote filter lists; users explicitly select any additional apps to tunnel.\n  - No permanent partial wakelock or forced 25-second keepalive. Keepalives are sent only when requested by the imported profile; recovery checks use adaptive intervals.\n- **Android System & Reliability Optimizations**:
  - Built-in shortcuts in **Settings** to disable Android Battery Optimizations (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) and grant Notification permissions.
  - Compiled with R8 code shrinking, obfuscation, and resource optimization enabled for Release builds.

---

## Project Architecture

```text
app/src/main/java/com/xconflictionx/xprivacyvpn/
├── MainActivity.kt                  # Compose entry point
├── config/
│   └── WireGuardConfig.kt           # WireGuard .conf parser & validator
├── dns/
│   ├── ZeroTrustDnsConfig.kt        # Zero Trust Location DNS configuration model
│   └── ZeroTrustDnsResolver.kt      # DoH (RFC 8484), DoT (RFC 7858), IPv4/IPv6 UDP & System DNS resolver
├── filter/
│   ├── FilterEngine.kt              # Multi-source filters.txt parser & matcher (domain, subdomain, path, wildcard)
│   └── FilterSourceRepository.kt    # Remote URL & local file persistence and downloader
├── packet/
│   └── PacketInspector.kt           # IPv4/IPv6 UDP DNS, TLS SNI, and HTTP packet inspector & reply synthesizer
├── ui/
│   ├── MainViewModel.kt             # UI state holder & actions
│   ├── XPrivacyVpnApp.kt            # Material 3 Dark UI (Dashboard, Filter Lists, WG & DNS, Activity, Settings)
│   └── theme/                       # Material 3 theme & colors
├── vpn/
│   ├── VpnStateManager.kt           # Reactive state, statistics, and SharedPreferences persistence
│   └── XPrivacyVpnService.kt        # Foreground Android VpnService (TUN loop + DNS + WireGuard session)
└── wireguard/
    ├── WireGuardCrypto.kt           # X25519, ChaCha20-Poly1305, BLAKE2s, HKDF primitives
    └── WireGuardSession.kt          # Noise_IKpsk2 handshake & transport packet encryption
```

---

## Prerequisites

- **Android Studio** (or Android SDK + JDK 17 / JBR 21+)
- **Android Device or Emulator** running Android 8.0+ (API 26+) with **USB Debugging (ADB)** enabled
- **PowerShell** (for automated one-command release build, install, and launch via `.build.ps1`)

---

## Build, Install & Run

### Automated Build & Deploy (`.build.ps1`)

Connect your Android phone via USB with USB Debugging enabled and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\.build.ps1
```

What `.build.ps1` does:
1. Locates your JDK (`JAVA_HOME` or Android Studio JBR) and Android `adb`.
2. Builds the R8-optimized **Release APK** (`.\gradlew.bat assembleRelease`).
3. Installs the selected APK onto your connected device via `adb install -r`. It never uninstalls the existing app or deletes its data when signatures differ.
4. Launches `com.xconflictionx.xprivacyvpn/.MainActivity` on your phone.

**Optional flags**:
- Build the Release APK only (skip ADB install):
  ```powershell
  .\.build.ps1 -SkipInstall
  ```
- Target a specific ADB device serial:
  ```powershell
  .\.build.ps1 -DeviceSerial <SERIAL>
  ```

### Running Unit Tests

```powershell
.\gradlew.bat testDebugUnitTest
```

---

## Usage Guide

1. **Import Your WireGuard Config (`WG & DNS` Tab)**:
   - Open the **WG & DNS** tab and tap **Import .conf File** (or paste your `[Interface]` / `[Peer]` configuration and tap **Save Config**).
2. **Configure DNS (`WG & DNS` Tab)**:
   - Normal DNS uses the `DNS =` servers from the imported WireGuard `[Interface]` section. DNS requests are filtered before being forwarded through the WireGuard tunnel.
   - For private home names, enter the private DNS suffix (for example, `home.example.com`) and the IP address of the DNS server reachable over the tunnel, then tap **Save DNS**.
   - Private-domain queries are sent only to that private DNS server. If it cannot be reached, xPrivacyVPN returns SERVFAIL rather than leaking the name to public DNS.
   - The WireGuard `[Peer]` `AllowedIPs` must include the private DNS server's network. A full-tunnel `0.0.0.0/0` route already includes IPv4 destinations.
   - Leave both private DNS fields blank if you do not use private hostnames.
3. **Add `filters.txt` Lists (`Filter Lists` Tab)**:
   - Paste one or more `filters.txt` URLs (one per line) and tap **Fetch & Add URL(s)**, or tap **Import Local filters.txt** to pick a file from your device.
4. **Optimize System Settings (`Settings` Tab)**:
   - Tap **Disable Battery Optimization** to set the app to *Unrestricted* so Android does not suspend the VPN tunnel.
   - Optionally toggle **Auto-Connect on Phone Boot / Update** if you want the tunnel to start when your phone boots.
5. **Connect (`Dashboard` Tab)**:
   - Open **Firewall** and enable the apps you want to route through the tunnel. All other apps use normal internet; xPrivacyVPN itself remains included for remote filter downloads.\n  - Tap the central power button to start the WireGuard + `filters.txt` tunnel.

---

## Privacy & Security

- **No hardcoded credentials**: WireGuard private keys, profiles, signing keys, and Zero Trust Location addresses must never be committed. Release signing material is supplied locally through `XPRIVACYVPN_KEYSTORE_PATH`, `XPRIVACYVPN_KEYSTORE_PASSWORD`, `XPRIVACYVPN_KEY_ALIAS`, and `XPRIVACYVPN_KEY_PASSWORD`; it is not part of this repository.
- All user-supplied configurations are stored locally in the app's private storage on your device.

---
