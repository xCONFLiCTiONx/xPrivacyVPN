# Aether Android integration assessment

Status: upstream source pinned; Android integration design verified; no native build or device test claimed yet.

## Pinned upstream

- Repository: https://github.com/CluvexStudio/Aether
- Revision: `ef06971101ba3d4b30f0bb317a2bba81c9b55ca2`
- Location: `third_party/Aether` (Git submodule)
- Aether crate: `third_party/Aether/aether/Cargo.toml`
- Quiche source: `third_party/Aether/quiche`

The source is kept as an upstream submodule. Do not silently edit files inside it; any required upstream patch must be explicit and tracked.

## Verified FFI surface

Aether exposes a C ABI from `aether/src/ffi.rs`, including:

- `aether_identity_open` / `aether_identity_summary` / `aether_identity_free`
- `aether_verify_start`
- `aether_tunnel_start`
- `aether_job_poll` / `aether_job_cancel` / `aether_job_free`
- `aether_team_sign_in`, `aether_team_code_request`, `aether_team_code_resend`, `aether_team_code_submit`
- `aether_team_token_set` / `aether_team_token_clear`
- `aether_string_free`

The functions exchange JSON through C strings and return asynchronous job handles. The repository does not currently ship a public C header for this FFI, so xPrivacyVPN will need a small, checked-in header matching the exact exported signatures.

## Critical data-plane finding

Aether is not a raw-IP packet channel that can directly replace `WireGuardSession` in the current Android TUN loop.

Its `api::connect()` implementation binds the configured local SOCKS listener (`TunnelSpec.socks`) and then runs the MASQUE tunnel behind that listener. The Android app therefore needs a TUN-to-SOCKS adapter to translate eligible IP flows into SOCKS5 TCP/UDP sessions.

The existing `XPrivacyVpnService` reads raw IP packets from Android's TUN, runs `PacketInspector.inspectOutboundPacket()`, handles filtered/DNS packets, and then encrypts remaining packets with WireGuard. The safe integration point is after inspection: blocked packets and locally handled DNS must remain local; allowed TCP/UDP flows must be forwarded through the Aether SOCKS endpoint; return traffic must be reconstructed and written to the same TUN.

That adapter is a real TCP/IP networking component, not a simple socket-forwarding substitution. Do not bypass the packet inspector or claim feature parity until TCP, UDP, IPv4, IPv6, fragmentation, MTU, DNS, and teardown behavior are tested.

## Android socket protection requirement

Aether's `egress.rs` centralizes outgoing TCP and UDP socket creation and applies `AETHER_MARK` when configured. Its QUIC path also calls the same socket-marking helper. On Android, the mark operation requires privileges that an ordinary app does not have.

When Aether runs inside xPrivacyVPN's process, its Cloudflare-facing sockets must bypass xPrivacyVPN's own TUN or they can route back into the VPN and loop. Android provides `VpnService.protect(fd)` for this purpose, but the pinned upstream FFI does not expose a socket-protection callback.

Before enabling the Aether tunnel under the Android VPN service, we must add a tracked Android integration patch (or a maintained xPrivacyVPN fork) that invokes a registered native socket-protection callback before connecting/binding each outbound socket. Do not rely on `AETHER_MARK` as an unprivileged Android workaround.

## Implementation sequence

1. Build Aether and Quiche for the Android ABIs supported by xPrivacyVPN; package the native libraries through the Android Gradle/NDK build.
2. Add a Kotlin/JNI bridge for Aether's JSON C ABI, asynchronous job polling/cancellation, identity lifecycle, and team email-code authentication.
3. Add the Android `VpnService.protect(fd)` callback to Aether's outbound socket creation path, tracked as an explicit upstream integration patch.
4. Implement the TUN-to-SOCKS adapter after `PacketInspector`, preserving current DNS handling, filtering, logging, app selection, and firewall behavior.
5. Keep the existing WireGuard transport selectable until Aether MASQUE passes device-level connection, traffic, reconnect, sleep/wake, IPv4/IPv6, DNS, and leak tests.

## Current test status

- Git submodule pointer: committed and pinned.
- Aether native Android build: not run.
- Kotlin/JNI bridge: not implemented.
- Socket protection callback: not implemented.
- TUN-to-SOCKS adapter: not implemented.
- End-to-end Cloudflare test: not run.

This status is intentional: source inclusion is complete, but the app must not report an Aether/Cloudflare connection before the native tunnel and packet path are actually working.
