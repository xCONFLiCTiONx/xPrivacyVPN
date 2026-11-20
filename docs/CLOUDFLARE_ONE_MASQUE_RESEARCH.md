# Cloudflare One MASQUE implementation research

Status: investigation / implementation gate. This document records verified public behavior and prevents xPrivacyVPN from pretending that a browser login alone enrolls a device.

## Confirmed Cloudflare One architecture

Cloudflare documents three separate connections for its managed client:

1. WARP tunnel: WireGuard or MASQUE over UDP, carrying IP packets to Gateway.
2. Gateway DNS-over-HTTPS: carried inside the WARP tunnel.
3. Device orchestration over HTTPS: user registration, device posture, and device-profile settings. This connection remains outside split-tunnel routing.

Cloudflare documents MASQUE as HTTP/3 and the default tunnel protocol. The documented MASQUE ingress uses UDP 443 (with documented fallback ports); this is not an ordinary HTTPS proxy and not just a generic QUIC socket.

References:
- https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/client-architecture/
- https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/
- https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/

## What this means for xPrivacyVPN

- Android `VpnService` remains the OS TUN interface. It does not require WireGuard as the transport.
- A browser-based login can authenticate a user, but it does not by itself provide the registered device identity, orchestration credentials, tunnel parameters, or session lifecycle.
- A compatible client needs the device-orchestration/enrollment flow as well as the MASQUE IP tunnel implementation and Gateway DNS behavior.
- Cloudflare's public docs describe the official client behavior, but do not provide a supported public Android SDK or complete third-party client enrollment API/contract.

## Implementation gate

Do not ship a fake "Cloudflare authenticated" state, scrape private API endpoints, reuse official-app cookies, or treat a Cloudflare dashboard/API token as a WARP device credential.

Before implementing enrollment, identify a supported Cloudflare interface or obtain a documented integration contract. Until then, retain the existing WireGuard path and keep the new transport boundary isolated.

## Planned milestones

1. Isolate transport selection from the existing TUN, filtering, and DNS pipeline.
2. Implement and test an independent MASQUE/CONNECT-IP transport against a compatible test endpoint.
3. Determine whether Cloudflare supports third-party device enrollment for this client use case.
4. Only then connect the MASQUE engine to Cloudflare's device orchestration and Gateway services.
5. Preserve the current WireGuard implementation as a fallback until end-to-end tests pass.
