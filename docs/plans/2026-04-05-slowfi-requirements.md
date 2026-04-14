# SlowFi Requirements

## Summary

`SlowFi` is a proposed derivative product built on `esp32_nat_router`. It is an ESP32-based local Wi-Fi hotspot that forwards traffic to an upstream network while intentionally degrading that traffic to reproduce realistic bad-network conditions for app and web testing.

The goal is a practical, portable bad-network test appliance for phones and laptops. It should be believable and useful for testing retries, timeouts, loading states, reconnect flows, and flaky uploads/downloads, without claiming lab-grade or carrier-grade fidelity.

## Product Goal

`SlowFi` shall operate as a transparent Wi-Fi hotspot that:

- accepts client devices over a SoftAP
- connects to an upstream Wi-Fi network as a station
- forwards traffic using NAT
- applies user-selected shaping rules to simulate poor network conditions

For v1, transparent means a client device only needs to join the `SlowFi` Wi-Fi network. It must not require a custom proxy configuration, client-side app install, certificate install, or per-device routing changes beyond normal Wi-Fi association.

## Intended Use Cases

`SlowFi` is intended to help developers test:

- loading and skeleton states
- retry logic
- timeout handling
- offline and reconnect UX
- upload and download failure behavior
- flaky authentication and startup flows
- real-world bad Wi-Fi behavior on phones and laptops

## Non-Goals

`SlowFi` is not intended to provide:

- exact carrier or tower emulation
- precise Linux `tc/netem` equivalence
- high-density client support
- per-device shaping in v1
- deep packet inspection or application-aware shaping in v1
- lab-grade fidelity for all UDP or real-time traffic

## Platform And Base Firmware

The initial implementation should target an ESP32-class device and build on the existing `esp32_nat_router` firmware as the base. The existing router already provides the foundational capabilities required for `SlowFi`:

- Wi-Fi station uplink
- SoftAP downlink
- NAT forwarding
- DHCP service
- management UI

Other debugging features, such as packet capture or richer telemetry, should be treated as optional follow-on work unless they can be cleanly inherited from the base firmware already present in the selected branch.

The base firmware's existing web UI should be treated as a starting point, not proof that `SlowFi` already satisfies the intended administration-security model. Any stronger UI access control required by this document is new `SlowFi` work unless it is explicitly verified in the chosen base revision.

## Operating Model

`SlowFi` shall run as:

- upstream interface: Wi-Fi STA connected to an existing network
- downstream interface: SoftAP for test clients
- forwarding model: NAT router
- management model: local web UI

All shaping shall be applied in the forwarding path between downstream clients and the upstream network.

## Traffic Shaping Model

V1 shaping shall be global to the device rather than per client.

Supported impairments in v1:

- upstream bandwidth cap
- downstream bandwidth cap
- base latency
- jitter
- packet loss
- burst loss or short outage windows
- bounded queueing with overflow drops

Not required in v1:

- guaranteed packet reordering simulation
- per-flow fairness tuning
- protocol-specific shaping
- application-aware failure injection

## Presets

V1 shall ship with named presets plus a custom mode.

Initial preset list:

- `Good WiFi`
- `Bad Cafe WiFi`
- `Train WiFi`
- `Hotel WiFi`
- `Weak 3G`
- `Edge-ish`
- `Offline Spikes`
- `Custom`

Preset target parameters for v1:

| Preset | Upstream cap | Downstream cap | Base latency | Jitter | Loss | Burst / outage behavior |
| --- | --- | --- | --- | --- | --- | --- |
| `Good WiFi` | 8000 kbps | 12000 kbps | 20 ms | 5 ms | 0.0% to 0.5% | none |
| `Bad Cafe WiFi` | 1500 kbps | 4000 kbps | 90 ms | 40 ms | 1% to 3% | 1 to 2 second stall roughly every 2 to 5 minutes |
| `Train WiFi` | 700 kbps | 2500 kbps | 160 ms | 90 ms | 2% to 5% | 2 to 4 second stall roughly every 1 to 3 minutes |
| `Hotel WiFi` | 1200 kbps | 5000 kbps | 110 ms | 60 ms | 1% to 2% | 3 to 6 second stall roughly every 3 to 8 minutes |
| `Weak 3G` | 300 kbps | 900 kbps | 220 ms | 120 ms | 2% to 4% | no forced outage |
| `Edge-ish` | 80 kbps | 220 kbps | 650 ms | 220 ms | 4% to 8% | optional 1 to 3 second stall roughly every 2 to 4 minutes |
| `Offline Spikes` | 2500 kbps | 6000 kbps | 70 ms | 30 ms | 0.5% to 2% | 5 to 15 second full outage roughly every 2 to 6 minutes |

Preset intent:

- `Good WiFi`: baseline profile for comparison with minimal impairment
- `Bad Cafe WiFi`: mildly frustrating public Wi-Fi with moderate contention and short stalls
- `Train WiFi`: unstable link with stronger jitter and more frequent stalls
- `Hotel WiFi`: acceptable throughput interrupted by periodic captive-portal-like pauses or congestion spikes
- `Weak 3G`: slow but usable network for retries, spinners, and degraded mobile flows
- `Edge-ish`: near-failure profile for extreme timeout and resilience testing
- `Offline Spikes`: normal-ish browsing interrupted by temporary full disconnects

Presets should be believable and useful, not marketed as scientifically exact.

## User Interface

The primary management surface shall be a local web UI reachable by connected clients.

The v1 UI shall expose:

- current hotspot and upstream connection status
- active preset
- shaping controls
- enable or disable shaping
- current shaping parameter values
- traffic and drop counters
- saved presets

Recommended controls:

- select preset
- edit custom values
- save preset
- restore defaults
- disable all shaping quickly

## Observability

The device should expose enough information to confirm that shaping is active and behaving plausibly.

Visible counters should include:

- bytes upstream and downstream
- packets forwarded
- packets dropped due to configured loss
- packets dropped due to queue overflow
- current queue depth
- active shaping parameters
- triggered outage or burst events

## Error Handling And Limits

The design shall prefer graceful degradation over lockup.

Rules:

- queues must be bounded
- packets should be dropped rather than buffered without limit
- shaping failure should result in a surfaced error or safe fallback state
- the UI must show whether shaping is active, disabled, or degraded

Known constraints to document:

- best suited to 1 to 3 active client devices
- optimized for web, mobile, and API testing rather than high-throughput media testing
- latency and jitter precision are approximate, not lab-grade
- real-time UDP behavior may be less predictable than TCP-heavy traffic

## Security And Persistence

Minimum operational requirements:

- configurable AP password
- local admin UI protection
- no upstream-facing remote admin by default
- optional monitoring features disabled by default
- explicit warning when packet monitoring or traffic inspection is enabled

Bootstrap expectation for v1:

- on first boot, the device may expose a protected onboarding flow over the local AP
- normal Wi-Fi association alone should not be treated as sufficient authorization for configuration changes once onboarding is complete
- if separate UI credentials are implemented, they should be distinct from the AP password

The device shall persist:

- AP credentials
- upstream credentials
- active preset
- custom shaping parameters
- saved presets
- management settings

## Verifiable Requirements

### Routing And Access

1. The device shall boot and offer a configurable Wi-Fi access point.
2. The device shall connect to an upstream Wi-Fi network as a station.
3. The device shall provide NAT-based Internet access to downstream clients.
4. A newly connected client shall be able to reach the local management UI.
5. Configuration shall persist across reboot.
6. A client device shall be able to use `SlowFi` by joining the Wi-Fi network alone, without requiring manual proxy settings, certificate installation, or app-specific configuration.

### Shaping Controls

7. The device shall support independent upstream and downstream bandwidth limits.
8. The device shall support configurable base latency.
9. The device shall support configurable jitter.
10. The device shall support configurable packet loss percentage.
11. The device shall support burst-loss or outage-window behavior.
12. The user shall be able to enable or disable shaping without reflashing firmware.
13. The user shall be able to switch between shipped presets from the UI.
14. The user shall be able to define and save at least one custom preset.
15. Each shipped preset shall map to documented shaping values or ranges for bandwidth, latency, jitter, loss, and burst or outage behavior.

### Behavior

16. With shaping disabled, traffic shall flow through the hotspot without intentional impairment.
17. With a bandwidth cap enabled, measured throughput shall be lower than unshaped throughput in the capped direction.
18. With latency enabled, median request latency shall increase relative to unshaped traffic.
19. With loss enabled, repeated transfer tests shall show non-zero packet loss or failed requests consistent with the configured impairment.
20. With burst-loss enabled, transfers shall occasionally experience clustered failures rather than only isolated drops.
21. Queue growth shall be bounded under sustained load.
22. Under queue saturation, the system shall drop packets rather than hang or exhaust memory indefinitely.

### UI And Observability

23. The UI shall display the currently active preset or custom profile.
24. The UI shall display whether shaping is currently enabled.
25. The UI shall display counters for forwarded traffic and dropped traffic.
26. The UI shall display the currently applied shaping parameter values.
27. The UI shall reflect profile changes without requiring a firmware rebuild.

### Reliability

28. The device shall remain reachable via Wi-Fi and UI during normal shaping operation with at least one active client.
29. The device shall recover cleanly from upstream disconnect and reconnect.
30. Invalid shaping inputs shall be rejected or clamped to safe ranges.
31. If shaping cannot be applied safely, the device shall surface an error state rather than silently claiming success.

### Security

32. The hotspot shall support a configurable AP password.
33. The local management UI shall require authentication or equivalent access protection before configuration changes can be made.
34. Remote administration from the upstream-facing interface shall be disabled by default.
35. Monitoring or traffic-inspection features, if present, shall be disabled by default and shall present a visible warning when enabled.

### Documentation

36. The project shall document the difference between believable bad-network testing and exact carrier emulation.
37. The project shall document known limits for throughput, client count, and protocol fidelity.
38. Each shipped preset shall document its intended testing scenario.

## Acceptance Checks

Recommended manual checks for validation:

1. Connect a phone or laptop to `SlowFi` and confirm Internet access with shaping disabled.
2. Confirm the client can use the hotspot without setting a proxy, installing a certificate, or changing app-specific network settings.
3. Enable `Weak 3G` and confirm a speed test or file download slows materially.
4. Enable a latency-heavy preset and confirm page or API round-trip times increase.
5. Enable a burst-loss preset and confirm retries, stalls, or clustered failures occur.
6. Reboot the device and confirm preset and configuration persistence.
7. Saturate traffic and confirm the device remains responsive while queue drops stay bounded.
8. Disconnect the upstream network and confirm status reporting and recovery after reconnect.
