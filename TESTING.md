# Phase 6 — L2 Repeater Hardware Test Matrix

## 0. Build & baseline
- [ ] `CONFIG_REPEATER_MODE=n`: build succeeds, flashes, boots, web UI reachable — confirms we didn't break the NAT-router baseline.
- [ ] `CONFIG_REPEATER_MODE=y`: build succeeds, flashes, boots.
- [ ] Log on boot shows `Repeater mode: L2 bridge (no NAPT)` and `Repeater forwarding initialized`.
- [ ] `repeater show` in the console prints empty FDB + XID tables.

## 1. Station-side connectivity (ESP itself)
- [ ] Configure STA with upstream SSID; STA associates, gets DHCP lease on the upstream subnet.
- [ ] From a machine on the upstream LAN, `ping <ESP_STA_IP>` succeeds — confirms the netif-hook early-return for "dst == our IP" is working and we didn't accidentally bridge it.
- [ ] Web UI reachable at `http://<ESP_STA_IP>/`.

## 2. softAP base association (no bridging yet)
- [ ] A client associates to the ESP AP. MAC appears in `sta` command output (AP association list).
- [ ] Client **does not** get a DHCP lease yet — that's expected. We need step 3 for that.

## 3. DHCP proxy via bridge (the first real test)
- [ ] With packet capture running on upstream (mirror port / tcpdump on the upstream router), connect a client to our ESP AP.
- [ ] Expect: `DHCPDISCOVER` from `chaddr=client_MAC` reaches upstream DHCP server, with L2 src = **ESP STA MAC** (MAC-translated).
- [ ] Expect: `DHCPOFFER`/`DHCPACK` returns to L2 dst = **ESP STA MAC**, then is rewritten to L2 dst = `client_MAC` and emitted on AP.
- [ ] Client gets an IP **on the upstream subnet** (same /24 as ESP STA IP).
- [ ] `repeater show` now contains: one XID entry during the transaction (ephemeral), and one FDB entry `<client_IP> <client_MAC>` after ACK.
- [ ] Log shows `DHCP lease learned mac=…`.

**If this fails:** check XID map is populated (snoop side), check STA rx hook is firing, check the ACK's `yiaddr` isn't being zeroed by some filter.

## 4. ARP reachability (the critical softAP filter test)
- [ ] From the client, `ping <upstream_gateway_IP>`.
- [ ] First reply arrives → means ARP round-trip succeeded via our bridge.
- [ ] Sustained pings: **does it keep working past the first second?**
  - ✅ **Continues working**: softAP is permissive — bridge is viable as-is.
  - ❌ **Breaks after ARP cache populates**: softAP strictly filters by L2 dst. We need proxy-ARP. Document which ESP-IDF + chip combination exhibits this.
- [ ] `arp -a` on the client: note whether the gateway entry shows the **real upstream GW MAC** or the **ESP AP MAC**. This tells us which case we're in.

## 5. Broader L3 traffic
- [ ] Client → Internet HTTP/HTTPS (curl, browser). Record throughput (ballpark, vs. direct connection to upstream).
- [ ] Client → Internet DNS (`dig @8.8.8.8`).
- [ ] Client → upstream LAN peer (another device on the same subnet, **not** on ESP AP). Tests bidirectional bridge.
- [ ] Upstream peer → client (initiated from upstream side). This is the reverse-direction FDB lookup — most likely to fail first.
- [ ] iperf3 in both directions; note if it's meaningfully slower than NAT mode.

## 6. Client lifecycle
- [ ] Client disconnects and reconnects: gets same lease (DHCP server's decision), FDB re-learns.
- [ ] Two clients simultaneously: each gets distinct IP, both reachable, FDB has two entries.
- [ ] Let FDB entries age past `REPEATER_FDB_DEFAULT_TTL_S` (600s) with client idle — confirm `repeater show` drops them; confirm first packet after expiry re-learns.
- [ ] `repeater clear` followed by client traffic: FDB repopulates from the first IP packet / DHCP renewal.

## 7. Edge cases / failure modes
- [ ] IPv6-only traffic from client: currently dropped by bridge (handler returns false, lwIP has no route) — confirm it dies cleanly, no crash.
- [ ] Broadcast storms: mDNS/NBNS/SSDP flood from upstream — confirm ESP doesn't hang or miss keepalives.
- [ ] DHCP server with Option 82 / relay-agent-info: does upstream still give out leases?
- [ ] Client MAC randomization (modern phones): new MAC per SSID — does `chaddr` in DHCP still match the L2 src? It should, but verify.
- [ ] Power cycle ESP during active client traffic: client should recover within ~DHCP retry window.

## 8. Regression: NAT mode still clean
- [ ] Reflash with `CONFIG_REPEATER_MODE=n`. Confirm: NAPT enabled, AP DHCPS hands out leases, portmap CLI + UI present, NAT checkbox on config page functional.
- [ ] `repeater` command **not** registered (should return "Unrecognized command").

## 9. Data to record per test pass
For each hardware target tested (esp32c3, c6, s3, etc.):
- ESP-IDF version
- Which AP-side filter behavior (step 4)
- Throughput numbers (step 5)
- Any WiFi disconnects / driver errors in logs
- FDB hit rate after warm-up (informal)

---

**Gating decision for production:** Step 4 is the hinge. If the softAP filters strictly on all our target chips, proxy-ARP is a blocker for Phase 7 (not yet scoped). If it passes, the current bridge is functional and Phase 6 ships.
