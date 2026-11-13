# Discovery endpoints and network-scoped mDNS

`$PORTL_HOME/config/portl.toml` configures agent discovery and CLI client lookups. `PORTL_DISCOVERY`, when set, replaces the entire discovery section, including the mDNS policy. Restart after editing configuration; network-policy decisions are re-evaluated at runtime without a restart.

## Self-hosted HTTP pkarr without n0

```toml
[agent.discovery]
pkarr = ["https://fabade-1.thinh.dev/pkarr"]
dns = false
relays = ["https://fabade-1.thinh.dev/", "https://mifoka-1.thinh.dev/"]

[agent.discovery.local]
enabled = true
deny = [{ ssid = "TCB-BYOD" }, { ssid = "TCBS-INTERNET" }, { subnet = "10.61.176.0/20" }]
allow = []
unknown = "deny"
```

This publishes to and resolves from fabade-1 **over HTTP(S)**. DNS lookup is deliberately off: an HTTP pkarr relay is sufficient for resolving endpoint IDs, and fabade-1's DNS port is not public. Setting `dns = ["fabade-1.thinh.dev"]` would query the system DNS resolver for `_iroh.<endpoint-key>.fabade-1.thinh.dev`, not use the HTTPS pkarr service. The relay URLs above are configuration examples, not evidence that those servers expose working iroh relay services. No n0 relay, pkarr service, or discovery origin is implicitly appended to explicit lists. System DNS may still resolve the configured servers' hostnames; this is not n0 endpoint discovery.

The SSID deny rules above are fail-closed when SSIDs are unavailable. On a Mac that redacts every SSID, they will also disable mDNS at home. To enable mDNS at home without Location Services access, use a non-SSID policy instead, for example:

```toml
[agent.discovery.local]
enabled = true
allow = [{ interface = "en0", subnet = "192.168.50.0/24" }]
deny = [{ subnet = "10.61.176.0/20" }]
unknown = "deny"
```

Replace the home subnet/interface with the actual values. Do not combine a redacted SSID deny with a home allow and expect the allow to override uncertainty about the deny. Subnets, interface names and SSIDs are policy hints, not authenticated network identities: an attacker can reproduce them.

## Endpoint selection

`pkarr` and `dns` accept:

- `true`, `"default"` or `["default"]`: n0's built-in endpoint (including iroh's staging defaults when enabled).
- `false` or `[]`: disabled.
- A string or ordered list of strings: explicit endpoints; `"default"` may be mixed with custom entries.
- Omitted field: the compiled default, independently for each field.

Pkarr entries must be HTTP(S) URLs with a host, without credentials, query strings or fragments. Existing relay URL parsing is unchanged. The agent creates one publisher **and** one resolver for each URL. Ordinary dial clients resolve only; pairing preserves stable agent-style publication and mDNS advertising.

DNS entries are origin domains, optionally followed by `@IP:port` to choose a DNS nameserver. Without a nameserver, iroh uses the endpoint's system DNS resolver. Both IPv4 and IPv6 nameservers are supported; bracket IPv6 when specifying a port. A bare IP nameserver uses port 53.

```toml
[agent.discovery]
pkarr = ["https://my.example/pkarr", "default"]
dns = ["my.example@192.0.2.53:5353", "other.example@[2001:db8::53]:53", "default"]
local = false
relays = ["default"]
```

Lists retain configuration order and deduplicate equivalent entries. iroh 1.4.1 queries lookup services concurrently and publishes to every publisher; order is **not** a sequential fallback or strict priority guarantee. `dns` is lookup-only, not a publisher. Pkarr here is HTTP publishing/resolving, not Mainline DHT discovery.

Since iroh 1.4, pkarr publishing and resolving inherit the endpoint's proxy URL, selected by Portl for the first configured relay. When present, that proxy applies to every pkarr URL too, without per-pkarr `NO_PROXY` evaluation. Without an endpoint proxy, pkarr still uses standard HTTP proxy environment settings. Relay-free endpoints now update advertised local addresses on interface changes without waiting for relay probes.

Environment equivalents keep the old `dns,pkarr,local,relay` and `none` meanings. Add custom entries with `pkarr:<URL>`, `dns:<origin>[@nameserver]` and `relay:<URL>`; `=` is an alias for `:`. Repeat tokens to select multiple endpoints. Bare `pkarr`, `dns` and `relay` add their defaults. For example, `PORTL_DISCOVERY=pkarr:https://fabade-1.thinh.dev/pkarr,relay:https://fabade-1.thinh.dev/,relay:https://mifoka-1.thinh.dev/` enables only those remote services and disables mDNS. Use TOML for network-scoped mDNS; the environment's bare `local` means unrestricted mDNS, as before.

With relays, DNS and pkarr all off, Portl installs its existing local-only DNS resolver rather than initializing system DNS. With custom remote services enabled it retains system hostname resolution, even when every n0 service is off.

## mDNS policy and precedence

`local = true|false` remains a shorthand. The table form accepts `enabled` (default true), `allow`, `deny` (both default empty) and `unknown = "allow"|"deny"`.

Each rule supports exact, case-sensitive `ssid`, exact `interface` name, and an IPv4/IPv6 `subnet` CIDR containing an address assigned to that interface. Multiple fields in one rule are ANDed. Separate rules are ORed. Empty rules and invalid CIDRs are rejected. Interface *types* and gateway matching are intentionally not implemented: names and address CIDRs are the minimal portable fallbacks, without guessing that `en0` always means Wi-Fi or that a VPN's default gateway is the Wi-Fi gateway.

1. `enabled = false` disables mDNS.
2. A definite deny match on **any** active network disables mDNS, regardless of allows or `unknown`.
3. If a deny rule could match but a required SSID is unavailable, apply `unknown`. A matching allow does not override this uncertainty.
4. If `allow` is nonempty, **every** active network must match an allow. A definite nonmatch denies; an indeterminate SSID match uses `unknown`.
5. Otherwise allow. With no active network, use `unknown`.

`unknown` defaults to **deny when any rule exists**, or allow without rules to preserve `local = true`. Unknown applies to unavailable matcher information, not to a definite known mismatch. A rule constrained to a different interface or subnet is a definite nonmatch even if the SSID is unavailable.

The upstream mDNS implementation uses process-wide multicast sockets, not per-interface policy controls. Portl therefore gates the entire service: any denied interface turns advertising **and** resolution off everywhere. Policy examines all up interfaces with non-loopback, non-unspecified assigned addresses, including bridges, tunnels and link-local addresses, not just the default route. Allowlist users may need to account for additional active interfaces; this conservative choice avoids leaking on a denied Wi-Fi while Ethernet/VPN is allowed.

On deny, Portl drops the mDNS actor and sockets and cancels in-flight lookup streams. On allow it creates a fresh instance and republishes retained endpoint data; no denied-network mDNS cache survives. Previously discovered addresses already held by iroh/connections are not revoked: this is a discovery control, not a packet firewall or connection access policy.

The mDNS 0.6.1 upgrade refreshes cached peer addresses when advertisements change and suppresses unchanged refresh notifications. It adds an optional discovery cadence API; Portl retains the 700 ms default and 10-second unsuccessful lookup deadline. This does not change service ownership, policy gating, or the separate SSID recheck below.

Portl uses the same `netwatch` OS interface/route notifications as iroh, via a separate monitor because iroh does not expose its internal monitor. It quiesces mDNS on a notification before collecting the new identity. Netwatch 0.19.3 suppresses events when the interface/IP snapshot is unchanged; SSID-only roaming can therefore be invisible. A 10-second identity recheck covers that case and retries transient detection/socket failures. Each helper command has a two-second timeout. Detection is best-effort and not instantaneous: debounce, helper latency and unreported SSID-only roams leave a transition window. For a strict guarantee on untrusted networks, disable mDNS entirely or enforce multicast restrictions in the OS firewall.

`portl status` shows configured pkarr/DNS endpoints and current mDNS active state, reason and network summary; JSON adds these fields without changing existing backend booleans. `portl doctor` shows effective remote endpoints. Every mDNS state/identity transition is logged at info level, without MAC addresses, BSSIDs, identity secrets or tickets. SSIDs, interface names and local addresses are included in the summary.

## SSID detection and platform limits

**macOS:** Portl first reads `/usr/sbin/ipconfig getsummary <interface>` and accepts a visible `SSID :` value. If the field is absent it tries `/usr/sbin/networksetup -getairportnetwork <interface>`. Empty, missing, failed or `<redacted>` results are unknown, never a known nonmatch. These read-only helpers require no added application framework or interactive prompt, but do **not** bypass privacy controls. Portl does not run privileged `wdutil`, scan with `system_profiler`, or install a CoreLocation permission helper.

Apple DTS [confirms that Sonoma's CoreWLAN SSID property requires Location Services to be enabled and the calling app to be authorized](https://developer.apple.com/forums/thread/732431). That discussion also says a launchd agent *can* obtain the information, while asking how it is associated with and installed by a GUI app; it does not establish that a standalone Portl LaunchAgent has authorization. Direct CoreWLAN use without authorization is therefore not a reliable alternative. A GUI application's or interactive terminal's success does not prove the LaunchAgent's access. Local Network permission is separate from Location Services.

**Evidence boundary:** the owner observed `ipconfig` redaction on their Mac. This change is developed and tested in a Linux orb, not in that LaunchAgent. Helper output parsing and unknown-policy behavior are tested, but successful macOS SSID access from launchd is **not verified or promised**. A permission-associated application may make it available; otherwise rely on interface/subnet rules. No universally reliable permission-free macOS 14+ SSID method was established.

**Linux:** Portl tries `iw dev <interface> link`, then NetworkManager's active SSID via `nmcli` (with rescanning disabled) on interfaces identified by `/proc/net/wireless`. `/proc/net/wireless` alone does not contain an SSID. Missing tools, permissions, non-NetworkManager setups or unavailable SSIDs yield unknown. Neither tool is required for interface/subnet matching. Other operating systems currently use unknown SSIDs and retain interface/subnet rules.
