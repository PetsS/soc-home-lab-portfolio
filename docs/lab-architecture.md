# Lab Architecture

## Goals

Built as a hands-on complement to CompTIA CySA+ (CS0-004) study, with a deliberate focus on
tooling and workflows that transfer directly to UK commercial SOC environments (Splunk, Microsoft
Sentinel, QRadar-style investigation patterns), rather than exam-only knowledge.

## Host

| Component | Spec |
|---|---|
| Machine | Dell Precision 3450 |
| CPU | Intel i5-11500 @ 2.7GHz (11th gen, 6C/12T) |
| RAM | 32GB |
| Storage | 1TB NVMe (active VMs) + 3TB HDD (archive/on-demand VMs) |
| Hypervisor | VMware Workstation |

## Network Topology

```
                        WAN (VMnet8 NAT, 192.168.163.0/24)
                         │
                      pfSense (Firewall / Router / Suricata IDS)
                         │
      ┌──────────────────┴─────────────────┐
      │                                    │
10.10.10.0/24                        10.10.20.0/24
(VMnet2 — Corporate)                 (VMnet3 — Attacker)
```

### pfSense
| Interface | IP | Notes |
|:---|:---|:---|
| WAN (em0) | 192.168.163.128/24 | DHCP from VMnet8 NAT |
| LAN (em1) | 10.10.10.1/24 | Corporate segment |
| LAN2 (em2) | 10.10.20.1/24 | Attacker segment |

**Firewall policy:**
- LAN → LAN2: blocked
- LAN → WAN: allowed
- LAN2 → LAN: **allowed** (intentional — simulates an attacker with a foothold reaching the corporate network)
- LAN2 → WAN: allowed

## VM Inventory

| VM | Hostname | IP | Role |
|:---|:---|:---|:---|
| pfSense | — | .1 (LAN) / .1 (LAN2) | Firewall, routing, Suricata IDS |
| Windows Server 2016 | DC2016 | 10.10.10.10 | AD DS, DNS, DHCP for `lab.local` |
| Windows 11 | WIN11-01 | 10.10.10.101 (DHCP) | Domain-joined workstation, Sysmon |
| Ubuntu Server 24.04 | elastic01 | 10.10.10.20 (static) | Elasticsearch, Kibana, Fleet Server |
| Kali Linux | kali | 10.10.20.100 (DHCP) | Attacker machine |

## Detection Stack

- **SIEM**: Elastic Security (Elasticsearch + Kibana), single-node
- **Endpoint telemetry**: Elastic Agent (Fleet-managed) + Sysmon (SwiftOnSecurity config) on all Windows hosts
- **Network IDS**: Suricata on pfSense (WAN + LAN interfaces), Emerging Threats Open ruleset
- **Log forwarding**: pfSense syslog → Elastic Agent Custom UDP Logs integration (port 5514)

## Key Architecture Decisions

**Elastic Security over Wazuh** — chosen specifically for UK SOC market recognition and closer
structural resemblance to commercial SIEMs (KQL-style querying, timeline investigation, case
management), even though it carries more operational overhead (Fleet Server, JVM tuning) than
Wazuh's simpler agent model.

**HOME_NET/EXTERNAL_NET segmentation in Suricata** — pfSense's default "Home Net" treats all
directly-connected networks (both the corporate and attacker segments) as internal, which
silently breaks any detection rule that depends on distinguishing attacker traffic from internal
traffic. Fixed by scoping Home Net to the corporate subnet only, via a custom Alias assigned
through a Pass List (Aliases alone aren't selectable directly in this pfSense version).

**Deliberate rule tuning over blanket-enabling** — of the dozens of NMAP-variant signatures
available in Suricata's *emerging-scan* category, only two were enabled (matching the actual
scan behavior tested against), rather than turning on everything. Reduces alert fatigue and
mirrors how a real SOC tunes a ruleset to its environment rather than running vendor defaults
wholesale.

## Notable Build Issues Diagnosed

A sample of real troubleshooting from the build, kept here because working through infrastructure
problems methodically is itself a relevant SOC/analyst skill:

- **pfSense had internet but LAN clients didn't** — traced to a firewall rule using the
  `WAN subnets` alias as a destination, which only matches pfSense's directly-connected WAN
  network (192.168.163.0/24), not "the internet." Fixed by changing the destination to `any`.
- **Elastic Agent silently failed to execute on first install** — turned out to be an
  aarch64 (ARM) binary accidentally downloaded onto an x86_64 host. Always verify with
  `uname -m` and `file <binary>` before running an unfamiliar downloaded binary.
- **DHCP was issuing a /8 subnet mask instead of /24** from the AD-integrated DHCP scope,
  silently affecting how Windows clients treated the local network's boundaries. Fixed at
  the DHCP scope configuration level on the domain controller.

## Roadmap

- Network + firewall + IDS foundation
- AD domain + domain-joined endpoints with Sysmon
- Elastic Security stack + Fleet-managed agents
- Suricata detection validated end-to-end (Kali → corporate segment)
- pfSense → Elastic syslog forwarding validated end-to-end
- Baseline AD user creation and activity generation
- First custom detection rule (failed logon threshold, T1110)
- Atomic Red Team technique library, one scenario at a time
- Structured EVE JSON parsing (Suricata → ECS fields via Grok)
- Vulnerability scanning (OpenVAS/Greenbone)
