# SOC Analyst Home Lab — Investigation Portfolio

A self-built Active Directory + Elastic SIEM lab used to generate, detect, and investigate
security scenarios end-to-end — from attack/simulation through to a written incident report.

Built as hands-on preparation for **UK SOC analyst / cybersecurity analyst** roles, alongside
**CompTIA CySA+** (CS0-004) study.

---

## What's in this repo

| Folder | Contents |
|---|---|
| [docs/lab-architecture.md](docs/lab-architecture.md) | Full lab build: network diagram, VM inventory, tools, key design decisions |
| [scenarios/](scenarios/) | One folder per investigated alert — each is a self-contained incident report |
| [templates/scenario-template.md](templates/scenario-template.md) | The blank template every scenario report follows |

---

## Skills demonstrated

- SIEM administration and detection engineering (Elastic Security / Kibana, KQL, threshold rules)
- Network segmentation and firewall administration (pfSense, Suricata IDS/ET Open ruleset)
- Active Directory build and management (Windows Server, DHCP/DNS/AD DS)
- Endpoint instrumentation (Sysmon, Elastic Agent/Fleet)
- Log correlation across multiple sources (Windows Security log ↔ Sysmon ↔ network IDS)
- MITRE ATT&CK-mapped incident documentation
- Methodical troubleshooting (see architecture doc for real build issues diagnosed and fixed)

---

## Scenario index

| # | Scenario | ATT&CK Technique | Verdict | Report |
|---|---|---|---|---|
| 001 | Multiple failed logons → successful authentication | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) | True Positive (Simulated) | [View](scenarios/001-brute-force-failed-logon/README.md) |

*(New rows are added here as each scenario is completed — see the template for the format.)*

---

## Lab at a glance

````
                        WAN (VMnet8 NAT)
                         │
                      pfSense (Firewall + Suricata IDS)
                         │
      ┌──────────────────┴─────────────────┐
      │                                    │
10.10.10.0/24                        10.10.20.0/24
Corporate (AD domain: lab.local)     Attacker segment
* DC2016                             * Kali linux
* WIN11-01
      │
      └── Elastic Agent / Sysmon ──► Elastic Security (elastic01)
```

Full detail, including firewall rules, DHCP/NTP config, and Suricata tuning decisions, is in
[docs/lab-architecture.md](docs/lab-architecture.md).

---

## About

Built and documented by [Peter](https://github.com/PetsS) as part of a structured and phased home lab project —
architecture decided before building, one capability added at a time, each investigation
documented the way a real SOC incident report would be written.