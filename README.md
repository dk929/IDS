 Mini Intrusion Detection System (IDS) using Scapy

**Project:** Custom lightweight Network IDS for lab use  
**Author:** Your Name  
**Repo:** (replace with your GitHub URL)

---

## 🚀 Project Overview

This repository contains a simple, extendable **Intrusion Detection System (IDS)** prototype built with **Python + Scapy**.  
It captures live packets on an interface, applies basic heuristics to detect suspicious behaviour (port scans, ICMP floods), logs alerts to `alerts.log`, and prints real-time notifications to the console.

This project is intended for **learning and lab environments only**. Do NOT run it on production networks without permission.

---

## ⚙️ Features

- Live packet capture using Scapy
- Basic detection rules:
  - Port-scan detection (multiple destination ports from same source)
  - ICMP flood detection (excessive ping traffic)
- Persistent alert logging to `alerts.log`
- Easy to extend: add email/Slack alerts, GeoIP lookups, DB storage, or dashboards
