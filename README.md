# ARP Spoofer

A Python tool that performs ARP poisoning to position itself as a man-in-the-middle between a target device and its router, intercepting all traffic between them. Linux only.

> **Disclaimer:** For educational purposes and authorized testing only. Only use on networks you own or have explicit permission to test. ARP spoofing on unauthorized networks is illegal. The author is not responsible for any misuse.

---

## How it works

1. Continuously sends spoofed ARP replies to both the target and the router
2. This poisons their ARP caches — making each think the attacker's MAC is the other's IP
3. All traffic between them flows through the attacker's machine
4. On exit (`Ctrl+C`), the ARP tables are automatically restored

## Requirements

```bash
pip install -r requirements.txt
```

> **Note:** Linux only. Requires root privileges.

## Usage

```bash
sudo python3 arp_spoofer.py -t <target_ip> -r <router_ip>
```

```bash
sudo python3 arp_spoofer.py -t 192.168.1.5 -r 192.168.1.1
```

Use `--help` for all options. Press `Ctrl+C` to stop and restore ARP tables automatically.

**Combine with [packet_sniffer](https://github.com/shubham-patel/packet_sniffer)** to intercept and inspect HTTP traffic from the target device.

---

## Part of [H-Tools](https://github.com/shubham-patel/H-Tools)

Built during B.Tech studies. H-Tools bundles this and other networking/security utilities in a single CLI menu.
