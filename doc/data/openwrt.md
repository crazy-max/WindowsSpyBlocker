# Data - OpenWrt

DNS/IP block rules using dnsmasq/iptables are available in [`data/openwrt`](../../data/openwrt) folder. These rules are focused on latest OpenWrt release (Chaos Calmer 15.05.1).

Requires package "iptables-mod-nat-extra" for port 53 (DNS) redirect rule from dnsmasq.conf. `dnsmasq.conf` is bypassed if you use DNSCrypt on client machine (recommended) so use hosts before DNSCrypt exit point.

DNSCrypt is also available in OpenWrt repo, but may be slow and CPU hungry on average routers, stay with the PC client as recommended.
