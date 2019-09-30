# How it works

To capture and interpret network traffic, QEMU virtual machines are used on the server virtualization management platform [Proxmox VE](https://www.proxmox.com/en/) based on:

* Windows 10 Pro 64bits with automatic updates enabled.
* Windows 8.1 Pro 64bits with automatic updates enabled.
* Windows 7 SP1 Pro 64bits with automatic updates enabled.

Traffic dumps are cleaned monthly and compared with the current rules to update hosts and firewall rules. Tools used to capture traffic:

* `qemu -net dump` : capture
* [Wireshark](app/dev/wireshark.md) : capture + logs
* [Sysmon](app/dev/sysmon.md) : capture + logs
* [Proxifier](app/dev/proxifier.md) : logs

> Go to [Usage](usage.md) page
