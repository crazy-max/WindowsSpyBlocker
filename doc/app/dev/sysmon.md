# Dev - Sysmon

## About

**Sysmon** is an advanced background monitor that records process-related activity to the event log.

* https://technet.microsoft.com/en-us/sysinternals/sysmon

## Capture

This application is available through the WindowsSpyBlocker executable (see [sysmon.go](https://github.com/crazy-max/WindowsSpyBlocker/blob/master/app/cmds/dev/sysmon/sysmon.go#L60-L74) for more info).<br />
To install Sysmon, execute `WindowsSpyBlocker.exe` and choose the `Install` option in `Dev > Sysmon`.

![](../../.res/dev/sysmon/sysmon-install-20170515.png)

This installs Sysmon as a service that will survive reboots, collect network connection information, record MD5 hashes for all created processes, and record loading of modules.<br />
Everything will be recorded in the Windows event log in `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`.<br />
You can see every events in the Event Viewer window (Start > Run > eventvwr) :

![](../../.res/dev/sysmon/sysmon-eventviewer-20160602.png)
> Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

## Parsing

WindowsSpyBlocker can be used to parse events and generate CSV files.<br />
Before executing the script, do not forget to edit the `app.conf` file.

* **sysmon**
  * **evtxPath**: Path to the event log.
* **exclude**
  * **ips**: exclude IPs addresses from parsing. Ranges are allowed and in most cases you have to exclude your local network.
  * **hosts**: exclude domains from parsing. Wildcard are allowed and in most cases you have to exclude your local network.
  * **orgs**: exclude by whois organization from parsing. Wildcard are allowed and in most cases you have to exclude your ISP.

Then launch `WindowsSpyBlocker.exe` and select `Dev > Sysmon > Extract log` :

![](../../.res/dev/sysmon/sysmon-parsing-20170515.png)

CSV files will be generated in `logs/` folder :

* `sysmon-all.csv`
* `sysmon-hosts-count.csv`
* `sysmon-unique.csv`
