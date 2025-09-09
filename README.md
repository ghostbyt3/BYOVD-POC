# BYOVD POC

This repo contains proof-of-concepts (PoCs) demonstrating BYOVD (Bring Your Own Vulnerable Driver) techniques by exploiting flaws in signed drivers. These drivers are either not included in [Microsoft's blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) or have been previously overlooked.

## POCs

| Driver | MD5 Hash | Download Link | Type | HVCI Blocked | VirusTotal | POC | 
| ------------- | ------ | ------ | ------ | ------ | ------ | ------ |
| TrueSight.sys | f53fa44c7b591a2be105344790543369 | [LOLDrivers](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/) | EDR Killer | No | [Result](https://www.virustotal.com/gui/file/bfc2ef3b404294fe2fa05a8b71c7f786b58519175b7202a69fe30f45e607ff1c) | [POC](./poc/edr-killer/truesight/) | 
| TfSysMon.sys | 761f2e2b759389a472bd3d94141742b9 | [LOLDrivers](https://www.loldrivers.io/drivers/bd9f084e-b235-4978-bf2a-5f1dc02937df/) | EDR Killer | Yes | [Result](https://www.virustotal.com/gui/file/1c1a4ca2cbac9fe5954763a20aeb82da9b10d028824f42fff071503dcbe15856) | [POC](./poc/edr-killer/tfsysmon/) |
| Viragt64.sys | 779af226b7b72ff9d78ce1f03d4a3389 | [LOLDrivers](https://www.loldrivers.io/drivers/7edb5602-239f-460a-89d6-363ff1059765/) | EDR Killer | No | [Result](https://www.virustotal.com/gui/file/18deed37f60b6aa8634dda2565a0485452487d7bce88afb49301a7352db4e506) | [POC](./poc/edr-killer/viragt64/) |
| Winio64.sys | 8fc6cafd4e63a3271edf6a1897a892ae | [LOLDrivers](https://www.loldrivers.io/drivers/1ff757df-9a40-4f78-a28a-64830440abf7/) | EDR Callback Patch | No | [Result](https://www.virustotal.com/gui/file/15fb486b6b8c2a2f1b067f48fba10c2f164638fe5e6cee618fb84463578ecac9) | [POC](./poc/edr-callbacks/winio64/) |
| RTCore64.sys | 2d8e4f38b36c334d0a32a7324832501d | [LOLDrivers](https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/) | EDR Callback Patch | Not Sure | [Result](https://www.virustotal.com/gui/file/01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd) | [POC](./poc/edr-callbacks/rtcore64/)

## Other Resources

- https://vx-underground.org/Archive/Driver%20Collection
- https://github.com/wavestone-cdt/EDRSandblast/
- https://github.com/zeze-zeze/ioctlance
- https://github.com/0xJs/BYOVD_EDRKiller/
- https://github.com/BlackSnufkin/BYOVD

## Disclaimer

This repository is intended for educational and research purposes only. The PoCs provided here should not be used for any illegal activities or malicious purposes. The maintainers of this repository are not responsible for any misuse of the information and code provided here.
