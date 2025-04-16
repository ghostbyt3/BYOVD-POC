# BYOVD POC

This repo contains proof-of-concepts (PoCs) demonstrating BYOVD (Bring Your Own Vulnerable Driver) techniques by exploiting flaws in signed drivers. These drivers are either not included in [Microsoft's blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) or have been previously overlooked.

## POCs

| Driver | MD5 Hash | Download Link | Type | HVCI Blocked | VirusTotal | POC | 
| ------------- | ------ | ------ | ------ | ------ | ------ | ------ |
| TrueSight.sys | f53fa44c7b591a2be105344790543369 | [LOLDrivers](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/) | EDR Killer | No | [Result](https://www.virustotal.com/gui/file/bfc2ef3b404294fe2fa05a8b71c7f786b58519175b7202a69fe30f45e607ff1c) | [POC](./poc/edr-killer/truesight/) | 
| TfSysMon.sys | 761f2e2b759389a472bd3d94141742b9 | [LOLDrivers](https://www.loldrivers.io/drivers/bd9f084e-b235-4978-bf2a-5f1dc02937df/) | EDR Killer | Yes | [Result](https://www.virustotal.com/gui/file/1c1a4ca2cbac9fe5954763a20aeb82da9b10d028824f42fff071503dcbe15856) | [POC](./poc/edr-killer/tfsysmon/) |
| Viragt64.sys | 779af226b7b72ff9d78ce1f03d4a3389 | [LOLDrivers](https://www.loldrivers.io/drivers/7edb5602-239f-460a-89d6-363ff1059765/) | EDR Killer | No | [Result](https://www.virustotal.com/gui/file/18deed37f60b6aa8634dda2565a0485452487d7bce88afb49301a7352db4e506) | [POC](./poc/edr-killer/viragt64/) |
