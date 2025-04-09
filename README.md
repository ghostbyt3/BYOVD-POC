# BYOVD POC

This repo contains proof-of-concepts (PoCs) demonstrating BYOVD (Bring Your Own Vulnerable Driver) techniques by exploiting flaws in signed drivers. These drivers are either not included in [Microsoft's blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) or have been previously overlooked.

## POCs

| Driver | Link | POC | Type | HVCI Blocked |
| ------------- | ------ | ------ | ------ | ------ |
| TrueSight.sys | [LOLDrivers](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/) | [POC](./poc/edr-killer/truesight/) | EDR Killer | No |
| TfSysMon.sys | [LOLDrivers](https://www.loldrivers.io/drivers/bd9f084e-b235-4978-bf2a-5f1dc02937df/) | [POC](./poc/edr-killer/tfsysmon/) | EDR Killer | Yes |
| Viragt64.sys | [LOLDrivers](https://www.loldrivers.io/drivers/7edb5602-239f-460a-89d6-363ff1059765/) | [POC](./poc/edr-killer/viragt64/) | EDR Killer | No |
