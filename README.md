# Deck 8 One Step

<a href="https://www.buymeacoffee.com/mezantrop" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

Although the project is a bit outdated already, it requires to be rewritten to enhance the code and support new equipment
as well as fresh technologies, it still has some gems and interesting methods to have as reference
when writing code to enquire storage devices.

![d81s](d81s_screenshot.png?raw=true "D81S report")

D81S – simple SAN visualisation tool. It is developed to build a full map of a Fibre Channel Storage Area Network by tracing all paths from HBAs to storage logical devices. D81S scans SAN switches and storage systems to create a database of all volumes which are accessible by hosts and the same LUNs provided by storage systems.

Running in the virtual machine on my laptop it took ~15 minutes to process ~5000 of SAN ports and ~200 storage systems.

D81S supports:
* Brocade SAN via SSH
* Hitachi High-end and Midrange storage systems via Hitachi Command Suite (Device manager)
* HP Hi-end storage arrays via Command View AE.
* HP 3PAR 7400 storages via SSH
* HP EVA arrays via HP Command view EVA
* IBM TS3500 tape libraries via HTTP

D81S requires to run:
* Linux server
* Python 3 with several addition modules
* Mysql database
* D81S is a work in progress, so it doesn’t have GUI for now, but I am planning to create WEBUI for it.
