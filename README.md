### [Home](https://github.com/Komonodrg-portfolio)  | [Cybersecurity](https://github.com/Komonodrg-portfolio/Cybersecurity) | [Networking](https://github.com/Komonodrg-portfolio/Networking) | [Data Science (AI)](https://github.com/Komonodrg-portfolio/AI) | [Media Creation](https://github.com/Komonodrg-portfolio/MediaCreation) | [Mission](https://github.com/Komonodrg-portfolio/Mission/)

---
---

# Wazuh SIEM & XDR Deployment  

## 📌 Goals
This project demonstrates the deployment of a **Wazuh SIEM & XRD instance** three different ways to in order to provide different methods to deploy based on hardware and financial resources, in conjuction with aligning with principles of my [mission](https://github.com/Komonodrg-portfolio/Mission/).  

It highlights skills in:
- Barebone deployment, for dedicated security device
- Virtualization and hypervisor management (**VMWare**)  
- Security Information and Event Management (**Wazuh**)
- Actions against unified view of threats and automates remediation (**XDR**) 
- System (OS) administration and Windows/Linux server setup  
- Log collection, monitoring, and security alerting

---
## 🧰 Tools & Technologies

| Tool       | Purpose                              |
|------------|--------------------------------------|
| VMWare Workstation | Type-2 hypervisor for virtualization         |
| Wazuh | Open-source SIEM & XDR platform         |
| Debian/Ubuntu    | Guest OS for Wazuh server          |
| Nginx  | Reverse proxy for web dashboard (optional)                      |
| Suricata, Wazuh, Syslog  | Log collection and injestion agents and protocol         |


---

## 📂 Topology

---

## 🛠️  Setup Instructions
<details>
 <summary><h4><b>  A)  Wazuh Server (standalone) Deployment"</b></h4></summary>
  <br> 
This method involves installing Wazuh Server on a standalone PC/Laptop.  This deployment is best to use if you want a dedicated security appliance to monitor and protect your home network.<br>  
<br>
Create a <a href="https://chatgpt.com/s/t_68e1cb99a0088191bb1937e92241f81a" target="_blank">Ventoy USB drive</a> and boot PC/laptop off of a <a href="https://releases.ubuntu.com/jammy/" target="_blank">Ubuntu 22.04 Server.iso</a> file to intiate installation.  Make sure to be on network during installation and eventually after it completes installation, you'll be granted with login instructions and credentials for web gui to access from the browser of another computer on the network:<br>
<br>
<p float="center">
  <img src="images/UbuntuServerSelect.png" width="200" />
  <img src="images/Ventoy.png" width="200" />
  <img src="images/wazuhinstallcomplete.png" width="200" />
          
| VMWare Workstation | Type-2 hypervisor for virtualization         |
| Wazuh | Open-source SIEM & XDR platform         |
| Debian/Ubuntu    | Guest OS for Wazuh server          |
| Nginx  | Reverse proxy for web dashboard (optional)                      |
| Suricata, Wazuh, Syslog  | Log collection and injestion agents and protocol         |
          
</details>

<details>
 <summary><h4><b>  B)  Windows Server 2022 Setup</b></h4></summary>
  <br> 
This is intial setup of Windows Server 2022 from within VMWare. <br>  
<br>

 <p align="left">
  <img src="images/Server1.png" width="800" /><br>
<br>

```
1) Change server name
   └─ Computer Name > click "Change..." > Enter new name > OK > Restart

2) Enable Remote Desktop (allowing vulnerability for extra log generation/events from within cyber range)
   └─ Remote Desktop > select "Allow remote connections to this computer"

3) Disable IPv6 while and setup static IP address & DNS for server
   └─ Ethernet0 > right click on network adapter, select "Properties" > uncheck "IPv6" >
      select IPv4 > Set up static IP & DNS servers

4) Change Time Zone
   └─ "Change time zone..." > select appropriately
```
</details>

<details>
 <summary><h4><b>  C)  Windows 10 (Victim) VM Setup</b></h4></summary>
  <br> 
<h4> Enable Powershell Logging </h4>  

 <p align="left">
  <img src="images/WIn1.png" width="800" /><br>

```
Startup gpedit.msc > Computer Configuration > Administrative Templates > Windows Powershell
   └─ Enable Module Logging, click "Show" and enter "*" wildcard to encompass all modules
   └─ Enable Powershell Transcription, placing a check for include invocation headers (timestamps)
   └─ Enable Script Block Logging DON'T enable invocation headers
```
<h4> Enable Firewall (Defender) Logging </h4> 

<p align="left">
  <img src="images/Win2.png" width="800" /><br>

```
1) Startup gpedit.msc > Computer Configuration > Windows Settings > Windows Firewall w/ Advanced Security
   > Windows Defender Firewall Properties
2) Turn on Firewall, blocking inbound connections, allowing outbound connections
3) Do the same for Profile & Public Profiles
4) Customize...
5) Remove check to enable Logs, select "Yes" for Log dropped packets & successful connections
6) ...Do the same on Private and Public Profiles
```
<h4> Enable SYSMON Logging </h4> 
<br>

1) Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and extract it to C:/Program Files/Sysmon folder<br>
2) Download [Olaf Hartong](https://github.com/olafhartong/sysmon-modular) sysmon configuration file and extract contents to C:/Program Files/Sysmon folder<br>

<p align="left">
  <img src="images/Win3.png" width="500" /><br>

3) From CMD (administrative), navigate to C:/Program Files/Sysmon folder & run, which installs sysmon with olaf config file:
```
cd C:\Program Files\Sysmon
sysmon64.exe -i sysmonconfig.xml
```
4) Verify successful Sysmon installation via `services.msc`:

<p align="left">
  <img src="images/Win4.png" width="950" /><br>


