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
 <summary><h4><b>  A)  Barebone Deployment"</b></h4></summary>
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
1) Change server name <br> 
2) Enable Remote Desktop (allowing vulnerability for extra log generation/events from within cyber range)<br> 
3) Disable IPv6 while and setup static IP address for server <br> 
4) Change Time Zone<br> 
  
<h4>Promote Server to Domain Controller</h4>
 
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


