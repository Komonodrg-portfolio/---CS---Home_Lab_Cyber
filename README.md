### [Home](https://github.com/Komonodrg-portfolio)  | [Cybersecurity](https://github.com/Komonodrg-portfolio/Cybersecurity) | [Networking](https://github.com/Komonodrg-portfolio/Networking) | [Data Science (AI)](https://github.com/Komonodrg-portfolio/AI) | [Media Creation](https://github.com/Komonodrg-portfolio/MediaCreation) | [Mission](https://github.com/Komonodrg-portfolio/Mission/)

---
---

# Wazuh SIEM & XDR Deployment  

## 📌 Goals
This project demonstrates the deployment of a **Wazuh SIEM & XRD instance** three different ways to in order to provide different methods to deploy based on hardware and financial resources, in conjuction with aligning with principles of my [mission](https://github.com/Komonodrg-portfolio/Mission/).  

It highlights skills in:
- Barebone deployment, for dedicated security devices
- Virtualization and hypervisor management (**VMWare, Proxmox VE**)  
- Security Information and Event Management (**Wazuh**)
- Actions against unified view of threats and automates remediation (**XDR**) 
- System administration and Linux server setup  
- Log collection, monitoring, and security alerting

---
## 🧰 Tools & Technologies

| Tool       | Purpose                              |
|------------|--------------------------------------|
| Proxmox VE     | Type-1 hypervisor for virtualization         |
| VMWare Workstation | Type-2 hypervisor for virtualization         |
| Wazuh | Open-source SIEM & XDR platform         |
| Debian/Ubuntu    | Guest OS for Wazuh server          |
| Nginx  | Reverse proxy for web dashboard (optional)                      |
| Suricata, Wazuh, Syslog  | Log collection and injestion agents and protocol         |


---

## 📂 Repository Structure
```plaintext
.
├── docs/                # Deployment notes, diagrams, and documentation
├── configs/             # Example config files (Proxmox VM, Wazuh settings)
├── screenshots/         # Screenshots for setup and final dashboard
├── scripts/             # Helper scripts for automation
└── README.md            # Project overview (this file)

[ Bare-metal Hardware ]
          │
      Proxmox VE
          │
   ┌───────────────┐
   │ Wazuh Server  │
   │   (VM)        │
   └───────────────┘
          │
   ┌──────┴──────┐
   │ Wazuh Agents│ (Linux, Windows, Network Devices)
   └─────────────┘
```
## 🛠️  Setup Instructions
<details>
 <summary><h4><b>  A)  Barebone Deployment"</b></h4></summary>
  <br> 
This method involves installing Wazuh Server on a standalone PC/Laptop.  This deployment is best to use if you want a dedicated security appliance to monitor and protect your home network.<br>  
<br>
Create a <a href="https://chatgpt.com/s/t_68e1cb99a0088191bb1937e92241f81a" target="_blank">Ventoy USB drive</a> and boot PC/laptop off of a <a href="hhttps://releases.ubuntu.com/jammy/" target="_blank">Ubuntu 22.04 Server.iso</a> file to intiate installation.  Make sure to be on network during installation and eventually after it completes installation, you'll be granted with login instructions and credentials for web gui to access from the browser of another computer on the network:<br>
<br>

          
| VMWare Workstation | Type-2 hypervisor for virtualization         |
| Wazuh | Open-source SIEM & XDR platform         |
| Debian/Ubuntu    | Guest OS for Wazuh server          |
| Nginx  | Reverse proxy for web dashboard (optional)                      |
| Suricata, Wazuh, Syslog  | Log collection and injestion agents and protocol         |
          
</details>

🚀 Deployment Steps
1. Install Proxmox VE on Bare-Metal

Install Proxmox from ISO and configure storage/networking.

Apply latest updates.

2. Create VM for Wazuh Server

Allocate resources: 4 vCPU, 8 GB RAM, 100 GB Disk.

Install Debian/Ubuntu minimal.

3. Install & Configure Wazuh

Update packages and install dependencies.

Deploy Wazuh Manager + Dashboard.

Configure HTTPS for secure web access.

4. Add Wazuh Agents

Install agents on Linux/Windows endpoints.

Register them with Wazuh Manager.

Confirm agent connectivity.

5. Test & Validate

Simulate failed SSH login or other security events.

Confirm alerts in Wazuh dashboard.

📊 Sample Output

Wazuh Dashboard (placeholder screenshot):


Example Alert:

