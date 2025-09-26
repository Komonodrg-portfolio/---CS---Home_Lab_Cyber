### [Home](https://github.com/Komonodrg-portfolio)  | [Cybersecurity](https://github.com/Komonodrg-portfolio/Cybersecurity) | [Networking](https://github.com/Komonodrg-portfolio/Networking) | [Data Science (AI)](https://github.com/Komonodrg-portfolio/AI) | [Media Creation](https://github.com/Komonodrg-portfolio/MediaCreation) | [Mission](https://github.com/Komonodrg-portfolio/Mission/)

---
---

# Wazuh SIEM & XDR Deployment on Proxmox (Bare-Metal)  🛠️

## 📌 Goals
This project demonstrates the deployment of a **Wazuh SIEM instance** inside a **Proxmox bare-metal hypervisor** environment.  

It highlights skills in:  
- Virtualization and hypervisor management (**Proxmox VE**)  
- Security Information and Event Management (**Wazuh**)  
- System administration and Linux server setup  
- Log collection, monitoring, and security alerting  

---
## 🧰 Tools & Technologies

| Tool       | Purpose                              |
|------------|--------------------------------------|
| Proxmox VE     | Type-1 hypervisor for virtualization         |
| Wazuh | Open-source SIEM & XDR platform         |
| Debian/Ubuntu    | Guest OS for Wazuh server          |
| Nginx  | Reverse proxy for web dashboard (optional)                      |
| Suricata, Filebeat, Winlogbeat – Example agents for log collection  | Log collection and injestion agents          |


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
## 🔧 Setup Instructions



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

