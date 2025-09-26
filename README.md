# Wazuh SIEM Deployment on Proxmox (Bare-Metal)

## 📌 Project Overview
This project demonstrates the deployment of a **Wazuh SIEM instance** inside a **Proxmox bare-metal hypervisor** environment.  

It highlights skills in:  
- Virtualization and hypervisor management (**Proxmox VE**)  
- Security Information and Event Management (**Wazuh**)  
- System administration and Linux server setup  
- Log collection, monitoring, and security alerting  

---

## 🛠️ Technologies Used
- **Proxmox VE** – Type-1 hypervisor for virtualization  
- **Wazuh** – Open-source SIEM platform  
- **Debian/Ubuntu** – Guest OS for Wazuh server  
- **Nginx** – Reverse proxy for web dashboard (optional)  
- **Suricata, Filebeat, Winlogbeat** – Example agents for log collection  

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
