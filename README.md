# Sentinel AI - AI-Driven DDoS Detection System for 5G Networks

An advanced, real-time system designed for intelligent DDoS detection and mitigation in 5G networks, integrating machine learning, SDN (Software Defined Networking), and slice-specific network management. Sentinel AI autonomously detects threats, manages network slices, and recovers from attacks, providing a robust platform for both research and production scenarios.

---

## Features

- **Simulated & Real-Time Network Monitoring**: Analyzes both live and simulated traffic for anomaly detection.
- **AI-Powered Detection**: Utilizes machine learning (Random Forest ensemble) for DDoS detection.
- **5G Network Slice Management**: Supports management for eMBB, URLLC, and mMTC slices.
- **Autonomous Mitigation**: Self-healing and automated threat response for minimal downtime.
- **Web Dashboard**: Interactive, real-time charts and alerts for monitoring.
- **API Integration**: Integrates with AbuseIPDB for external IP reputation checks.
- **SDN-Enabled**: Dynamic network flow control using SDN principles.
- **Self-Healing Framework**: Isolates attacks and recovers services automatically.
- **Highly Portable**: Works in simulation or with real packet data (Wireshark/tshark).

---

## Directory Structure

```
Ly-Project/
│
├── backend/                 # Node.js backend API
│   ├── controllers/
│   ├── models/
│   ├── routes/
│   ├── utils/
│   ├── config/
│   ├── services/
│   ├── tests/
│   └── index.js
│
├── frontend/                # React + Vite frontend UI
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── assets/
│   │   ├── utils/
│   │   ├── api/
│   │   └── App.jsx/tsx
│   ├── public/
│   └── vite.config.js
│
├── model/                   # Python ML Model (Flask API)
│   ├── app/
│   │   ├── ml/
│   │   ├── api/
│   │   ├── utils/
│   │   └── app.py
│   ├── tests/
│   └── requirements.txt
│
├── scripts/                 # (Optional) Helper dev scripts
├── config/                  # (Optional) Shared/global settings
├── docs/                    # (Optional) Documentation, diagrams, papers
├── .gitignore
├── README.md
├── LICENSE
└── docker-compose.yml       # (Optional) Container orchestration
```

---

## Technologies Used

- **Frontend**: React, Vite, JavaScript/TypeScript, Live charting libraries
- **Backend**: Node.js, Express, REST API, Axios
- **AI Model**: Python (Flask, scikit-learn, pandas, numpy, joblib)
- **SDN Simulation**: Custom scripts for dynamic routing and mitigation
- **Integration**: AbuseIPDB (threat intelligence)
- **Packet Capture**: Wireshark/tshark (optional, simulated by default)
- **DevOps**: Git, npm, pip

---

## Prerequisites

- **Node.js** v16+ ([Download](https://nodejs.org/))
- **Python** v3.8+ ([Download](https://www.python.org/))
- **Git** ([Download](https://git-scm.com/))
- **Wireshark** (optional, for real packet capture) ([Download](https://www.wireshark.org/))

**Verify your installs:**
```bash
node --version
python --version
git --version
# Optional: tshark --version (after installing Wireshark)
```

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Akshita3104/Ly-Project.git
cd Ly-Project
```

### 2. Install Dependencies

```bash
# Backend
cd backend
npm install

# Frontend (in new terminal)
cd ../frontend
npm install

# Python ML Model (in another terminal)
cd ../model
pip install -r requirements.txt
```

### 3. Run the System

**Open 3 terminals:**

- **Terminal 1 (ML Model - Port 5001)**
  ```bash
  cd model/app
  python app.py
  ```

- **Terminal 2 (Backend API - Port 3000)**
  ```bash
  cd backend
  npm start
  ```

- **Terminal 3 (Frontend Dashboard - Port 5173)**
  ```bash
  cd frontend
  npm run dev
  ```

### 4. Open the Dashboard

Go to [http://localhost:5173](http://localhost:5173) in your browser.

---

## Usage

### Real Packet Capture (Recommended)
- Install Wireshark with npcap driver and run as administrator.
- The app will attempt live capture; fallback to simulation if disabled/missing.

### Simulation Mode (Fallback)
- The dashboard allows traffic simulation and manual entry for DDoS analysis without system-level capture.

### Features Overview

- **Live Capture**: Ethernet/Wi-Fi interfaces only;
- **Simulation**: Traffic and attack scenarios for research;
- **Detection**: View charts, alerts, and attack details in real-time;
- **Self-Healing**: Automatic or manual mitigation actions;

---

## System Architecture

1. **Network Traffic** → Real (Wireshark) or simulated streams
2. **Feature Extraction** → ML-ready traffic features
3. **ML Model** → Random Forest, Min-Max scaling, ensemble methods
4. **API Backend** → Node.js REST mediating traffic/data
5. **Dashboard** → React UI for analytics, control, and status

**Supported Slices:**
- eMBB (Enhanced Mobile Broadband)
- URLLC (Ultra-Reliable Low-Latency Communication)
- mMTC (Massive Machine Type Communication)

---

## Contributing

This project is actively developed as part of cybersecurity research. Contributions, issues, and suggestions are welcome! Please review the research documentation or connect with maintainers for more information.

---

## License

This project is for academic and research use. Refer to the LICENSE file for terms.

---
