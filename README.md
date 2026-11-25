# 🛡️ AI-Driven Network Intrusion Prevention System (AI-NIPS)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost-orange.svg)](https://xgboost.readthedocs.io/)
[![Scapy](https://img.shields.io/badge/Networking-Scapy-red.svg)](https://scapy.net/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An autonomous, enterprise-grade **Network Intrusion Prevention System (NIPS)** that combines low-level packet sniffing (`Scapy`), statistical flow feature extraction, machine learning threat detection (`XGBoost`), autonomous kernel-level banishment (`Linux IPTables`), and a real-time Security Operations Center (`Streamlit`) dashboard with automated forensic PDF reporting.

---

## 🚀 Key Features

- **Live High-Throughput Packet Inspection:** Captures raw network traffic across physical or virtual interfaces (`enp0s3` / `enp0s8`) at a sustained rate of 1,000+ packets/sec.
- **Dual-Layer Threat Detection:**
  - **Heuristic Engine:** Monitors port scan velocities (`unique destination ports > 20`), mitigating reconnaissance attacks instantly.
  - **Machine Learning Engine:** Multi-class **XGBoost** model trained on statistical network flow features from the **CSE-CIC-IDS2018** benchmark dataset.
- **Classified Attack Vectors:** Accurately classifies and mitigates **DoS-Hulk**, **Web Brute-Force**, **Infiltration**, and **Port Scans** with **98% validation accuracy**.
- **Autonomous Kernel-Level Mitigation:** Dynamically injects drop rules into active Linux Netfilter chains (`sudo iptables -A INPUT -s <IP> -j DROP`), severing hostile connectivity in sub-second response times.
- **Real-Time SOC Dashboard:** Built with Streamlit to visualize traffic distributions, telemetry metrics, and live threat ingress streams.
- **Forensic PDF Incident Reports:** Programmatically generates compliance-ready forensic incident reports via `FPDF` with automated generation on graceful shutdown (`SIGINT` / Ctrl+C).

---

## 📊 Extracted Statistical Flow Features

The inference engine aggregates individual packets into bidirectional flow sessions and computes 7 critical discriminative features:

| Feature | Description |
| :--- | :--- |
| `Dst Port` | Target destination service port (e.g. 80, 443, 22) |
| `Protocol` | Transport layer protocol identifier (TCP=6, UDP=17) |
| `Flow Duration` | Cumulative lifespan of the connection in microseconds |
| `Tot Fwd Pkts` | Total packet count in forward transmission direction |
| `Tot Bwd Pkts` | Total response packet count in reverse direction |
| `TotLen Fwd Pkts` | Cumulative byte payload volume in forward direction |
| `Fwd Pkt Len Max` | Peak packet payload size observed in the flow |

---

## 📁 Repository Structure

```
AI-Driven-NIPS/
├── README.md                   # Comprehensive system documentation
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git untracked patterns
├── src/
│   ├── nips_engine.py          # Core packet capture, ML inference & IPTables defense
│   └── dashboard.py            # Streamlit real-time SOC dashboard
├── models/
│   ├── phase1_model.pkl        # Serialized XGBoost multi-class classifier
│   ├── attack_encoder.pkl      # Attack label encoder
│   └── feature_columns.pkl     # Schema feature alignment
├── training/
│   └── train_cic_ids.py        # Model training pipeline on CSE-CIC-IDS2018
├── sample_reports/
│   └── NIPS_Report_Sample.pdf  # Sample auto-generated forensic PDF report
└── data/
    └── live_logs.csv           # IPC buffer for live SOC telemetry
```

---

## ⚡ Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/rajaditya1186-ai/AI-Driven-NIPS.git
cd AI-Driven-NIPS
```

### 2. Create and Activate a Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the System

**Terminal 1 — Start the NIPS Engine (Requires root/sudo privileges for raw socket sniffing & IPTables):**
```bash
sudo python src/nips_engine.py
```

**Terminal 2 — Launch the SOC Dashboard:**
```bash
streamlit run src/dashboard.py
```

---

## 📈 Model Training Details

- **Dataset:** [CSE-CIC-IDS2018 on AWS / UNB](https://www.unb.ca/cic/datasets/ids-2018.html)
- **Classifier:** `xgboost.XGBClassifier`
- **Hyperparameters:** `n_estimators=100`, `max_depth=6`, `tree_method='hist'`, `objective='multi:softprob'`
- **Validation:** 80/20 Stratified Train/Test split across 100k-sample chunks.

---

## 📜 License
This project is licensed under the MIT License.
