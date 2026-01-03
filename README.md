# AI-Based SOC Intrusion Detection Dashboard

An interactive **SOC-style intrusion detection dashboard** built using **Streamlit** and inspired by the **CICIDS 2017 dataset**.  
This project simulates a **Security Operations Center (SOC)** environment for visualizing, analyzing, and monitoring network security events.

---

## 🚀 Features

- 📊 Attack & traffic distribution visualization  
- 🚦 Severity-based alert classification  
- 🚨 SOC alert table with dynamic filters  
- 📈 Simulated attack timeline for trend analysis  
- 🧠 Detection overview (Benign vs Attack traffic)  
- 🛡️ **MITRE ATT&CK technique mapping visualization**  
- ⏱️ **SOC-style date & time window filtering**  
- 🧩 Modular, scalable, and SOC-oriented UI design  

---

## 🧠 Severity Levels

Severity is automatically mapped from attack types:

- 🔴 **Critical**  
- 🟠 **High**  
- 🟡 **Medium**  
- 🟢 **Low**  

---

## 🛠 Tech Stack

- **Python 3.10+**
- **Streamlit**
- **Pandas**
- **Plotly / Plotly Express**
- **Scikit-learn** (used offline for model training, not included in repo)

---

## 📊 Dataset (Not Included)

- **CICIDS 2017**
- Dataset files are **not included** due to size limitations
- Expected columns:
  - `timestamp`
  - `Label`

👉 Download the dataset separately (e.g., from Kaggle) and place it locally when running the dashboard.

---

## 📁 Project Structure

AI-Based-SOC-Intrusion-Detection-Dashboard/
│
├── dashboard/
│ ├── app.py # Main Streamlit application
│ ├── data_loader.py # Data loading & preprocessing
│ ├── metrics.py # SOC metrics & severity mapping
│ ├── charts.py # Plotly visualizations
│ ├── mitre_mapping.py # MITRE ATT&CK mapping logic
│ └── requirements.txt # Project dependencies
│
├── .gitignore
└── README.md

---

## ▶️ Run Locally

### 1️⃣ Clone the repository
```bash
git clone https://github.com/suhaibahmed1/AI-Based-SOC-Intrusion-Detection-Dashboard.git
cd AI-Based-SOC-Intrusion-Detection-Dashboard

2️⃣ Create and activate a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

3️⃣ Install dependencies
pip install -r dashboard/requirements.txt

4️⃣ Run the Streamlit dashboard
streamlit run dashboard/app.py


⚠️ Note:
Dataset files must be downloaded separately and are not pushed to GitHub.


