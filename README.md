# MITRE ATT&CK Mapping Automation

## 📌 Overview
This repository automates the process of mapping CVE vulnerabilities to the MITRE ATT&CK framework. It utilizes a Python script to fetch and update CVE mappings and integrates with GitHub Actions for scheduled updates.

## 🚀 Features
- Automatically fetches the latest CVE-MITRE mappings.
- Runs as a scheduled GitHub Action at 12:00 UTC daily.
- Saves mapping data into `cve_mitre_mapping.json`.
- Commits and pushes updates to the repository.

## 📂 Repository Structure
```
.
├── .github/workflows/        # GitHub Actions workflow files
│   ├── mitre-mapping.yml    # Automation script for scheduled updates
├── Mitre_Mapping.py         # Python script to fetch and process MITRE mappings
├── cve_mitre_mapping.json   # JSON file storing the updated mappings
├── requirements.txt         # Dependencies for running the script
├── README.md                # Project documentation
```

## 🛠️ Setup & Usage
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/alhelmyjhr98/mitre-attack-mapping-automation.git
cd mitre-attack-mapping-automation
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Mapping Script
```bash
python Mitre_Mapping.py
```
This will generate an updated `cve_mitre_mapping.json` file.

### 4️⃣ Automate Updates (Optional)
The GitHub Actions workflow is already set up to run daily at 12:00 UTC. Ensure your repository has a valid GitHub Personal Access Token stored as `MY_PAT_TOKEN` in GitHub Secrets.

## 🔄 GitHub Actions Workflow
The automation is handled by `.github/workflows/mitre-mapping.yml`. It performs the following steps:
1. Checks out the repository.
2. Installs dependencies.
3. Runs `Mitre_Mapping.py` to fetch CVE mappings.
4. Commits and pushes changes if updates are found.

## 📝 Contributing
Feel free to open an issue or submit a pull request if you find any bugs or want to improve the project!

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).
