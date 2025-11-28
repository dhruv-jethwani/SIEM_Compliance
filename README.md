# 🛡️ Unified Network Access Compliance Platform (UNACP): A Policy & Audit Reporting Tool

## 📄 Description

The Unified Network Access Compliance Platform (UNACP) is a demonstration of a lightweight **Security Information and Event Management (SIEM)** solution designed for **policy enforcement and compliance auditing** on a Windows host.

Built with Python and Flask, this tool interfaces directly with the **Windows Event Log** (Security, System, and Application logs) to ingest telemetry data in real-time. It then maps raw Event IDs against a granular set of over **20 rigorous security policies**, generating an immediate **"Compliant" or "Non-Compliant"** status.

This project showcases core cybersecurity principles, including threat correlation, defense-in-depth monitoring, and executive reporting.

## ✨ Key Features

* **Real-Time Log Ingestion:** Uses the `pywin32` library to read Windows Event Logs (Security, System, Application) from the last 3 days.

* **Policy Engine:** Contains over 20 specific security policies, categorized for the **MITRE ATT&CK framework**.

  * **Brute Force Detection (4625):** Monitors failed login attempts.

  * **Defense Evasion (1102, 4719, 5007):** Flags critical events like audit log clearing and Antivirus configuration tampering.

  * **Persistence Mechanisms (4697, 7045):** Detects unauthorized service or scheduled task installations.

  * **Lateral Movement (5140, 5145):** Monitors network share access and reconnaissance.

* **Idempotency & Data Integrity:** Ensures that subsequent scans only import unique, new logs, preventing database duplication.

* **Compliance Dashboard:** Visualizes system health via a compliance score and a ratio of Compliant vs. Non-Compliant events.

* **Executive Audit Reporting:** Generates a focused, printable report detailing:

  * Overall Compliance Score.

  * Top 5 Violated Policies.

  * Recent **Critical** Incidents (Filtered strictly by severity).

  * Automated Remediation Strategy based on top failing controls.

## 🚀 Installation

This application is designed to run on a **Windows operating system** and requires **Administrator privileges** for the log scanner to access the Security event log.

### Prerequisites

* Python 3.x

* Windows OS

### Steps

1. **Clone the Repository:**

   ```bash
   git clone [https://github.com/your-username/unacp_project.git](https://github.com/your-username/unacp_project.git)
   cd unacp_project
   ```

2. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run as Administrator (CRITICAL):**
   Open your command prompt or terminal **as Administrator**.

4. **Start the Flask Application:**
   The first run will initialize the `unacp.db` file and populate the 20+ default policies.

   ```bash
   python app.py
   ```

5. **Access the Application:**
   Open your web browser and navigate to:

   ```
   http://127.0.0.1:5000/
   ```

## 📋 Usage Instructions

1. **Dashboard (`/`):** View the compliance ratio and the live feed of policy failures.

2. **Policy Manager (`/policies`):** Review the 21+ security controls enforced by the platform.

3. **Scan Logs:** Click the **"Scan Windows Logs"** button (top right). This initiates the log processing and database update.

4. **Generate Report (`/reports`):** Navigate here for the executive summary and recommended actions.

## 📁 File Structure

The project follows a standard Flask structure:

```text
/unacp_project
  ├── app.py              # Main Flask application and security logic
  ├── models.py           # Database models (Policy, AuditLog)
  ├── requirements.txt    # Project dependencies
  ├── static/
  │   └── css/
  │       └── style.css   # Custom dark theme CSS
  └── templates/
      ├── base.html       # Master layout
      ├── dashboard.html  # Compliance charts and status
      ├── policies.html   # Policy list (read-only)
      ├── audit.html      # Raw audit log feed
      └── reports.html    # Executive summary report
```

## 💡 Next Steps / Future Enhancements

* Implement a **multi-user authentication** system.

* Add **log enrichment** (e.g., pulling geolocation data for IP addresses).

* Integrate a **machine learning model** to detect anomalies outside of pre-defined Event IDs.
