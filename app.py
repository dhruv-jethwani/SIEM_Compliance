import platform
import socket
from flask import Flask, render_template, request, redirect, url_for, flash
from models import db, Policy, AuditLog
from datetime import datetime, timedelta

# --- Windows Import Handling ---
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    WINDOWS_SUPPORT = True
except ImportError:
    WINDOWS_SUPPORT = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem-secret-key-final-v6'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unacp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def setup_database():
    with app.app_context():
        db.create_all()
        # Reset/Initialize with the MAXIMUM Policy Set
        if not Policy.query.first():
            defaults = [
                # --- ACCESS & IDENTITY ---
                Policy(name="Standard Logon Monitoring", description="Monitor successful user logons (4624).", severity="Low"),
                Policy(name="Explicit Credential Usage", description="Detect RunAs/Explicit Credential usage (4648).", severity="Medium"),
                Policy(name="Brute Force Detection", description="Detect multiple failed login attempts (4625).", severity="Critical"),
                Policy(name="NTLM Authentication", description="Monitor NTLM authentication traffic (4776).", severity="High"),
                Policy(name="Kerberos Operations", description="Monitor Kerberos TGT/TGS requests (4768, 4769).", severity="High"),
                
                # --- PRIVILEGE & ACCOUNTS ---
                Policy(name="Administrative Privileges", description="Detect Special Privilege assignment (4672).", severity="High"),
                Policy(name="User Account Creation", description="Monitor creation of new user accounts (4720).", severity="Medium"),
                Policy(name="Security Group Modification", description="Monitor changes to Admin/Security groups (4732).", severity="High"),
                
                # --- PERSISTENCE & SYSTEM ---
                Policy(name="Service Installation", description="Detect unauthorized service installs (4697, 7045).", severity="High"),
                Policy(name="Scheduled Task Activity", description="Monitor creation/modification of tasks (4698).", severity="High"),
                Policy(name="Registry Value Integrity", description="Monitor changes to Registry Run keys (4657).", severity="High"),
                Policy(name="Application Error Analysis", description="Monitor Application Crashes/Exploits (1000).", severity="Medium"),
                
                # --- DEFENSE EVASION ---
                Policy(name="Audit Log Clearing", description="CRITICAL: Detect clearing of Security Logs (1102).", severity="Critical"),
                Policy(name="Audit Policy Modification", description="Detect changes to System Audit Policy (4719).", severity="Critical"),
                Policy(name="Firewall Rule Modification", description="Monitor new rules added to Windows Firewall (4946).", severity="High"),
                
                # --- MALWARE & LATERAL MOVEMENT ---
                Policy(name="Malware Detection", description="Windows Defender malware detection events (1116).", severity="Critical"),
                Policy(name="Antivirus Config Tampering", description="Detect changes to AV settings/exclusions (5007).", severity="Critical"),
                Policy(name="Security Service Tampering", description="Monitor stopping of Defender/Firewall services (7036).", severity="Critical"),
                Policy(name="Network Share Access", description="Monitor access to network shares (5140).", severity="High"),
                Policy(name="Share Reconnaissance", description="Detailed check of file share objects (5145).", severity="High"),
                Policy(name="Suspicious Process Creation", description="Monitor execution of new processes (4688).", severity="Medium"),
            ]
            db.session.add_all(defaults)
            db.session.commit()

# --- ROUTES ---

@app.route('/')
def dashboard():
    total_policies = Policy.query.count()
    total_logs = AuditLog.query.count()
    non_compliant = AuditLog.query.filter_by(compliance_status='Non-Compliant').count()
    compliant = AuditLog.query.filter_by(compliance_status='Compliant').count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # --- LOGIC: Calculate Last Failure for each Policy ---
    all_policies_db = Policy.query.all()
    policy_failures = []
    
    for p in all_policies_db:
        last_fail = AuditLog.query.filter_by(policy_name=p.name, compliance_status='Non-Compliant')\
                                  .order_by(AuditLog.timestamp.desc()).first()
        
        if last_fail:
            policy_failures.append({
                'name': p.name,
                'severity': p.severity,
                'last_failure_time': last_fail.timestamp,
                'details': last_fail.details
            })

    policy_failures.sort(key=lambda x: x['last_failure_time'], reverse=True)

    return render_template('dashboard.html', 
                           total_policies=total_policies, 
                           total_logs=total_logs,
                           compliant=compliant,
                           non_compliant=non_compliant,
                           recent_logs=recent_logs,
                           policy_failures=policy_failures)

@app.route('/policies')
def policies():
    all_policies = Policy.query.all()
    return render_template('policies.html', policies=all_policies)

@app.route('/audit')
def audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10000).all()
    return render_template('audit.html', logs=logs)

@app.route('/reports')
def reports():
    total_logs = AuditLog.query.count()
    
    if total_logs == 0:
         return render_template('reports.html', logs=[], score=100, top_violations=[], critical_logs=[], recommendations=[])

    # 1. Calculate Compliance Score
    compliant_count = AuditLog.query.filter_by(compliance_status='Compliant').count()
    score = round((compliant_count / total_logs) * 100, 1)

    # 2. Identify Top Violations
    violations = AuditLog.query.filter_by(compliance_status='Non-Compliant').all()
    violation_counts = {}
    for v in violations:
        violation_counts[v.policy_name] = violation_counts.get(v.policy_name, 0) + 1
    
    # Sort and get top 5
    top_violations = sorted(violation_counts.items(), key=lambda item: item[1], reverse=True)[:5]

    # 3. Identify ONLY Critical Severity Incidents (Updated Logic)
    policies = Policy.query.all()
    severity_map = {p.name: p.severity for p in policies}
    
    critical_logs = []
    recent_violations = AuditLog.query.filter_by(compliance_status='Non-Compliant').order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    for log in recent_violations:
        sev = severity_map.get(log.policy_name, 'Medium')
        # UPDATED: Only show CRITICAL logs here, ignoring High/Medium
        if sev == 'Critical':
            critical_logs.append({
                'time': log.timestamp,
                'policy': log.policy_name,
                'details': log.details,
                'severity': sev
            })
            if len(critical_logs) >= 5: break 

    # 4. Generate Remediation Recommendations (New Feature)
    recommendations = []
    for policy_name, count in top_violations:
        if "Brute Force" in policy_name:
            recommendations.append("Enable Account Lockout Policies (Threshold: 5 attempts) to mitigate brute force attacks.")
        elif "Malware" in policy_name or "Antivirus" in policy_name:
            recommendations.append("Isolate affected hosts immediately and initiate a full offline antivirus scan.")
        elif "Audit Log" in policy_name:
            recommendations.append("Investigate potential insider threat or compromise. Clearing audit logs is a major red flag.")
        elif "Administrative" in policy_name:
            recommendations.append("Review recent Admin access. Ensure Least Privilege principles are enforced.")
        elif "Service" in policy_name or "Persistence" in policy_name:
            recommendations.append("Verify the legitimacy of recently installed services. This is a common persistence technique.")

    # Remove duplicates
    recommendations = list(set(recommendations))[:4] 
    if not recommendations and score < 100:
        recommendations.append("Review standard system hygiene and patch levels.")

    # 5. Appendix Logs (Filtered to Violations Only)
    # UPDATED: Max 100 entries, and ONLY non-compliant events. No more log dump.
    appendix_logs = AuditLog.query.filter_by(compliance_status='Non-Compliant').order_by(AuditLog.timestamp.desc()).limit(20).all()

    return render_template('reports.html', 
                           logs=appendix_logs, 
                           score=score,
                           top_violations=top_violations,
                           critical_logs=critical_logs,
                           recommendations=recommendations)

# --- ADVANCED LOG SCANNER ---
def process_windows_log(log_type, cutoff_date, max_per_source):
    new_logs_found = []
    if not WINDOWS_SUPPORT: return []

    try:
        hand = win32evtlog.OpenEventLog('localhost', log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        imported = 0
        
        while imported < max_per_source:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events: break
                
            for event in events:
                if event.TimeGenerated < cutoff_date:
                    win32evtlog.CloseEventLog(hand)
                    return new_logs_found

                event_id = event.EventID & 0xFFFF
                policy_name = None
                status = "Compliant"
                details = f"ID: {event_id}"
                
                # --- GRANULAR THREAT MAPPING ---
                if log_type == 'Security':
                    if event_id == 4625:
                        policy_name, status, details = "Brute Force Detection", "Non-Compliant", "FAILED LOGIN (Brute Force Risk)"
                    elif event_id == 4648:
                        policy_name, status, details = "Explicit Credential Usage", "Compliant", "Logon using Explicit Credentials"
                    elif event_id == 4776:
                        policy_name, status, details = "NTLM Authentication", "Non-Compliant", "NTLM Validation Failed"
                    elif event_id in [4768, 4769]:
                        policy_name, details = "Kerberos Operations", "Kerberos Ticket Requested"
                    elif event_id == 4672:
                        policy_name, status, details = "Administrative Privileges", "Non-Compliant", "Special Privileges (Admin)"
                    elif event_id == 4720:
                        policy_name, status, details = "User Account Creation", "Non-Compliant", "NEW USER ACCOUNT CREATED"
                    elif event_id in [4732, 4756]:
                        policy_name, status, details = "Security Group Modification", "Non-Compliant", "Member Added to Security Group"
                    elif event_id == 4697:
                        policy_name, status, details = "Service Installation", "Non-Compliant", "New Service Installed"
                    elif event_id in [4698, 4700, 4702]:
                        policy_name, status, details = "Scheduled Task Activity", "Non-Compliant", "Scheduled Task Created/Modified"
                    elif event_id == 1102:
                        policy_name, status, details = "Audit Log Clearing", "Non-Compliant", "AUDIT LOG CLEARED"
                    elif event_id == 4719:
                        policy_name, status, details = "Audit Policy Modification", "Non-Compliant", "Audit Policy Changed"
                    elif event_id == 4946:
                        policy_name, status, details = "Firewall Rule Modification", "Non-Compliant", "Firewall Exception Added"
                    elif event_id == 4663:
                        policy_name, details = "Registry Value Integrity", "Attempt to Access Object/File"
                    elif event_id == 4688:
                        policy_name, details = "Suspicious Process Creation", "New Process Created"
                    elif event_id == 4657:
                        policy_name, status, details = "Registry Value Integrity", "Non-Compliant", "Registry Value Modified"
                    elif event_id == 5140:
                        policy_name, status, details = "Network Share Access", "Compliant", "Network Share Accessed"
                    elif event_id == 5145:
                        policy_name, status, details = "Share Reconnaissance", "Compliant", "Network Share Checked for Access"
                    elif event_id == 4624:
                        policy_name, details = "Standard Logon Monitoring", "Successful User Logon"

                # Check System Log
                elif log_type == 'System':
                    if event_id == 7045:
                        policy_name, status, details = "Service Installation", "Non-Compliant", "New Service Installed"
                    elif event_id == 7036:
                        svc_name = str(event.StringInserts)
                        if "stopped" in svc_name.lower():
                            if any(x in svc_name for x in ["Defender", "MsMpEng", "SepMasterService", "MpsSvc"]):
                                policy_name, status, details = "Security Service Tampering", "Non-Compliant", "Security Service STOPPED"
                            else:
                                pass # Generic stop
                    elif event_id in [1116, 1117]:
                        policy_name, status, details = "Malware Detection", "Non-Compliant", "Malware Detected/Action Taken"
                    elif event_id == 5007:
                        policy_name, status, details = "Antivirus Config Tampering", "Non-Compliant", "Defender Config Changed"

                # Check Application Log
                elif log_type == 'Application':
                    if event_id == 1000:
                        policy_name, status, details = "Application Error Analysis", "Non-Compliant", "Application Error/Crash Detected"
                    elif event_id in [1116, 1117]:
                        policy_name, status, details = "Malware Detection", "Non-Compliant", "Malware Detected"

                # Add to list if matched
                if policy_name:
                    exists = AuditLog.query.filter_by(timestamp=event.TimeGenerated, details=details).first()
                    if not exists:
                        new_logs_found.append(AuditLog(
                            timestamp=event.TimeGenerated,
                            device_ip=socket.gethostbyname(socket.gethostname()),
                            user="System",
                            policy_name=policy_name,
                            compliance_status=status,
                            details=details
                        ))
                        imported += 1
                        
        win32evtlog.CloseEventLog(hand)
    except Exception as e: print(f"Error reading {log_type}: {e}")
    return new_logs_found

@app.route('/scan_logs')
def scan_logs():
    if not WINDOWS_SUPPORT:
        flash("Error: Windows Scan requires 'pywin32' library.", "danger")
        return redirect(url_for('dashboard'))

    cutoff_date = datetime.now() - timedelta(days=30)
    
    security_logs = process_windows_log('Security', cutoff_date, 1000)
    system_logs = process_windows_log('System', cutoff_date, 1000)
    app_logs = process_windows_log('Application', cutoff_date, 500)
    
    all_new_logs = security_logs + system_logs + app_logs
    
    if all_new_logs:
        all_new_logs.sort(key=lambda x: x.timestamp)
        for log in all_new_logs: db.session.add(log)
        db.session.commit()
        flash(f"Scan Complete: Added {len(all_new_logs)} new events from all sources.", "success")
    else:
        flash("Scan Complete: No new unique events found.", "warning")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    setup_database()
    app.run(debug=True)