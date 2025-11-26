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
app.config['SECRET_KEY'] = 'siem-secret-key-final-v2'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unacp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def setup_database():
    with app.app_context():
        db.create_all()
        # Reset policies if needed or just add if empty
        if not Policy.query.first():
            defaults = [
                Policy(name="Access Control", description="Monitor successful user logins (Event 4624).", severity="Low"),
                Policy(name="Password Policy", description="Detect failed login attempts (Event 4625).", severity="High"),
                Policy(name="Privilege Escalation", description="Monitor Admin logins & group changes (Event 4672, 4732).", severity="High"),
                Policy(name="Firewall Integrity", description="Monitor Firewall Service status (Event 7036, 5025).", severity="Critical"),
                Policy(name="System Integrity", description="Detect unexpected shutdowns & log clearing (Event 6008, 1102).", severity="Medium"),
                Policy(name="Process Watch", description="Monitor new process creation (Event 4688).", severity="Low"),
            ]
            db.session.add_all(defaults)
            db.session.commit()

# --- Routes ---

@app.route('/')
def dashboard():
    total_policies = Policy.query.count()
    total_logs = AuditLog.query.count()
    non_compliant = AuditLog.query.filter_by(compliance_status='Non-Compliant').count()
    compliant = AuditLog.query.filter_by(compliance_status='Compliant').count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                           total_policies=total_policies, 
                           total_logs=total_logs,
                           compliant=compliant,
                           non_compliant=non_compliant,
                           recent_logs=recent_logs)

@app.route('/policies')
def policies():
    # REMOVED: POST logic (User cannot add policies anymore)
    all_policies = Policy.query.all()
    return render_template('policies.html', policies=all_policies)

@app.route('/audit')
def audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10000).all()
    return render_template('audit.html', logs=logs)

@app.route('/reports')
def reports():
    high_fails = AuditLog.query.filter(AuditLog.compliance_status=='Non-Compliant').count()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20000).all()
    return render_template('reports.html', logs=logs, high_fails=high_fails)

# --- Helper to process logs generically ---
def process_windows_log(log_type, cutoff_date, max_per_source):
    """
    Reads a specific Windows Event Log (Security or System) and returns a list of mapped AuditLog objects.
    """
    new_logs_found = []
    
    if not WINDOWS_SUPPORT:
        return []

    try:
        server = 'localhost'
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        imported = 0
        
        while imported < max_per_source:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
                
            for event in events:
                if event.TimeGenerated < cutoff_date:
                    win32evtlog.CloseEventLog(hand)
                    return new_logs_found

                event_id = event.EventID & 0xFFFF
                
                # --- EVENT MAPPING LOGIC ---
                policy_name = None
                status = "Compliant"
                details = f"ID: {event_id} Source: {event.SourceName}"
                
                # Security Log Events
                if log_type == 'Security':
                    if event_id == 4624:
                        policy_name = "Access Control"
                        details = "Successful User Logon"
                    elif event_id == 4625:
                        policy_name = "Password Policy"
                        status = "Non-Compliant"
                        details = "FAILED LOGIN ATTEMPT"
                    elif event_id == 4672:
                        policy_name = "Privilege Escalation"
                        status = "Non-Compliant" # Flag Admin login for demo
                        details = "Admin/Special Privileges Assigned"
                    elif event_id == 4732:
                        policy_name = "Privilege Escalation"
                        status = "Non-Compliant"
                        details = "User Added to Local Admin Group"
                    elif event_id == 1102:
                        policy_name = "System Integrity"
                        status = "Non-Compliant"
                        details = "AUDIT LOG CLEARED (Suspicious Activity)"
                    elif event_id == 5025:
                        policy_name = "Firewall Integrity"
                        status = "Non-Compliant"
                        details = "Windows Firewall Service Stopped"
                    elif event_id == 4688:
                        policy_name = "Process Watch"
                        details = f"New Process Created" # Usually contains process name in data
                    elif event_id == 5157:
                        policy_name = "Firewall Integrity"
                        status = "Compliant" # Blocking is good
                        details = "Windows Filtering Platform Blocked a Connection"

                # System Log Events
                elif log_type == 'System':
                    if event_id == 7036:
                        # Service Control Manager - Check for Firewall or other critical services
                        # Note: StringInserts usually contain service name
                        service_name = event.StringInserts[0] if event.StringInserts else "Unknown"
                        state = event.StringInserts[1] if event.StringInserts and len(event.StringInserts) > 1 else "Unknown"
                        
                        if "Windows Defender Firewall" in service_name or "MpsSvc" in str(event.StringInserts):
                            policy_name = "Firewall Integrity"
                            if "stopped" in state.lower():
                                status = "Non-Compliant"
                                details = "Firewall Service STOPPED"
                            else:
                                status = "Compliant"
                                details = "Firewall Service State Change"
                        else:
                            # Generic service noise, ignore or map to System
                            pass 

                    elif event_id == 6008:
                        policy_name = "System Integrity"
                        status = "Non-Compliant"
                        details = "Unexpected System Shutdown Detected"
                    elif event_id == 7045:
                        policy_name = "System Integrity"
                        status = "Non-Compliant" # New service install
                        details = f"New Service Installed: {event.StringInserts[0] if event.StringInserts else 'Unknown'}"

                # Only add if we matched a policy
                if policy_name:
                    # Duplicate check
                    exists = AuditLog.query.filter_by(timestamp=event.TimeGenerated, details=details).first()
                    
                    if not exists:
                        log_entry = AuditLog(
                            timestamp=event.TimeGenerated,
                            device_ip=socket.gethostbyname(socket.gethostname()),
                            user="System",
                            policy_name=policy_name,
                            compliance_status=status,
                            details=details
                        )
                        new_logs_found.append(log_entry)
                        imported += 1
        
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f"Error reading {log_type}: {e}")
        
    return new_logs_found

@app.route('/scan_logs')
def scan_logs():
    if not WINDOWS_SUPPORT:
        flash("Error: Windows Scan requires 'pywin32' library.", "danger")
        return redirect(url_for('dashboard'))

    cutoff_date = datetime.now() - timedelta(days=3)
    
    # Scan SECURITY Log
    security_logs = process_windows_log('Security', cutoff_date, 10000)
    
    # Scan SYSTEM Log (New!)
    system_logs = process_windows_log('System', cutoff_date, 20000)
    
    all_new_logs = security_logs + system_logs
    
    if all_new_logs:
        # Sort by time so they insert in order
        all_new_logs.sort(key=lambda x: x.timestamp)
        
        for log in all_new_logs:
            db.session.add(log)
            
        db.session.commit()
        flash(f"Scan Complete: Added {len(all_new_logs)} new events from Security & System logs.", "success")
    else:
        flash("Scan Complete: No new unique events found in the last 3 days.", "warning")

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    setup_database()
    app.run(debug=True)