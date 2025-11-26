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
app.config['SECRET_KEY'] = 'siem-secret-key-real-data'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unacp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def setup_database():
    with app.app_context():
        db.create_all()
        if not Policy.query.first():
            defaults = [
                Policy(name="Access Control", description="Monitor successful user logins (Event 4624).", severity="Low"),
                Policy(name="Password Policy", description="Detect failed login attempts (Event 4625).", severity="High"),
                Policy(name="Privilege Escalation", description="Monitor changes to user groups (Event 4732).", severity="High"),
                Policy(name="Firewall Integrity", description="Detect if Firewall service is stopped (Event 5025).", severity="High"),
            ]
            db.session.add_all(defaults)
            db.session.commit()

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

@app.route('/policies', methods=['GET', 'POST'])
def policies():
    if request.method == 'POST':
        name = request.form.get('name')
        desc = request.form.get('description')
        severity = request.form.get('severity')
        db.session.add(Policy(name=name, description=desc, severity=severity))
        db.session.commit()
        flash('New Security Policy Added', 'success')
        return redirect(url_for('policies'))
    all_policies = Policy.query.all()
    return render_template('policies.html', policies=all_policies)

@app.route('/audit')
def audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit.html', logs=logs)

@app.route('/reports')
def reports():
    high_fails = AuditLog.query.filter(AuditLog.compliance_status=='Non-Compliant').count()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template('reports.html', logs=logs, high_fails=high_fails)

# --- REAL Windows Log Scanner (With Duplicate Check) ---
@app.route('/scan_logs')
def scan_logs():
    if not WINDOWS_SUPPORT:
        flash("Error: This feature requires Windows and the 'pywin32' library.", "danger")
        return redirect(url_for('dashboard'))

    try:
        server = 'localhost'
        log_type = 'Security' 
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        # TIME FILTER: Last 3 Days
        cutoff_date = datetime.now() - timedelta(days=7)
        
        imported_count = 0
        skipped_count = 0
        MAX_EVENTS_TO_IMPORT = 100 
        
        while imported_count < MAX_EVENTS_TO_IMPORT:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if not events:
                break 
                
            for event in events:
                if event.TimeGenerated < cutoff_date:
                    win32evtlog.CloseEventLog(hand)
                    flash(f"Scan Finished: Added {imported_count} new events. Skipped {skipped_count} duplicates.", "info")
                    return redirect(url_for('dashboard'))

                event_id = event.EventID & 0xFFFF
                
                # Expanded List of Interesting Events
                # 4672: Special Privileges (Admin) - We flag this as Non-Compliant for DEMO visibility
                target_events = [4624, 4625, 1102, 7045, 4720, 4732, 4723, 5025, 4672]

                if event_id in target_events:
                    
                    # --- MAPPING LOGIC ---
                    policy_name = "General Logging"
                    status = "Compliant"
                    details = f"Event ID: {event_id}"
                    
                    if event_id == 4624:
                        policy_name = "Access Control"
                        status = "Compliant"
                        details = "Successful User Logon"
                    elif event_id == 4625:
                        policy_name = "Password Policy"
                        status = "Non-Compliant"
                        details = "FAILED LOGIN ATTEMPT"
                    elif event_id == 4732:
                        policy_name = "Privilege Escalation"
                        status = "Non-Compliant"
                        details = "User Added to Security Group"
                    elif event_id == 5025:
                        policy_name = "Firewall Integrity"
                        status = "Non-Compliant"
                        details = "Windows Firewall Service Stopped"
                    elif event_id == 4672:
                        policy_name = "Privileged Access"
                        status = "Non-Compliant" # Flagging Admin usage as a violation for visibility
                        details = "Special Privileges Assigned (Admin Login)"
                    elif event_id == 4723:
                        policy_name = "Password Policy"
                        status = "Non-Compliant"
                        details = "Attempt to Change Password"

                    # --- DUPLICATE CHECK ---
                    # specific check: same time, same details
                    exists = AuditLog.query.filter_by(timestamp=event.TimeGenerated, details=details).first()
                    
                    if not exists:
                        new_log = AuditLog(
                            timestamp=event.TimeGenerated,
                            device_ip=socket.gethostbyname(socket.gethostname()),
                            user="System", 
                            policy_name=policy_name,
                            compliance_status=status,
                            details=details
                        )
                        db.session.add(new_log)
                        imported_count += 1
                    else:
                        skipped_count += 1
                    
                    if imported_count >= MAX_EVENTS_TO_IMPORT:
                        break

        db.session.commit()
        win32evtlog.CloseEventLog(hand)
        
        msg_type = "success" if imported_count > 0 else "warning"
        flash(f"Scan Complete: Added {imported_count} new events. Skipped {skipped_count} duplicates.", msg_type)

    except Exception as e:
        flash(f"Error reading logs: {str(e)}", "danger")

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    setup_database()
    app.run(debug=True)