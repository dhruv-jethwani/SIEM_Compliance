from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    severity = db.Column(db.String(20), nullable=False) # High, Medium, Low
    status = db.Column(db.String(20), default='Active')  # Active, Inactive

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_ip = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(50))
    policy_name = db.Column(db.String(100)) # Snapshot of policy at time of event
    compliance_status = db.Column(db.String(20)) # Compliant, Non-Compliant
    details = db.Column(db.String(200))