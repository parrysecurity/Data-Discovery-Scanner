from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    filesize = Column(Integer)
    scan_date = Column(DateTime, default=datetime.now)
    total_findings = Column(Integer)
    risk_score = Column(Float)
    status = Column(String(50), default='completed')
    findings_json = Column(Text)  # Store findings as JSON for simplicity

class Database:
    def __init__(self, db_path="sensitive_scanner.db"):
        self.engine = create_engine(f'sqlite:///{db_path}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
    
    def save_scan(self, scan_data):
        session = self.Session()
        try:
            scan = Scan(
                filename=scan_data['filename'],
                filesize=scan_data['filesize'],
                total_findings=scan_data['total_findings'],
                risk_score=scan_data['risk_score'],
                findings_json=json.dumps(scan_data['findings'])
            )
            session.add(scan)
            session.commit()
            return scan.id
        finally:
            session.close()
    
    def get_all_scans(self):
        session = self.Session()
        try:
            scans = session.query(Scan).order_by(Scan.scan_date.desc()).all()
            return [
                {
                    'id': s.id,
                    'filename': s.filename,
                    'filesize': s.filesize,
                    'scan_date': s.scan_date.isoformat(),
                    'total_findings': s.total_findings,
                    'risk_score': s.risk_score
                }
                for s in scans
            ]
        finally:
            session.close()
    
    def get_scan(self, scan_id):
        session = self.Session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                return {
                    'id': scan.id,
                    'filename': scan.filename,
                    'filesize': scan.filesize,
                    'scan_date': scan.scan_date.isoformat(),
                    'total_findings': scan.total_findings,
                    'risk_score': scan.risk_score,
                    'findings': json.loads(scan.findings_json)
                }
            return None
        finally:
            session.close()
    
    def delete_scan(self, scan_id):
        session = self.Session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                session.delete(scan)
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    def get_dashboard_stats(self):
        session = self.Session()
        try:
            scans = session.query(Scan).all()
            
            total_scans = len(scans)
            total_findings = sum(s.total_findings for s in scans)
            avg_risk = sum(s.risk_score for s in scans) / max(1, total_scans)
            
            # Risk distribution
            risk_dist = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            for scan in scans:
                findings = json.loads(scan.findings_json)
                for finding in findings:
                    risk_dist[finding['risk_level']] += 1
            
            return {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'average_risk_score': round(avg_risk, 2),
                'risk_distribution': risk_dist,
                'recent_scans': self.get_all_scans()[:10]
            }
        finally:
            session.close()
