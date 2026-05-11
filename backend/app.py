from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any
import shutil
from pathlib import Path

app = FastAPI(title="Sensitive Data Scanner")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create upload directory
UPLOAD_DIR = Path("/tmp/scanner_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Simple in-memory storage for scans (for testing)
scans_db = []
scan_counter = 1

# Patterns for detection
PATTERNS = {
    'email': {
        'regex': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'risk': 'low',
        'score': 3,
        'name': 'Email Address'
    },
    'credit_card_visa': {
        'regex': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
        'risk': 'critical',
        'score': 10,
        'name': 'Visa Card'
    },
    'credit_card_mastercard': {
        'regex': r'\b5[1-5][0-9]{14}\b',
        'risk': 'critical',
        'score': 10,
        'name': 'Mastercard'
    },
    'credit_card_amex': {
        'regex': r'\b3[47][0-9]{13}\b',
        'risk': 'critical',
        'score': 10,
        'name': 'American Express'
    },
    'ssn': {
        'regex': r'\b\d{3}-\d{2}-\d{4}\b',
        'risk': 'high',
        'score': 8,
        'name': 'SSN'
    },
    'api_key_google': {
        'regex': r'AIza[0-9A-Za-z\-_]{35}',
        'risk': 'critical',
        'score': 10,
        'name': 'Google API Key'
    },
    'api_key_aws': {
        'regex': r'AKIA[0-9A-Z]{16}',
        'risk': 'critical',
        'score': 10,
        'name': 'AWS Key'
    },
    'ip_address': {
        'regex': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'risk': 'medium',
        'score': 5,
        'name': 'IP Address'
    },
    'phone': {
        'regex': r'\b(?:\+?1?[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
        'risk': 'medium',
        'score': 5,
        'name': 'Phone Number'
    },
    'password': {
        'regex': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]+',
        'risk': 'critical',
        'score': 10,
        'name': 'Plaintext Password'
    }
}

def redact_value(value: str, pattern_name: str) -> str:
    """Redact sensitive values for display"""
    if 'credit_card' in pattern_name:
        return f"****-****-****-{value[-4:]}" if len(value) >= 4 else "***REDACTED***"
    elif 'email' in pattern_name:
        parts = value.split('@')
        return f"{parts[0][:2]}***@{parts[1]}" if len(parts[0]) > 2 else "***@***"
    elif 'ssn' in pattern_name:
        return f"***-**-{value[-4:]}" if len(value) >= 4 else "***-**-****"
    elif 'api_key' in pattern_name:
        return f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***REDACTED***"
    else:
        return value[:4] + "..." + value[-4:] if len(value) > 8 else "***REDACTED***"

def scan_file_content(content: str, filename: str) -> Dict[str, Any]:
    """Scan file content for sensitive data"""
    findings = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern_info in PATTERNS.items():
            matches = re.finditer(pattern_info['regex'], line, re.IGNORECASE)
            
            for match in matches:
                detected_value = match.group()
                
                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(line), match.end() + 50)
                context = line[start:end]
                
                findings.append({
                    'data_type': pattern_info['name'],
                    'pattern_name': pattern_name,
                    'detected_value': redact_value(detected_value, pattern_name),
                    'original_value': detected_value,
                    'line_number': line_num,
                    'context': context.strip(),
                    'risk_level': pattern_info['risk'],
                    'risk_score': pattern_info['score'],
                    'filename': filename
                })
    
    # Remove duplicates (same value, same line, same type)
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f['line_number'], f['pattern_name'], f['original_value'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Calculate risk score
    total_risk = sum(f['risk_score'] for f in unique_findings)
    file_size_kb = len(content) / 1024
    risk_score = min(100, (total_risk / max(1, file_size_kb)) * 10)
    
    return {
        'filename': filename,
        'filesize': len(content),
        'total_findings': len(unique_findings),
        'risk_score': round(risk_score, 2),
        'findings': unique_findings,
        'scan_date': datetime.now().isoformat()
    }

@app.get("/")
async def root():
    return {"message": "Sensitive Data Scanner API is running!", "status": "active"}

@app.get("/api/dashboard")
async def get_dashboard():
    """Get dashboard statistics"""
    total_scans = len(scans_db)
    total_findings = sum(s.get('total_findings', 0) for s in scans_db)
    avg_risk = sum(s.get('risk_score', 0) for s in scans_db) / max(1, total_scans)
    
    risk_dist = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    for scan in scans_db:
        for finding in scan.get('findings', []):
            risk_dist[finding['risk_level']] += 1
    
    return {
        'total_scans': total_scans,
        'total_findings': total_findings,
        'average_risk_score': round(avg_risk, 2),
        'risk_distribution': risk_dist,
        'recent_scans': scans_db[-10:]  # Last 10 scans
    }

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and scan a file"""
    global scan_counter
    
    try:
        # Read file content
        content = await file.read()
        
        # Try to decode as text
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            # Try other encodings or treat as binary
            try:
                text_content = content.decode('latin-1')
            except:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Cannot read file as text. Only text-based files are supported."}
                )
        
        # Scan the content
        scan_result = scan_file_content(text_content, file.filename)
        
        # Store in memory
        scan_result['id'] = scan_counter
        scans_db.append(scan_result)
        scan_counter += 1
        
        return {
            "scan_id": scan_result['id'],
            "results": scan_result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans")
async def get_scans():
    """Get all scans"""
    return [{'id': s['id'], 'filename': s['filename'], 'scan_date': s['scan_date'], 
             'total_findings': s['total_findings'], 'risk_score': s['risk_score']} 
            for s in scans_db]

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    """Get specific scan"""
    for scan in scans_db:
        if scan['id'] == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
