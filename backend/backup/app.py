from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import shutil
import os
from pathlib import Path
from scanner import DataScanner
from database import Database

app = FastAPI(title="Sensitive Data Discovery Scanner")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
scanner = DataScanner()
db = Database()
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@app.get("/")
async def root():
    return {"message": "Sensitive Data Discovery Scanner API"}

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and scan a file"""
    try:
        # Validate file size (50MB limit)
        file.file.seek(0, 2)
        size = file.file.tell()
        file.file.seek(0)
        
        if size > 50 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large (max 50MB)")
        
        # Save file
        file_path = UPLOAD_DIR / file.filename
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Scan file
        scan_result = await scanner.scan_file(str(file_path), file.filename)
        
        # Save to database
        scan_id = db.save_scan(scan_result)
        
        # Clean up
        os.remove(file_path)
        
        return {
            "scan_id": scan_id,
            "results": scan_result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans")
async def get_scans():
    """Get all scans"""
    return db.get_all_scans()

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    """Get specific scan details"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a scan"""
    if db.delete_scan(scan_id):
        return {"message": "Scan deleted"}
    raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/dashboard")
async def get_dashboard():
    """Get dashboard statistics"""
    return db.get_dashboard_stats()

@app.get("/api/report/{scan_id}/csv")
async def export_csv(scan_id: int):
    """Export findings as CSV"""
    import csv
    from io import StringIO
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Filename', 'Line Number', 'Data Type', 'Detected Value', 'Risk Level', 'Risk Score', 'Context'])
    
    for finding in scan['findings']:
        writer.writerow([
            finding['filename'],
            finding['line_number'],
            finding['data_type'],
            finding['detected_value'],
            finding['risk_level'],
            finding['risk_score'],
            finding['context']
        ])
    
    return JSONResponse(content={"csv": output.getvalue()})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
