import re
import os
from typing import List, Dict, Any
from datetime import datetime
import pandas as pd
import pdfplumber
from patterns import DetectionPatterns

class DataScanner:
    """Main scanning engine for sensitive data detection"""
    
    def __init__(self):
        self.patterns = DetectionPatterns.PATTERNS
        
    async def scan_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Scan a single file for sensitive data"""
        findings = []
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Extract text based on file type
        content = await self._extract_content(file_path, file_ext)
        
        if not content:
            return {
                'filename': filename,
                'filesize': file_size,
                'findings': [],
                'total_findings': 0,
                'risk_score': 0,
                'scan_date': datetime.now().isoformat()
            }
        
        # Scan each line
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line_findings = self._scan_line(line, line_num, filename)
            findings.extend(line_findings)
        
        # Calculate risk score
        total_risk = sum(f['risk_score'] for f in findings)
        risk_score = min(100, (total_risk / max(1, file_size / 1024)) * 10)
        
        return {
            'filename': filename,
            'filesize': file_size,
            'findings': findings,
            'total_findings': len(findings),
            'risk_score': round(risk_score, 2),
            'scan_date': datetime.now().isoformat()
        }
    
    def _scan_line(self, line: str, line_num: int, filename: str) -> List[Dict]:
        """Scan a single line for all patterns"""
        findings = []
        
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info['regex'], line, re.IGNORECASE)
            
            for match in matches:
                detected_value = match.group()
                
                # Validate credit cards
                if 'credit_card' in pattern_name:
                    if not DetectionPatterns.validate_credit_card(detected_value):
                        continue
                
                # Get context (surrounding text)
                start = max(0, match.start() - 50)
                end = min(len(line), match.end() + 50)
                context = line[start:end]
                
                findings.append({
                    'data_type': pattern_info['description'],
                    'pattern_name': pattern_name,
                    'detected_value': DetectionPatterns.redact_value(detected_value, pattern_name),
                    'original_value': detected_value,
                    'line_number': line_num,
                    'context': context,
                    'risk_level': pattern_info['risk_level'],
                    'risk_score': pattern_info['risk_score'],
                    'filename': filename
                })
        
        return findings
    
    async def _extract_content(self, file_path: str, file_ext: str) -> str:
        """Extract text content from various file types"""
        try:
            if file_ext in ['.txt', '.csv', '.json', '.log', '.py', '.js', '.html', '.css']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
                    
            elif file_ext in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
                return df.to_string()
                
            elif file_ext == '.pdf':
                text = ""
                with pdfplumber.open(file_path) as pdf:
                    for page in pdf.pages:
                        text += page.extract_text() or ""
                return text
                
            else:
                # Try as text file
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
                    
        except Exception as e:
            return f"Error extracting content: {str(e)}"
