from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import pandas as pd
import asyncio
import aiofiles
import re
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from typing import List, Dict, Optional
import json
import uuid
from pathlib import Path
import time
from datetime import datetime
import numpy as np

app = FastAPI(title="Email List Cleaner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global storage for processing tasks
processing_tasks = {}

class ProcessingStatus(BaseModel):
    task_id: str
    status: str
    progress: float
    total_emails: int
    processed_emails: int
    valid_emails: int
    invalid_emails: int
    start_time: str
    estimated_completion: Optional[str] = None

class CleaningOptions(BaseModel):
    remove_duplicates: bool = True
    validate_syntax: bool = True
    check_domains: bool = True
    remove_disposable: bool = True
    whitelist_domains: List[str] = []
    blacklist_domains: List[str] = []
    custom_regex: Optional[str] = None

class EmailResult(BaseModel):
    email: str
    is_valid: bool
    reason: Optional[str] = None
    domain: str

# Disposable email domains list (partial)
DISPOSABLE_DOMAINS = {
    '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org',
    'yopmail.com', 'temp-mail.org', 'throwaway.email', 'maildrop.cc',
    'fakeinbox.com', 'tempmailaddress.com', 'getairmail.com', 'mailnull.com'
}

class EmailCleaner:
    def __init__(self):
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
    async def validate_email_syntax(self, email: str) -> tuple[bool, Optional[str]]:
        """Fast email syntax validation"""
        if not email or '@' not in email:
            return False, "Invalid format"
        
        email = email.strip().lower()
        
        if not self.email_pattern.match(email):
            return False, "Syntax error"
        
        return True, None
    
    async def check_domain_mx(self, domain: str) -> bool:
        """Check if domain has MX records"""
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            try:
                dns.resolver.resolve(domain, 'A')
                return True
            except:
                return False
    
    def is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is disposable email provider"""
        return domain.lower() in DISPOSABLE_DOMAINS
    
    async def clean_email(self, email: str, options: CleaningOptions) -> EmailResult:
        """Clean and validate a single email"""
        email = email.strip()
        domain = email.split('@')[-1].lower() if '@' in email else ''
        
        result = EmailResult(email=email, is_valid=False, domain=domain)
        
        # Syntax validation
        if options.validate_syntax:
            is_valid, reason = await self.validate_email_syntax(email)
            if not is_valid:
                result.reason = reason
                return result
        
        # Domain validation
        if options.check_domains:
            if options.whitelist_domains and domain not in options.whitelist_domains:
                result.reason = "Domain not in whitelist"
                return result
            
            if options.blacklist_domains and domain in options.blacklist_domains:
                result.reason = "Domain in blacklist"
                return result
            
            if options.remove_disposable and self.is_disposable_domain(domain):
                result.reason = "Disposable email domain"
                return result
            
            # MX record check (async)
            if not await self.check_domain_mx(domain):
                result.reason = "Invalid domain (no MX/A record)"
                return result
        
        # Custom regex validation
        if options.custom_regex:
            custom_pattern = re.compile(options.custom_regex)
            if not custom_pattern.match(email):
                result.reason = "Failed custom validation"
                return result
        
        result.is_valid = True
        return result

cleaner = EmailCleaner()

@app.get("/")
async def root():
    return {"message": "Email List Cleaner API", "version": "1.0.0"}

@app.get("/test")
async def test():
    return {"status": "working", "message": "Backend is running correctly"}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and process email list file"""
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        if not file.filename.endswith(('.csv', '.txt', '.xlsx', '.xls')):
            raise HTTPException(status_code=400, detail="Unsupported file format")
        
        task_id = str(uuid.uuid4())
        file_path = f"uploads/{task_id}_{file.filename}"
        
        # Ensure uploads directory exists
        try:
            Path("uploads").mkdir(exist_ok=True)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to create uploads directory: {str(e)}")
        
        try:
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
        
        processing_tasks[task_id] = {
            "file_path": file_path,
            "status": "uploaded",
            "progress": 0.0,
            "total_emails": 0,
            "processed_emails": 0,
            "valid_emails": 0,
            "invalid_emails": 0,
            "start_time": datetime.now().isoformat()
        }
        
        return {"task_id": task_id, "message": "File uploaded successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.post("/process/{task_id}")
async def start_processing(task_id: str, options: CleaningOptions, background_tasks: BackgroundTasks):
    """Start processing the uploaded file"""
    if task_id not in processing_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    background_tasks.add_task(process_emails, task_id, options)
    
    processing_tasks[task_id]["status"] = "processing"
    
    return {"message": "Processing started", "task_id": task_id}

async def process_emails(task_id: str, options: CleaningOptions):
    """Process emails in the background"""
    task_data = processing_tasks[task_id]
    file_path = task_data["file_path"]
    
    try:
        # Check if file exists
        if not Path(file_path).exists():
            task_data["status"] = "error"
            task_data["error"] = f"File not found: {file_path}"
            return
        
        # Read emails from file
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                emails = df.iloc[:, 0].astype(str).tolist()
            elif file_path.endswith('.xlsx') or file_path.endswith('.xls'):
                df = pd.read_excel(file_path)
                emails = df.iloc[:, 0].astype(str).tolist()
            else:  # .txt
                async with aiofiles.open(file_path, 'r') as f:
                    content = await f.read()
                    emails = [line.strip() for line in content.split('\n') if line.strip()]
        except Exception as e:
            task_data["status"] = "error"
            task_data["error"] = f"Failed to read file: {str(e)}"
            return
        
        # Remove duplicates if option is enabled
        if options.remove_duplicates:
            emails = list(dict.fromkeys(emails))  # Preserve order while removing duplicates
        
        task_data["total_emails"] = len(emails)
        task_data["status"] = "processing"
        
        # Process emails in batches for performance
        batch_size = 1000
        valid_emails = []
        invalid_emails = []
        
        for i in range(0, len(emails), batch_size):
            batch = emails[i:i+batch_size]
            
            # Process batch concurrently
            tasks = [cleaner.clean_email(email, options) for email in batch]
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result.is_valid:
                    valid_emails.append(result.email)
                else:
                    invalid_emails.append({
                        "email": result.email,
                        "reason": result.reason
                    })
            
            task_data["processed_emails"] = i + len(batch)
            task_data["valid_emails"] = len(valid_emails)
            task_data["invalid_emails"] = len(invalid_emails)
            task_data["progress"] = (i + len(batch)) / len(emails) * 100
        
        # Save results
        results_path = f"results/{task_id}_results.csv"
        Path("results").mkdir(exist_ok=True)
        
        # Save valid emails
        valid_df = pd.DataFrame({"email": valid_emails})
        valid_df.to_csv(results_path.replace('.csv', '_valid.csv'), index=False)
        
        # Save invalid emails with reasons
        invalid_df = pd.DataFrame(invalid_emails)
        invalid_df.to_csv(results_path.replace('.csv', '_invalid.csv'), index=False)
        
        task_data["status"] = "completed"
        task_data["results_path"] = results_path
        
    except Exception as e:
        task_data["status"] = "error"
        task_data["error"] = str(e)

@app.get("/status/{task_id}")
async def get_status(task_id: str) -> ProcessingStatus:
    """Get processing status"""
    if task_id not in processing_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task_data = processing_tasks[task_id]
    
    # Calculate estimated completion time
    estimated_completion = None
    if task_data["status"] == "processing" and task_data["processed_emails"] > 0:
        elapsed_time = time.time() - datetime.fromisoformat(task_data["start_time"]).timestamp()
        emails_per_second = task_data["processed_emails"] / elapsed_time
        remaining_emails = task_data["total_emails"] - task_data["processed_emails"]
        remaining_seconds = remaining_emails / emails_per_second if emails_per_second > 0 else 0
        estimated_completion = datetime.fromtimestamp(
            time.time() + remaining_seconds
        ).isoformat()
    
    return ProcessingStatus(
        task_id=task_id,
        status=task_data["status"],
        progress=task_data["progress"],
        total_emails=task_data["total_emails"],
        processed_emails=task_data["processed_emails"],
        valid_emails=task_data["valid_emails"],
        invalid_emails=task_data["invalid_emails"],
        start_time=task_data["start_time"],
        estimated_completion=estimated_completion
    )

@app.get("/download/{task_id}/{file_type}")
async def download_results(task_id: str, file_type: str):
    """Download processed results"""
    if task_id not in processing_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task_data = processing_tasks[task_id]
    
    if task_data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Processing not completed")
    
    if file_type == "valid":
        file_path = f"results/{task_id}_results_valid.csv"
    elif file_type == "invalid":
        file_path = f"results/{task_id}_results_invalid.csv"
    else:
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    if not Path(file_path).exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        file_path,
        media_type="text/csv",
        filename=f"cleaned_emails_{file_type}_{task_id}.csv"
    )

@app.get("/")
async def root():
    return {"message": "Email List Cleaner API", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
