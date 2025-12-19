import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import re
import dns.resolver
import threading
import time
from datetime import datetime
import uuid
from pathlib import Path
import json

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
        
    def validate_email_syntax(self, email):
        """Fast email syntax validation"""
        if not email or '@' not in email:
            return False, "Invalid format"
        
        email = email.strip().lower()
        
        if not self.email_pattern.match(email):
            return False, "Syntax error"
        
        return True, None
    
    def check_domain_mx(self, domain):
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
    
    def is_disposable_domain(self, domain):
        """Check if domain is disposable email provider"""
        return domain.lower() in DISPOSABLE_DOMAINS
    
    def clean_email(self, email, options):
        """Clean and validate a single email"""
        email = email.strip()
        domain = email.split('@')[-1].lower() if '@' in email else ''
        
        result = {'email': email, 'is_valid': False, 'reason': None, 'domain': domain}
        
        # Syntax validation
        if options['validate_syntax']:
            is_valid, reason = self.validate_email_syntax(email)
            if not is_valid:
                result['reason'] = reason
                return result
        
        # Domain validation
        if options['check_domains']:
            if options['whitelist_domains'] and domain not in options['whitelist_domains']:
                result['reason'] = "Domain not in whitelist"
                return result
            
            if options['blacklist_domains'] and domain in options['blacklist_domains']:
                result['reason'] = "Domain in blacklist"
                return result
            
            if options['remove_disposable'] and self.is_disposable_domain(domain):
                result['reason'] = "Disposable email domain"
                return result
            
            # MX record check
            if not self.check_domain_mx(domain):
                result['reason'] = "Invalid domain (no MX/A record)"
                return result
        
        # Custom regex validation
        if options['custom_regex']:
            custom_pattern = re.compile(options['custom_regex'])
            if not custom_pattern.match(email):
                result['reason'] = "Failed custom validation"
                return result
        
        result['is_valid'] = True
        return result

class EmailCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email List Cleaner - Ultra Fast")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0f172a')
        self.root.minsize(1000, 700)
        
        self.cleaner = EmailCleaner()
        self.file_path = None
        self.processing = False
        self.stop_processing = False
        self.processing_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#0f172a')
        title_frame.pack(pady=10)
        
        tk.Label(title_frame, text="📧 Email List Cleaner", 
                font=("Arial", 24, "bold"), 
                fg='#60a5fa', bg='#0f172a').pack()
        
        tk.Label(title_frame, text="Super Fast Working Speed - Domains and Other Mail", 
                font=("Arial", 12), 
                fg='#94a3b8', bg='#0f172a').pack()
        
        # File selection
        file_frame = tk.Frame(self.root, bg='#1e293b')
        file_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(file_frame, text="📁 Select Email File:", 
                font=("Arial", 12, "bold"), 
                fg='white', bg='#1e293b').pack(anchor='w', pady=5)
        
        self.file_label = tk.Label(file_frame, text="No file selected", 
                               font=("Arial", 10), 
                               fg='#94a3b8', bg='#1e293b')
        self.file_label.pack(anchor='w', pady=5)
        
        tk.Button(file_frame, text="Browse Files", 
                command=self.browse_file,
                bg='#3b82f6', fg='white', 
                font=("Arial", 10, "bold"),
                padx=20, pady=5).pack(pady=5)
        
        # Options
        options_frame = tk.Frame(self.root, bg='#1e293b')
        options_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        tk.Label(options_frame, text="⚙️ Cleaning Options:", 
                font=("Arial", 14, "bold"), 
                fg='white', bg='#1e293b').pack(anchor='w', pady=5)
        
        # Checkboxes
        self.options = {
            'remove_duplicates': tk.BooleanVar(value=True),
            'validate_syntax': tk.BooleanVar(value=True),
            'check_domains': tk.BooleanVar(value=True),
            'remove_disposable': tk.BooleanVar(value=True)
        }
        
        checkbox_frame = tk.Frame(options_frame, bg='#1e293b')
        checkbox_frame.pack(fill='x', pady=5)
        
        tk.Checkbutton(checkbox_frame, text="Remove duplicates", 
                     variable=self.options['remove_duplicates'],
                     fg='white', bg='#1e293b', 
                     selectcolor='#1e293b',
                     font=("Arial", 10)).pack(anchor='w')
        
        tk.Checkbutton(checkbox_frame, text="Validate syntax", 
                     variable=self.options['validate_syntax'],
                     fg='white', bg='#1e293b', 
                     selectcolor='#1e293b',
                     font=("Arial", 10)).pack(anchor='w')
        
        tk.Checkbutton(checkbox_frame, text="Check MX/A records", 
                     variable=self.options['check_domains'],
                     fg='white', bg='#1e293b', 
                     selectcolor='#1e293b',
                     font=("Arial", 10)).pack(anchor='w')
        
        tk.Checkbutton(checkbox_frame, text="Block disposable inboxes", 
                     variable=self.options['remove_disposable'],
                     fg='white', bg='#1e293b', 
                     selectcolor='#1e293b',
                     font=("Arial", 10)).pack(anchor='w')
        
        # Domain lists
        domain_frame = tk.Frame(options_frame, bg='#1e293b')
        domain_frame.pack(fill='x', pady=10)
        
        tk.Label(domain_frame, text="Whitelist domains (one per line):", 
                font=("Arial", 10), 
                fg='white', bg='#1e293b').pack(anchor='w')
        
        self.whitelist_text = tk.Text(domain_frame, height=2, bg='#334155', fg='white',
                                   font=("Arial", 9))
        self.whitelist_text.pack(fill='x', pady=3)
        
        tk.Label(domain_frame, text="Blacklist domains (one per line):", 
                font=("Arial", 10), 
                fg='white', bg='#1e293b').pack(anchor='w', pady=(5,0))
        
        self.blacklist_text = tk.Text(domain_frame, height=2, bg='#334155', fg='white',
                                   font=("Arial", 9))
        self.blacklist_text.pack(fill='x', pady=3)
        
        tk.Label(domain_frame, text="Custom regex (optional):", 
                font=("Arial", 10), 
                fg='white', bg='#1e293b').pack(anchor='w', pady=(10,0))
        
        self.regex_entry = tk.Entry(domain_frame, bg='#334155', fg='white',
                               font=("Arial", 9))
        self.regex_entry.pack(fill='x', pady=5)
        
        # Progress
        self.progress_frame = tk.Frame(self.root, bg='#0f172a')
        self.progress_frame.pack(fill='x', padx=20, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, 
                                      maximum=100, length=400)
        self.progress_bar.pack(pady=5)
        
        self.status_label = tk.Label(self.progress_frame, text="Ready to clean emails", 
                                font=("Arial", 10), 
                                fg='#94a3b8', bg='#0f172a')
        self.status_label.pack()
        
        self.stats_label = tk.Label(self.progress_frame, text="", 
                                font=("Arial", 9), 
                                fg='#64748b', bg='#0f172a')
        self.stats_label.pack()
        
        # Action buttons
        button_frame = tk.Frame(self.root, bg='#0f172a')
        button_frame.pack(pady=10)
        
        self.clean_button = tk.Button(button_frame, text="🚀 Start Cleaning", 
                                command=self.start_cleaning,
                                bg='#10b981', fg='white', 
                                font=("Arial", 12, "bold"),
                                padx=30, pady=10)
        self.clean_button.pack(side='left', padx=5)
        
        self.save_button = tk.Button(button_frame, text="💾 Save Results", 
                                command=self.save_results,
                                bg='#3b82f6', fg='white', 
                                font=("Arial", 12, "bold"),
                                padx=30, pady=10,
                                state='disabled')
        self.save_button.pack(side='left', padx=5)
        
        # Results
        self.results = []
        
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select email list file",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), 
                      ("Excel files", "*.xlsx *.xls"), ("All files", "*.*")]
        )
        
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=f"Selected: {Path(file_path).name}")
            
    def get_options(self):
        whitelist = [d.strip() for d in self.whitelist_text.get("1.0", tk.END).split('\n') if d.strip()]
        blacklist = [d.strip() for d in self.blacklist_text.get("1.0", tk.END).split('\n') if d.strip()]
        custom_regex = self.regex_entry.get().strip()
        
        return {
            'remove_duplicates': self.options['remove_duplicates'].get(),
            'validate_syntax': self.options['validate_syntax'].get(),
            'check_domains': self.options['check_domains'].get(),
            'remove_disposable': self.options['remove_disposable'].get(),
            'whitelist_domains': whitelist,
            'blacklist_domains': blacklist,
            'custom_regex': custom_regex if custom_regex else None
        }
    
    def start_cleaning(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
            
        if self.processing:
            return
            
        self.processing = True
        self.clean_button.config(state='disabled')
        self.results = []
        
        # Start processing in background thread
        thread = threading.Thread(target=self.process_emails_thread)
        thread.daemon = True
        thread.start()
        
    def process_emails_thread(self):
        try:
            # Read emails from file
            if self.file_path.endswith('.csv'):
                df = pd.read_csv(self.file_path)
                emails = df.iloc[:, 0].astype(str).tolist()
            elif self.file_path.endswith('.xlsx') or self.file_path.endswith('.xls'):
                df = pd.read_excel(self.file_path)
                emails = df.iloc[:, 0].astype(str).tolist()
            else:  # .txt
                with open(self.file_path, 'r') as f:
                    emails = [line.strip() for line in f.readlines() if line.strip()]
            
            options = self.get_options()
            
            # Remove duplicates if option is enabled
            if options['remove_duplicates']:
                emails = list(dict.fromkeys(emails))  # Preserve order while removing duplicates
            
            total_emails = len(emails)
            valid_emails = []
            invalid_emails = []
            
            # Process emails
            for i, email in enumerate(emails):
                result = self.cleaner.clean_email(email, options)
                if result['is_valid']:
                    valid_emails.append(result['email'])
                else:
                    invalid_emails.append(result)
                
                # Update progress
                progress = ((i + 1) / total_emails) * 100
                self.root.after(0, self.update_progress, progress, i + 1, total_emails, 
                               len(valid_emails), len(invalid_emails))
            
            self.results = valid_emails + invalid_emails
            self.root.after(0, self.processing_complete)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Processing failed: {str(e)}"))
            self.root.after(0, self.reset_ui)
    
    def update_progress(self, progress, processed, total, valid, invalid):
        self.progress_var.set(progress)
        self.status_label.config(text=f"Processing... {processed:,}/{total:,} emails")
        self.stats_label.config(text=f"Valid: {valid:,} | Invalid: {invalid:,}")
        
    def processing_complete(self):
        self.processing = False
        self.status_label.config(text="✅ Cleaning complete!")
        self.save_button.config(state='normal')
        messagebox.showinfo("Success", f"Processed {len(self.results):,} emails successfully!")
    
    def reset_ui(self):
        self.processing = False
        self.clean_button.config(state='normal')
        self.save_button.config(state='disabled')
        self.progress_var.set(0)
        self.status_label.config(text="Ready to clean emails")
        self.stats_label.config(text="")
    
    def save_results(self):
        if not self.results:
            messagebox.showerror("Error", "No results to save!")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save cleaned emails",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if save_path:
            # Separate valid and invalid emails
            valid_emails = [r for r in self.results if isinstance(r, str) for r in [r]]
            invalid_emails = [r for r in self.results if isinstance(r, dict) for r in [r]]
            
            # Save valid emails
            valid_df = pd.DataFrame({'email': valid_emails})
            valid_path = save_path.replace('.csv', '_valid.csv')
            valid_df.to_csv(valid_path, index=False)
            
            # Save invalid emails with reasons
            if invalid_emails:
                invalid_df = pd.DataFrame(invalid_emails)
                invalid_path = save_path.replace('.csv', '_invalid.csv')
                invalid_df.to_csv(invalid_path, index=False)
            
            messagebox.showinfo("Success", f"Results saved to:\n{valid_path}\n{invalid_path if invalid_emails else ''}")

def main():
    root = tk.Tk()
    app = EmailCleanerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
