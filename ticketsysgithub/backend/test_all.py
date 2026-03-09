#!/usr/bin/env python3
"""
FULL EMAIL SCANNER
- Scans ALL emails (no limit)
- Shows progress every 10 emails
- Times out if taking too long
"""

import win32com.client
import json
import re
from datetime import datetime, timedelta
import time

# === LIMITS ===
TIMEOUT_SECONDS = 300  # Stop after 5 minutes

class QuickEmailScanner:
    def __init__(self):
        self.load_filters()
    
    def load_filters(self):
        try:
            with open("database/email_filters.json", "r", encoding="utf-8") as f:
                self.filters = json.load(f)
        except:
            self.filters = []
    
    def contains(self, text, search):
        return search.lower() in str(text).lower()
    
    def apply_filters(self, email_data):
        actions = []
        for f in self.filters:
            if not f.get('enabled', True):
                continue
            
            # Check from_email
            if f.get('from_email') and not self.contains(email_data.get('sender', ''), f['from_email']):
                continue
            
            # Check to_email
            if f.get('to_email'):
                to_names = [r['name'] for r in email_data.get('recipients', []) if r.get('type') == 1]
                if not any(f['to_email'] in name for name in to_names):
                    continue
            
            if f.get('action'):
                actions.append(f['action'])
        
        return actions
    
    def extract_cdc(self, body):
        data = {}
        try:
            # Ticket number - look for Inci. ID pattern
            m = re.search(r'Inci\. ID:\s*([A-Z0-9]+)', body)
            if m:
                data['ticket_number'] = m.group(1)
            
            # Shop
            m = re.search(r'Cust\. Name:\s*.*?[(（](.*?)[)）]', body, re.DOTALL)
            if m:
                shop = m.group(1).strip()
                shop_clean = shop.strip('_').strip()
                if not shop_clean.lower().startswith('ss') and not shop_clean.lower().startswith('it') and not shop_clean.lower().startswith('ih'):
                    shop = f'cdc{shop}'
                data['shop'] = shop
            
            # Description
            m = re.search(r'Description:\s*(.*?)\r\n', body, re.DOTALL)
            if m:
                data['description'] = m.group(1).strip()
        except:
            pass
        return data
    
    def extract_mx(self, body):
        data = {}
        try:
            # Number
            idx = body.lower().find('number:')
            if idx != -1:
                text = body[idx+7:idx+207]
                num = text.split('User:')[0].strip()
                data['ticket_number'] = num
            
            # Location/Shop
            idx = body.lower().find('location:')
            if idx != -1:
                text = body[idx+9:idx+209]
                loc = text.split('Category:')[0].strip()
                shop = loc.split('-')[0].strip()
                if shop.startswith('0'):
                    shop = shop[1:]
                data['shop'] = f'MX{shop}'
            
            # Description
            idx = body.lower().find('short description:')
            if idx != -1:
                text = body[idx+18:idx+518]
                desc = text.split('\r\n')[0].strip()
                data['description'] = desc
        except:
            pass
        return data

def main():
    print("="*60)
    print("FULL EMAIL SCANNER")
    print("="*60)
    print(f"Timeout: {TIMEOUT_SECONDS} seconds")
    print("="*60)
    
    start_time = time.time()
    scanner = QuickEmailScanner()
    
    print("\n[1/3] Connecting to Outlook...")
    try:
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        inbox = outlook.GetDefaultFolder(6)
        print("[OK] Connected")
    except Exception as e:
        print(f"[ERROR] {e}")
        return
    
    print("\n[2/3] Scanning ALL emails...")
    try:
        messages = inbox.Items
        messages.Sort("[ReceivedTime]", True)
        
        total = messages.Count
        print(f"Scanning ALL {total} emails...")
        
        results = []
        
        i = 0  # Initialize to prevent unbound variable error
        for i in range(total):
            # Check timeout
            if time.time() - start_time > TIMEOUT_SECONDS:
                print(f"\n[TIMEOUT] Stopped after {TIMEOUT_SECONDS}s")
                break
            
            try:
                msg = messages[i]
                
                # Progress every 10 emails
                if i % 10 == 0:
                    elapsed = int(time.time() - start_time)
                    print(f"  {i+1}/{total} ({elapsed}s)", end='\r')
                
                # Get basic data
                sender = f"{msg.SenderName}"
                date = str(msg.ReceivedTime)
                subject = str(msg.Subject)
                body = str(msg.Body)
                
                # Recipients
                recipients = []
                for r in msg.Recipients:
                    recipients.append({"name": r.Name, "email": r.Address, "type": r.Type})
                
                email_data = {
                    "sender": sender,
                    "date": date,
                    "subject": subject,
                    "body": body,
                    "recipients": recipients
                }
                
                # Check if should keep
                actions = scanner.apply_filters(email_data)
                has_isupport = any(r["name"] == "iSupport" for r in recipients)
                
                if has_isupport or actions:
                    email_data["filter_actions"] = actions
                    
                    # Extract data
                    if 'extract_cdc' in actions:
                        cdc_data = scanner.extract_cdc(body)
                        email_data.update(cdc_data)
                    
                    if 'send_mx_alert' in actions:
                        mx_data = scanner.extract_mx(body)
                        email_data.update(mx_data)
                    
                    results.append(email_data)
            
            except Exception as e:
                print(f"\n  Error on email {i+1}: {str(e)[:40]}")
                continue
        
        print(f"\n  Scanned {i+1} emails in {int(time.time()-start_time)}s")
        print(f"  Kept {len(results)} matching emails")
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return
    
    print("\n[3/3] Saving...")
    try:
        with open("database/outlook_emails.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[OK] Saved to outlook_emails.json")
    except Exception as e:
        print(f"[ERROR] {e}")
        return
    
    print("\n" + "="*60)
    print("COMPLETE!")
    print("="*60)
    print(f"Time taken: {int(time.time()-start_time)}s")
    print(f"Emails saved: {len(results)}")
    
    if results:
        mx = sum(1 for e in results if 'send_mx_alert' in e.get('filter_actions', []))
        cdc = sum(1 for e in results if 'extract_cdc' in e.get('filter_actions', []))
        print(f"  MX: {mx}, CDC: {cdc}, Other: {len(results)-mx-cdc}")

if __name__ == "__main__":
    main()