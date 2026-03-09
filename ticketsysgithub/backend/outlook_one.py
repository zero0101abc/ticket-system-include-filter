#!/usr/bin/env python3
"""
SCAN ONE UNREAD EMAIL
- Scans only 1 latest unread email
- Returns extracted ticket data or null if no new email
- Extracts username, phone, ip, address (like normal scan)
"""

import win32com.client
import json
import re
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class OneEmailScanner:
    def __init__(self):
        self.load_filters()
        self.load_sites()
        self.last_email_id = self.load_last_email_id()
    
    def load_filters(self):
        try:
            filters_path = os.path.join(PROJECT_ROOT, 'database', 'email_filters.json')
            with open(filters_path, "r", encoding="utf-8") as f:
                self.filters = json.load(f)
        except:
            self.filters = []
    
    def load_sites(self):
        """Load sites for IP and address lookup"""
        try:
            sites_path = os.path.join(PROJECT_ROOT, 'database', 'site.json')
            with open(sites_path, "r", encoding="utf-8") as f:
                self.sites = json.load(f)
        except:
            self.sites = []
    
    def get_site_info(self, shop_code):
        """Get IP and address from sites based on shop code"""
        if not shop_code or not self.sites:
            return {'ip': '', 'address': ''}
        
        shop_upper = shop_code.upper()
        
        for site in self.sites:
            site_code = site.get('shop_code', '').upper()
            if site_code == shop_upper:
                return {
                    'ip': site.get('ip', ''),
                    'address': site.get('address', '')
                }
        
        return {'ip': '', 'address': ''}
    
    def load_last_email_id(self):
        """Load last processed email ID from settings"""
        try:
            from backend.db import get_setting
            return get_setting('last_processed_email_id', '')
        except:
            return ''
    
    def save_last_email_id(self, email_id):
        """Save last processed email ID to settings"""
        try:
            from backend.db import set_setting
            set_setting('last_processed_email_id', str(email_id))
        except:
            pass
    
    def contains(self, text, search):
        return search.lower() in str(text).lower()
    
    def apply_filters(self, email_data):
        actions = []
        for f in self.filters:
            if not f.get('enabled', True):
                continue
            
            if f.get('from_email') and not self.contains(email_data.get('sender', ''), f['from_email']):
                continue
            
            if f.get('to_email'):
                to_names = [r['name'] for r in email_data.get('recipients', []) if r.get('type') == 1]
                if not any(f['to_email'] in name for name in to_names):
                    continue
            
            if f.get('action'):
                actions.append(f['action'])
        
        return actions
    
    def extract_cdc(self, body):
        """Extract CDC ticket data - same as create_tickets.py"""
        data = {}
        try:
            # Ticket number
            m = re.search(r'Inci\. ID:\s*([A-Z0-9]+)', body)
            if m:
                data['ticket_number'] = m.group(1)
            
            # Shop
            m = re.search(r'Cust\. Name:\s*.*?[(（](.*?)[)）]', body, re.DOTALL)
            if m:
                shop = m.group(1).strip()
                shop_clean = shop.strip('_').strip()
                if not shop_clean.lower().startswith(('ss', 'it', 'ih', 'ik')):
                    shop = f'cdc{shop}'
                elif shop_clean.lower().startswith('ik'):
                    if shop.lower().startswith('cdc'):
                        shop = shop[3:]
                data['shop'] = shop
            
            # Description
            m = re.search(r'Description:\s*(.*?)\r\n', body, re.DOTALL)
            if m:
                data['description'] = m.group(1).strip()
            
            # Username (Reporter Name)
            username_match = re.search(r'Reporter Name:\s*\n\s*(.+?)(?:\n|$)', body)
            if username_match:
                data['username'] = username_match.group(1).strip()
            
            # Phone (Contact Number 1)
            phone_match = re.search(r'Contact Number 1:\s*\n\s*(.+?)(?:\n|$)', body)
            if phone_match:
                data['phone'] = phone_match.group(1).strip()
                
        except:
            pass
        return data
    
    def extract_mx(self, body):
        """Extract MX ticket data - same as create_tickets.py"""
        data = {}
        try:
            # Ticket number
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
            
            # Username (User:)
            user_idx = body.lower().find('user:')
            if user_idx != -1:
                user_text = body[user_idx+5:user_idx+105]
                user_split = user_text.split('\r\n')
                data['username'] = user_split[0].strip()
            
            # Phone (Phone:)
            phone_idx = body.lower().find('phone:')
            if phone_idx != -1:
                phone_text = body[phone_idx+6:phone_idx+56]
                phone_split = phone_text.split('\r\n')
                data['phone'] = phone_split[0].strip()
                
        except:
            pass
        return data
    
    def extract_fw(self, body):
        """Extract Fairwood ticket data"""
        data = {}
        try:
            text = body
            
            # Ticket number
            ticket_match = re.search(r'申請編號[:\s]*([A-Z0-9\-]+)', text, re.IGNORECASE)
            if ticket_match:
                data['ticket_number'] = ticket_match.group(1).strip()
            
            # Location
            location_match = re.search(r'[分店\s\t]+F(\d+)', text) or re.search(r'F(\d+)', text)
            if location_match:
                loc_num = location_match.group(1)
                if loc_num:
                    data['shop'] = 'FW' + loc_num
            
            # Description
            desc_match = re.search(r'故障現象[:\s]*([^\n]+)', text)
            if desc_match:
                description = desc_match.group(1).strip()
                if description:
                    data['description'] = description
            
            # Username (申請者)
            username_match = re.search(r'申請者\s*([^\t]+)', text)
            if username_match:
                data['username'] = username_match.group(1).strip()
            
            # Phone (8-digit pattern)
            phone_match = re.search(r'\b(\d{8})\b', text)
            if phone_match:
                data['phone'] = phone_match.group(1)
                
        except:
            pass
        return data
    
    def format_date(self, date_str):
        """Convert date string to YYYY-MM-DD HH:MM format"""
        try:
            from datetime import datetime
            if 'T' in date_str and 'Z' in date_str:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            elif '+' in date_str:
                dt = datetime.fromisoformat(date_str)
            else:
                dt = datetime.fromisoformat(date_str)
            return dt.strftime('%Y-%m-%d %H:%M')
        except:
            try:
                if ' ' in date_str:
                    date_part = date_str.split(' ')[0]
                    time_part = date_str.split(' ')[1].split('.')[0].split('+')[0]
                    return f"{date_part} {time_part[:5]}"
            except:
                pass
            return date_str
    
    def should_delete_after_scan(self):
        try:
            from backend.db import get_setting
            return get_setting('delete_after_scan', 'false') == 'true'
        except:
            return False

    def get_one_unread(self):
        """Get one latest unread email"""
        try:
            outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
            inbox = outlook.GetDefaultFolder(6)
            messages = inbox.Items
            messages.Sort("[ReceivedTime]", True)
            
            if messages.Count == 0:
                return None
            
            last_id = self.last_email_id
            
            # Scan up to 10 most recent emails to find unread ones
            for i in range(min(10, messages.Count)):
                msg = messages[i]
                
                email_id = msg.EntryID
                
                # Skip if already processed
                if last_id and email_id == last_id:
                    continue
                
                # Check if unread
                if msg.Unread:
                    sender = msg.SenderName if msg.SenderName else msg.SenderEmailAddress
                    subject = msg.Subject or ""
                    body = msg.Body or ""
                    
                    email_data = {
                        'sender': sender,
                        'subject': subject,
                        'body': body,
                        'received_time': msg.ReceivedTime.strftime("%Y-%m-%d %H:%M") if msg.ReceivedTime else ""
                    }
                    
                    # Apply filters to get actions
                    actions = self.apply_filters(email_data)
                    
                    if not actions:
                        # Email doesn't match any filter. Mark as read so we don't process it again.
                        try:
                            msg.Unread = False
                            msg.Save()
                        except Exception as e:
                            pass
                        continue
                    
                    # Extract data based on actions
                    ticket_data = {}
                    
                    if 'extract_cdc' in actions:
                        ticket_data = self.extract_cdc(body)
                    elif 'send_mx_alert' in actions:
                        ticket_data = self.extract_mx(body)
                    elif 'extract_fw' in actions:
                        ticket_data = self.extract_fw(body)
                    

                    
                    if ticket_data.get('ticket_number'):
                        # Format date
                        if 'date' not in ticket_data:
                            ticket_data['date'] = self.format_date(email_data.get('received_time', ''))
                        
                        # Ensure required fields
                        if 'shop' not in ticket_data:
                            ticket_data['shop'] = ''
                        if 'description' not in ticket_data:
                            ticket_data['description'] = ''
                        
                        # Get IP and address from sites database
                        site_info = self.get_site_info(ticket_data.get('shop', ''))
                        ticket_data['ip'] = site_info.get('ip', '')
                        ticket_data['address'] = site_info.get('address', '')
                        
                        # Save this email ID as processed
                        self.save_last_email_id(email_id)
                        
                        try:
                            if self.should_delete_after_scan():
                                msg.Delete()
                            else:
                                msg.Unread = False
                                msg.Save()
                        except Exception as e:
                            print(f"Failed to update email status: {e}")

                        
                        return {
                            'email': email_data,
                            'ticket': {
                                **ticket_data,
                                'sender': sender,
                                'subject': subject,
                                'date': ticket_data.get('date', email_data['received_time']),
                                'actions': actions
                            }
                        }
            
            return None
            
        except Exception as e:
            return {'error': str(e)}


def main():
    scanner = OneEmailScanner()
    result = scanner.get_one_unread()
    
    if result is None:
        print("NO_NEW_EMAIL")
    elif 'error' in result:
        print(f"ERROR: {result['error']}")
    else:
        print("NEW_EMAIL_FOUND")
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
