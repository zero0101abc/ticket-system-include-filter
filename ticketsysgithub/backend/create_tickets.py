#!/usr/bin/env python3
import json
import re
import sys
import io
from datetime import datetime


def load_sites():
    """Load sites list for IP and Address matching"""
    try:
        with open('database/site.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading sites: {e}")
        return []


def get_site_info(shop_code, sites):
    """Find site info by matching shop codes (case-insensitive)"""
    if not shop_code:
        return None
    shop_lower = shop_code.lower()
    for site in sites:
        if site.get('shop_code', '').lower() == shop_lower:
            return site
    return None


if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def contains(text: str, search: str) -> bool:
    return search.lower() in text.lower()

def apply_filters(filters, email_data):
    """Apply all enabled filters to email data and return matching actions"""
    matching_actions = []
    
    for filter_data in filters:
        if not filter_data.get('enabled', True):
            continue
        
        # Check from email filter
        if filter_data.get('from_email'):
            if not contains(email_data.get('sender', ''), filter_data['from_email']):
                continue
        
        # Check subject filter 
        if filter_data.get('subject_filter'):
            if 'has been assigned to' in filter_data['subject_filter']:
                if 'has been assigned to' not in email_data.get('subject', ''):
                    continue
        
        # Check body filter
        if filter_data.get('body_filter'):
            pass
        
        # Check TO email filter
        if filter_data.get('to_email'):
            to_recipients = [r['name'] for r in email_data.get('recipients', []) if r.get('type') == 1]
            if not any(filter_data['to_email'] in to_name for to_name in to_recipients):
                continue
        
        # If all conditions match, add the action
        if filter_data.get('action'):
            matching_actions.append(filter_data['action'])
    
    return matching_actions

def extract_cdc_data(email_data):
    """Extract CDC specific data with shop prefix logic"""
    body = email_data.get('body', '')
    data = {}
    try:
        # Extract ticket number
        ticket_match = re.search(r'Inci\. ID:\s*([A-Z0-9]+)', body)
        if ticket_match:
            data['ticket_number'] = ticket_match.group(1)
        
        # Extract shop
        shop_match = re.search(r'Cust\. Name:\s*.*?[(（](.*?)[)）]', body, re.DOTALL)
        if shop_match:
            shop = shop_match.group(1).strip()
            # Add "cdc" prefix if shop doesn't start with "ss"
            shop_clean = shop.strip('_').strip()
            if not shop_clean.lower().startswith(('ss', 'it', 'ih', 'ik')):
                shop = f'cdc{shop}'
            elif shop_clean.lower().startswith('ik'):
                # Strip cdc prefix if accidentally passed or already present
                if shop.lower().startswith('cdc'):
                    shop = shop[3:]
            data['shop'] = shop

        # Extract description
        desc_match = re.search(r'Description:\s*(.*?)\r\n', body, re.DOTALL)
        if desc_match:
            data['description'] = desc_match.group(1).strip()
        
        # Extract username (Reporter Name)
        username_match = re.search(r'Reporter Name:\s*\n\s*(.+?)(?:\n|$)', body)
        if username_match:
            data['username'] = username_match.group(1).strip()
        
        # Extract phone (Contact Number 1)
        phone_match = re.search(r'Contact Number 1:\s*\n\s*(.+?)(?:\n|$)', body)
        if phone_match:
            data['phone'] = phone_match.group(1).strip()
            
    except Exception as e:
        print(f"Error extracting CDC data: {e}")
    return data

def extract_fw_data(email_data):
    """Extract Fairwood workflow data from email body"""
    body_text = email_data.get('body', '')
    
    def trim(text: str) -> str:
        return text.strip() if text else ''
    
    fw_data = {}
    
    try:
        text = body_text
        
        # Extract ticket_number: 申請編號: ITD-SUP-000179
        ticket_match = re.search(r'申請編號[:\s]*([A-Z0-9\-]+)', text, re.IGNORECASE)
        if ticket_match:
            fw_data['ticket_number'] = ticket_match.group(1).strip()
        
        # Extract Location - look for F followed by numbers (like F314)
        # Also try the format "分店 F314" or "分店	F314" (with tab)
        location_match = re.search(r'[分店\s\t]+F(\d+)', text) or re.search(r'F(\d+)', text)
        if location_match:
            loc_num = location_match.group(1)
            if loc_num:
                fw_data['shop'] = 'FW' + loc_num
        
        # Extract Description: 故障現象: ...
        desc_match = re.search(r'故障現象[:\s]*([^\n]+)', text)
        if desc_match:
            description = desc_match.group(1).strip()
            if description:
                fw_data['description'] = description
        
        # Extract username (申請者)
        username_match = re.search(r'申請者\s*([^\t]+)', text)
        if username_match:
            fw_data['username'] = username_match.group(1).strip()
        
        # Extract phone (8-digit pattern)
        phone_match = re.search(r'\b(\d{8})\b', text)
        if phone_match:
            fw_data['phone'] = phone_match.group(1)
        
    except Exception as e:
        print(f"Error extracting FW data: {e}")
    
    return fw_data

def extract_mx_data(email_data):
    """Extract MX specific data from email body"""
    body_text = email_data.get('body', '')
    
    def trim(text: str) -> str:
        return text.strip()
    
    def first(items: list) -> str:
        return items[0] if items else ''
    
    def split(text: str, separator: str) -> list:
        return text.split(separator)
    
    def substring(text: str, start_index: int, length: int = None) -> str:
        if length is None:
            return text[start_index:]
        return text[start_index:start_index + length]
    
    def index_of(text: str, search: str) -> int:
        return text.lower().find(search.lower())
    
    def equals(value1, value2) -> bool:
        return str(value1).lower() == str(value2).lower()
    
    def concat(*args) -> str:
        return "".join(str(arg) for arg in args)
    
    mx_data = {}
    
    try:
        # Extract ticket_number
        number_index = index_of(body_text, 'Number:')
        if number_index != -1:
            number_text = substring(body_text, number_index + 7, 200)
            number_split = split(number_text, 'User:')
            ticket_number = trim(first(number_split))
            mx_data['ticket_number'] = ticket_number
        
        # Extract shop
        location_index = index_of(body_text, 'Location:')
        if location_index != -1:
            location_text = substring(body_text, location_index + 9, 200)
            location_split = split(location_text, 'Category:')
            shop_raw = trim(first(location_split))
            
            # Process shop with MX prefix logic
            shop_parts = split(shop_raw, '-')
            shop_base = trim(first(shop_parts))
            
            if equals(substring(shop_base, 0, 1), '0'):
                shop_processed = concat('MX', substring(shop_base, 1))
            else:
                shop_processed = concat('MX', shop_base)
            
            mx_data['shop'] = shop_processed
        
        # Extract description
        desc_index = index_of(body_text, 'Short Description:')
        if desc_index != -1:
            desc_text = substring(body_text, desc_index + 18, 500)
            desc_split = split(desc_text, '\r\n')
            description = trim(first(desc_split))
            mx_data['description'] = description
        
        # Extract username (User:)
        user_index = index_of(body_text, 'User:')
        if user_index != -1:
            user_text = substring(body_text, user_index + 5, 100)
            user_split = split(user_text, '\r\n')
            mx_data['username'] = trim(first(user_split))
        
        # Extract phone (Phone:)
        phone_index = index_of(body_text, 'Phone:')
        if phone_index != -1:
            phone_text = substring(body_text, phone_index + 6, 50)
            phone_split = split(phone_text, '\r\n')
            mx_data['phone'] = trim(first(phone_split))
            
    except Exception as e:
        print(f"Error extracting MX data: {e}")
    
    return mx_data

def format_date(date_str):
    """Convert date string to YYYY-MM-DD HH:MM format"""
    try:
        # Handle different date formats
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

def load_existing_tickets():
    """Load existing ticket.json if it exists"""
    try:
        with open('database/ticket.json', 'r', encoding='utf-8') as f:
            existing = json.load(f)
            print(f"Loaded {len(existing)} existing tickets from ticket.json")
            return existing
    except FileNotFoundError:
        print("No existing ticket.json found - will create new one")
        return []
    except Exception as e:
        print(f"Error loading existing tickets: {e}")
        return []

def merge_tickets(existing_tickets, new_tickets):
    """Merge new tickets with existing, preserving edits and avoiding duplicates"""
    
    # Create a dictionary of existing tickets by ticket_number
    existing_dict = {ticket['ticket_number']: ticket for ticket in existing_tickets}
    
    added_count = 0
    updated_count = 0
    
    for new_ticket in new_tickets:
        ticket_num = new_ticket['ticket_number']
        
        if ticket_num in existing_dict:
            # Ticket already exists - UPDATE only the base fields if changed
            existing = existing_dict[ticket_num]
            
            # Update basic fields only if they changed (preserve user edits)
            if new_ticket.get('shop') and new_ticket['shop'] != existing.get('shop'):
                existing['shop'] = new_ticket['shop']
                updated_count += 1
            
            if new_ticket.get('description') and new_ticket['description'] != existing.get('description'):
                existing['description'] = new_ticket['description']
                updated_count += 1
            
            if new_ticket.get('date') and new_ticket['date'] != existing.get('date'):
                existing['date'] = new_ticket['date']
                updated_count += 1
            
            # --- update IP/address as well if changed ---
            if new_ticket.get('ip') and new_ticket['ip'] != existing.get('ip'):
                existing['ip'] = new_ticket['ip']
                updated_count += 1
            if new_ticket.get('address') and new_ticket['address'] != existing.get('address'):
                existing['address'] = new_ticket['address']
                updated_count += 1
            # ---------------------------------------------
            
            # DO NOT update: problem, handled_by, assigned_to, username, phone, status, resolve_time, ph_rm_os, solution, fu_action
            # These are user-edited fields that should be preserved!
            
        else:
            # NEW ticket - add with default values for editable fields
            new_ticket['problem'] = new_ticket.get('problem', '')
            new_ticket['resolve_time'] = new_ticket.get('resolve_time', '')
            new_ticket['ph_rm_os'] = new_ticket.get('ph_rm_os', '')
            new_ticket['solution'] = new_ticket.get('solution', '')
            new_ticket['fu_action'] = new_ticket.get('fu_action', '')
            new_ticket['handled_by'] = new_ticket.get('handled_by', 'USE_MISSING')
            new_ticket['assigned_to'] = new_ticket.get('assigned_to', '')
            new_ticket['status'] = new_ticket.get('status', 'in progress')
            
            existing_dict[ticket_num] = new_ticket
            added_count += 1
    
    # Convert back to list
    merged_tickets = list(existing_dict.values())
    
    # Sort by date (newest first)
    merged_tickets.sort(key=lambda x: x.get('date', ''), reverse=True)
    
    print(f"\nMerge Summary:")
    print(f"  Existing tickets: {len(existing_tickets)}")
    print(f"  New tickets added: {added_count}")
    print(f"  Tickets updated: {updated_count}")
    print(f"  Total tickets: {len(merged_tickets)}")
    
    return merged_tickets

def create_ticket_json():
    """Process outlook_emails.json and create/update ticket.json with merged data"""
    
    # Load data
    try:
        with open('database/outlook_emails.json', 'r', encoding='utf-8') as f:
            emails = json.load(f)
    except FileNotFoundError:
        print("ERROR: outlook_emails.json not found. Please run test_quick.py first.")
        return
    
    try:
        with open('database/email_filters.json', 'r', encoding='utf-8') as f:
            filters = json.load(f)
    except FileNotFoundError:
        print("ERROR: email_filters.json not found.")
        return
    
    # Load existing tickets
    existing_tickets = load_existing_tickets()
    
    # Load sites so we can automatically attach IP/address
    sites = load_sites()

    # Process new emails
    new_tickets = []
    processed_count = 0
    
    print("\nProcessing emails and extracting ticket data...")
    
    for email in emails:
        # Apply filters to see if this email should be processed
        actions = apply_filters(filters, email)
        
        if not actions:
            continue
        
        processed_count += 1
        ticket_data = {}
        
        # Extract data based on the action
        if 'extract_cdc' in actions:
            extracted = extract_cdc_data(email)
            ticket_data.update(extracted)
        elif 'send_mx_alert' in actions:
            extracted = extract_mx_data(email)
            ticket_data.update(extracted)
        elif 'extract_fw' in actions:
            extracted = extract_fw_data(email)
            ticket_data.update(extracted)
        
        # Only add if we have ticket data
        if ticket_data and 'ticket_number' in ticket_data:
            # Format the date
            ticket_data['date'] = format_date(email.get('date', ''))
            
            # Ensure all required fields are present
            if 'shop' not in ticket_data:
                ticket_data['shop'] = ''
            if 'description' not in ticket_data:
                ticket_data['description'] = ''
            
            # Automatically attach IP and Address based on the shop code
            site_info = get_site_info(ticket_data.get('shop'), sites)
            if site_info:
                ticket_data['ip'] = site_info.get('ip', '')
                ticket_data['address'] = site_info.get('address', '')
            else:
                ticket_data['ip'] = ''
                ticket_data['address'] = ''

            new_tickets.append(ticket_data)
            print(f"  Found: {ticket_data['ticket_number']} - {ticket_data['shop']}")
    
    print(f"\nExtracted {len(new_tickets)} tickets from {len(emails)} emails")
    
    # Merge with existing tickets
    merged_tickets = merge_tickets(existing_tickets, new_tickets)
    
    # Save to ticket.json
    with open('database/ticket.json', 'w', encoding='utf-8') as f:
        json.dump(merged_tickets, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Successfully saved to ticket.json")
    
    if merged_tickets:
        print(f"\nLatest 3 tickets:")
        for i, ticket in enumerate(merged_tickets[:3]):
            desc = ticket['description'][:40] + "..." if len(ticket['description']) > 40 else ticket['description']
            status = ticket.get('status', 'in progress')
            handler = ticket.get('handled_by', 'USE_MISSING')
            print(f"  {i+1}. {ticket['ticket_number']} | {ticket['date']} | {ticket['shop']}")
            print(f"     Status: {status} | Handler: {handler} | {desc}")

if __name__ == "__main__":
    create_ticket_json()
