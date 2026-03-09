#!/usr/bin/env python3
import json
from datetime import datetime

def parse_date(date_str):
    """Parse date string in various formats"""
    try:
        # Handle YYYY-MM-DD HH:MM format
        if ' ' in date_str and ':' in date_str:
            return datetime.strptime(date_str[:16], '%Y-%m-%d %H:%M')
        # Handle YYYY-MM-DD format
        elif '-' in date_str and len(date_str) == 10:
            return datetime.strptime(date_str, '%Y-%m-%d')
        # Handle DD-MM-YYYY format
        elif date_str.count('-') == 2:
            # Try DD-MM-YYYY format
            parts = date_str.split('-')
            if len(parts) == 3 and len(parts[2]) == 4:
                return datetime.strptime(date_str, '%d-%m-%Y')
        return None
    except:
        return None

def filter_tickets_by_date_range(tickets, start_date_str, end_date_str):
    """Filter tickets within date range"""
    start_date = parse_date(start_date_str)
    end_date = parse_date(end_date_str)
    
    if not start_date or not end_date:
        print(f"Error: Invalid date format for {start_date_str} or {end_date_str}")
        return []
    
    # Set end_date to end of day if it's just a date
    if parse_date(end_date_str) and end_date.hour == 0 and end_date.minute == 0:
        end_date = end_date.replace(hour=23, minute=59)
    
    filtered_tickets = []
    
    for ticket in tickets:
        ticket_date = parse_date(ticket['date'])
        if ticket_date and start_date <= ticket_date <= end_date:
            filtered_tickets.append(ticket)
    
    return filtered_tickets

def set_custom_date_range(start_date, end_date):
    """Set custom date range and create target_ticket.json"""
    
    try:
        with open('database/ticket.json', 'r', encoding='utf-8') as f:
            all_tickets = json.load(f)
    except FileNotFoundError:
        print("Error: ticket.json not found. Please run create_tickets.py first.")
        return
    
    print(f"Filtering tickets from {start_date} to {end_date}")
    
    filtered_tickets = filter_tickets_by_date_range(all_tickets, start_date, end_date)
    
    if filtered_tickets:
        with open('database/target_ticket.json', 'w', encoding='utf-8') as f:
            json.dump(filtered_tickets, f, indent=2, ensure_ascii=False)
        
        print(f"SUCCESS: Created target_ticket.json with {len(filtered_tickets)} tickets")
        
        # Show summary
        cdc_count = len([t for t in filtered_tickets if t['shop'].startswith('cdc')])
        ss_count = len([t for t in filtered_tickets if t['shop'].startswith('SS')])
        mx_count = len([t for t in filtered_tickets if t['shop'].startswith('MX')])
        
        print(f"Summary: CDC={cdc_count}, SS={ss_count}, MX={mx_count}")
        
        # Show date range of filtered tickets
        if filtered_tickets:
            first_date = filtered_tickets[0]['date']
            last_date = filtered_tickets[-1]['date']
            print(f"Date range: {first_date} to {last_date}")
    else:
        print(f"No tickets found in date range {start_date} to {end_date}")

# Easy to use functions for common date ranges
def filter_last_week():
    """Filter tickets from last week"""
    set_custom_date_range("22-1-2026", "28-1-2026")

def filter_three_days():
    """Filter tickets from 3 days"""
    set_custom_date_range("20-1-2026", "22-1-2026")

def filter_january():
    """Filter all January tickets"""
    set_custom_date_range("1-1-2026", "31-1-2026")

if __name__ == "__main__":
    print("=== Custom Date Range Filter ===")
    print("Available functions:")
    print("- filter_last_week()  # 22-1-2026 to 28-1-2026")
    print("- filter_three_days() # 20-1-2026 to 22-1-2026") 
    print("- filter_january()    # 1-1-2026 to 31-1-2026")
    print("- set_custom_date_range('DD-MM-YYYY', 'DD-MM-YYYY') # Custom range")
    
    # Run example
    print(f"\nRunning example: filter_three_days()")
    filter_three_days()