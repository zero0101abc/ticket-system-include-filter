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

def create_target_tickets():
    """Create target_ticket.json with custom date range"""
    
    try:
        with open('database/ticket.json', 'r', encoding='utf-8') as f:
            all_tickets = json.load(f)
    except FileNotFoundError:
        print("Error: ticket.json not found. Please run create_tickets.py first.")
        return
    
    print("=== Date Range Filter ===")
    print(f"Total tickets available: {len(all_tickets)}")
    
    # Show available date range
    dates = [t['date'] for t in all_tickets if 'date' in t]
    if dates:
        min_date = min(dates)
        max_date = max(dates)
        print(f"Available date range: {min_date} to {max_date}")
    
    # Create several examples
    print("\nCreating filtered ticket files...")
    
    # Example 1: 20-1-2026 to 22-1-2026 (3 days)
    start_date = "20-1-2026"
    end_date = "22-1-2026"
    filtered = filter_tickets_by_date_range(all_tickets, start_date, end_date)
    
    if filtered:
        with open('database/target_ticket.json', 'w', encoding='utf-8') as f:
            json.dump(filtered, f, indent=2, ensure_ascii=False)
        print(f"Created target_ticket.json: {len(filtered)} tickets from {start_date} to {end_date}")
        
        # Show summary
        cdc_count = len([t for t in filtered if t['shop'].startswith('cdc')])
        ss_count = len([t for t in filtered if t['shop'].startswith('SS')])
        mx_count = len([t for t in filtered if t['shop'].startswith('MX')])
        
        print(f"  CDC: {cdc_count}, SS: {ss_count}, MX: {mx_count}")
        
        print("\nFirst 3 tickets:")
        for i, ticket in enumerate(filtered[:3]):
            desc = ticket['description'][:40] + "..." if len(ticket['description']) > 40 else ticket['description']
            print(f"  {i+1}. {ticket['ticket_number']} | {ticket['date']} | {ticket['shop']} | {desc}")
    else:
        print(f"No tickets found from {start_date} to {end_date}")
    
    # Example 2: Full month
    print(f"\nCreating full month filter...")
    start_date = "1-1-2026"
    end_date = "31-1-2026"
    full_month = filter_tickets_by_date_range(all_tickets, start_date, end_date)
    
    if full_month:
        with open('january_2026_tickets.json', 'w', encoding='utf-8') as f:
            json.dump(full_month, f, indent=2, ensure_ascii=False)
        print(f"Created january_2026_tickets.json: {len(full_month)} tickets for January 2026")

if __name__ == "__main__":
    create_target_tickets()