#!/usr/bin/env python3
"""
Interactive filter editor for EmailFilterManager
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.testfile.test_fixed import EmailFilterManager

def main():
    print("=== Interactive Filter Editor ===")
    
    filter_manager = EmailFilterManager()
    
    while True:
        print("\n" + "="*50)
        print("CURRENT FILTERS:")
        filters = filter_manager.list_filters()
        
        if not filters:
            print("No filters found.")
        else:
            for f in filters:
                status = "✓" if f.get('enabled', True) else "✗"
                print(f"{status} ID:{f['id']} - {f['name']}")
                print(f"    From: {f['from_email'] or '(empty)'}")
                print(f"    Subject: {f['subject_filter'] or '(empty)'}")
                print(f"    Body: {f['body_filter'] or '(empty)'}")
                print(f"    Action: {f['action'] or '(empty)'}")
            
        
        
        print("\nOPTIONS:")
        print("1. Edit filter by ID")
        print("2. Create new filter")
        print("3. Delete filter")
        print("4. Toggle filter (enable/disable)")
        print("5. Test filter with sample email")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            # Edit filter
            try:
                filter_id = int(input("Enter filter ID to edit: "))
                print(f"\nEditing filter ID {filter_id}")
                print("Leave empty to keep current value")
                
                # Get current filter
                current_filter = next((f for f in filters if f['id'] == filter_id), None)
                if not current_filter:
                    print("Filter not found!")
                    continue
                
                # Get new values
                new_values = {}
                
                new_name = input(f"Name [{current_filter['name']}]: ").strip()
                if new_name:
                    new_values['name'] = new_name
                
                new_from = input(f"From email [{current_filter['from_email']}]: ").strip()
                if new_from:
                    new_values['from_email'] = new_from
                
                new_subject = input(f"Subject filter [{current_filter['subject_filter']}]: ").strip()
                if new_subject:
                    new_values['subject_filter'] = new_subject
                
                new_body = input(f"Body filter [{current_filter['body_filter']}]: ").strip()
                if new_body:
                    new_values['body_filter'] = new_body
                
                new_action = input(f"Action [{current_filter['action']}]: ").strip()
                if new_action:
                    new_values['action'] = new_action
                
                new_desc = input(f"Description [{current_filter['description']}]: ").strip()
                if new_desc:
                    new_values['description'] = new_desc
                
                if new_values:
                    success = filter_manager.edit_filter(filter_id, **new_values)
                    print(f"Filter updated: {success}")
                else:
                    print("No changes made.")
                    
            except ValueError:
                print("Invalid ID!")
        
        elif choice == "2":
            # Create new filter
            print("\nCreating new filter")
            name = input("Filter name: ").strip()
            from_email = input("From email (optional): ").strip()
            subject_filter = input("Subject filter (optional): ").strip()
            body_filter = input("Body filter (optional): ").strip()
            action = input("Action (optional): ").strip()
            description = input("Description (optional): ").strip()
            
            success = filter_manager.create_filter(
                name=name,
                from_email=from_email,
                subject_filter=subject_filter,
                body_filter=body_filter,
                action=action,
                description=description
            )
            print(f"Filter created: {success}")
        
        elif choice == "3":
            # Delete filter
            try:
                filter_id = int(input("Enter filter ID to delete: "))
                confirm = input(f"Are you sure you want to delete filter {filter_id}? (y/N): ").strip().lower()
                if confirm == 'y':
                    success = filter_manager.delete_filter(filter_id)
                    print(f"Filter deleted: {success}")
                else:
                    print("Cancelled.")
            except ValueError:
                print("Invalid ID!")
        
        elif choice == "4":
            # Toggle filter
            try:
                filter_id = int(input("Enter filter ID to toggle: "))
                current_filter = next((f for f in filters if f['id'] == filter_id), None)
                if current_filter:
                    new_status = not current_filter.get('enabled', True)
                    success = filter_manager.edit_filter(filter_id, enabled=new_status)
                    status_text = "enabled" if new_status else "disabled"
                    print(f"Filter {filter_id} {status_text}: {success}")
                else:
                    print("Filter not found!")
            except ValueError:
                print("Invalid ID!")
        
        elif choice == "5":
            # Test filter
            try:
                filter_id = int(input("Enter filter ID to test: "))
                print("\nEnter sample email data:")
                
                sender = input("Sender email: ").strip()
                subject = input("Subject: ").strip()
                body = input("Body (first 100 chars): ").strip()[:100]
                
                sample_email = {
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "date": "2026-01-26",
                    "recipients": []
                }
                
                # Test specific filter
                current_filter = next((f for f in filters if f['id'] == filter_id), None)
                if current_filter:
                    print(f"\nTesting filter: {current_filter['name']}")
                    actions = filter_manager.apply_filters(sample_email)
                    print(f"Matching actions: {actions}")
                else:
                    print("Filter not found!")
                    
            except ValueError:
                print("Invalid ID!")
        
        elif choice == "6":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()