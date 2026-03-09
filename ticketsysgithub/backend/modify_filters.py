#!/usr/bin/env python3
"""
Direct filter modification examples
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.testfile.test_fixed import EmailFilterManager

def example_modifications():
    """Examples of how to modify filters directly in code"""
    
    filter_manager = EmailFilterManager()
    
    print("=== Direct Filter Modification Examples ===\n")
    
    # Example 1: Change MX filter
    print("1. Updating MX filter...")
    success = filter_manager.edit_filter(
        1,  # MX filter ID
        from_email="new-mx@company.com",
        subject_filter='contains(subject, "Critical MX")',
        action="urgent_mx_notification"
    )
    print(f"MX filter updated: {success}")
    
    # Example 2: Change CDC filter
    print("\n2. Updating CDC filter...")
    success = filter_manager.edit_filter(
        2,  # CDC filter ID
        subject_filter='or(contains(subject, "CDC"), contains(subject, "Health"))',
        body_filter='contains(body, "report")',
        action="process_health_data"
    )
    print(f"CDC filter updated: {success}")
    
    # Example 3: Disable a filter
    print("\n3. Disabling MX filter...")
    success = filter_manager.edit_filter(1, enabled=False)
    print(f"MX filter disabled: {success}")
    
    # Example 4: Re-enable filter
    print("\n4. Re-enabling MX filter...")
    success = filter_manager.edit_filter(1, enabled=True)
    print(f"MX filter re-enabled: {success}")
    
    # Example 5: Add complex Power Automate expression
    print("\n5. Adding complex expression to CDC filter...")
    success = filter_manager.edit_filter(
        2,
        subject_filter='if(contains(subject, "URGENT"), "HIGH_PRIORITY", "NORMAL")',
        action='if(contains(body, "statistics"), "analyze_data", "log_message")'
    )
    print(f"CDC filter with complex expression updated: {success}")
    
    print("\n6. Current filter status:")
    filters = filter_manager.list_filters()
    for f in filters:
        print(f"ID:{f['id']} - {f['name']} (Enabled: {f.get('enabled', True)})")
        print(f"  From: {f['from_email']}")
        print(f"  Subject: {f['subject_filter']}")
        print(f"  Action: {f['action']}")
        print()

if __name__ == "__main__":
    example_modifications()