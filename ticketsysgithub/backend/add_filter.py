#!/usr/bin/env python3
"""
Simple script to add a new filter without clearing existing ones
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.testfile.test_fixed import EmailFilterManager

def add_filter(name, from_email="", subject_filter="", body_filter="", action="", description=""):
    """Add a new filter without clearing existing ones"""
    filter_manager = EmailFilterManager()
    
    # Check if filter with this name already exists
    existing_names = [f['name'] for f in filter_manager.filters]
    if name in existing_names:
        print(f"Filter '{name}' already exists. Use edit_filter instead.")
        return False
    
    success = filter_manager.create_filter(
        name=name,
        from_email=from_email,
        subject_filter=subject_filter,
        body_filter=body_filter,
        action=action,
        description=description
    )
    
    if success:
        print(f"Filter '{name}' created successfully with ID {filter_manager.get_next_id() - 1}")
        print(f"Total filters: {len(filter_manager.filters)}")
    else:
        print(f"Failed to create filter '{name}'")
    
    return success

if __name__ == "__main__":
    # Example usage - modify these parameters as needed
    add_filter(
        name="cdc",
        from_email="cdc@notifications.com", 
        subject_filter='contains(subject, "CDC")',
        action="process_cdc",
        description="CDC notification filter"
    )