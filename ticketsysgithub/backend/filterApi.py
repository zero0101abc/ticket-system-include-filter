#!/usr/bin/env python3
"""
Simple filter management functions
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.testfile.test_fixed import EmailFilterManager

def create_filter(name, from_email="", subject_filter="", body_filter="", action="", description=""):
    """Create a new filter"""
    fm = EmailFilterManager()
    return fm.create_filter(name, from_email, subject_filter, body_filter, action, description)

def edit_filter(filter_id, **kwargs):
    """Edit an existing filter - pass any of: name, from_email, subject_filter, body_filter, action, description, enabled"""
    fm = EmailFilterManager()
    return fm.edit_filter(filter_id, **kwargs)

def delete_filter(filter_id):
    """Delete a filter by ID"""
    fm = EmailFilterManager()
    return fm.delete_filter(filter_id)

def list_filters():
    """List all current filters"""
    fm = EmailFilterManager()
    return fm.list_filters()

# Example usage:
if __name__ == "__main__":
    # Create MX filter
    create_filter("mx", 
                  from_email="system.MX@hkt-emsconnect.com",
                  subject_filter='contains(subject, "MX Alert")',
                  action="send_mx_alert")
    
    # Create CDC filter  
    create_filter("cdc",
                  from_email="cdc@notifications.com", 
                  subject_filter='contains(subject, "CDC")',
                  action="log_cdc_data")
    
    # List filters
    filters = list_filters()
    for f in filters:
        print(f"ID:{f['id']} - {f['name']}: {f['action']}")
    
    # Edit MX filter
    edit_filter(1, subject_filter='equals(subject, "Critical MX")')
    
    print("\nAfter editing:")
    filters = list_filters()
    for f in filters:
        print(f"ID:{f['id']} - {f['name']}: {f['subject_filter']}")