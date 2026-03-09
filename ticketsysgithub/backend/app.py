#!/usr/bin/env python3
"""
IT Ticket Management System - Flask Server
With SQLite database and multi-user authentication
"""

from flask import Flask, request, redirect, session, jsonify, send_from_directory, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
import subprocess
import json
import os
import shutil
from datetime import datetime, timedelta
import hashlib

# Import database module
import db as database

# Configuration
app = Flask(__name__)
app.secret_key = 'cdcitd34-it-tickets-secret-key'

# Get project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COOKIES_DIR = os.path.join(PROJECT_ROOT, 'cookies')
os.makedirs(COOKIES_DIR, exist_ok=True)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = COOKIES_DIR
app.config['SESSION_FILE_THRESHOLD'] = 500
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=90)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

# Settings storage (will be loaded from database)
SESSION_DURATION = 90  # days
DATABASE_DIR = os.path.join(PROJECT_ROOT, 'database')
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'catch_login'

# Default admin credentials (will be created on first run)
DEFAULT_ADMIN = {
    'username': 'admin',
    'password': 'cdcitd34',
    'role': 'admin'
}


class User(UserMixin):
    def __init__(self, id, username='', role='staff', permissions=None):
        self.id = id
        self.username = username
        self.role = role
        self.permissions = permissions or []


@login_manager.user_loader
def load_user(user_id):
    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        return None
        
    user_data = database.get_user_with_permissions(user_id_int)
    if user_data:
        return User(
            user_data['id'], 
            user_data['username'], 
            user_data['role'],
            user_data.get('permissions', [])
        )
    return None


def require_permission(permission):
    """Decorator to check if user has specific permission"""
    def decorator(f):
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"status": "error", "message": "Authentication required"}), 401
            
            # Admin with '*' has all permissions
            if '*' in current_user.permissions:
                return f(*args, **kwargs)
            
            # Check specific permission
            if permission not in current_user.permissions:
                return jsonify({"status": "error", "message": "Access denied"}), 403
            
            return f(*args, **kwargs)
        wrapped.__name__ = f.__name__
        return wrapped
    return decorator


def hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()


def init_default_user():
    """Create default admin user if not exists"""
    user = database.get_user_by_username(DEFAULT_ADMIN['username'])
    if not user:
        user_id = database.create_user(
            DEFAULT_ADMIN['username'],
            hash_password(DEFAULT_ADMIN['password']),
            DEFAULT_ADMIN['role']
        )
        # Add admin permissions (all permissions)
        database.set_user_permissions(user_id, ['*'])
        print(f"Created default user: {DEFAULT_ADMIN['username']}")


# ============================================
# Authentication Routes
# ============================================

@app.route('/login', methods=['POST'])
def login():
    """Handle login - traditional form POST"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    next_page = request.form.get('next', '/dashboard.html')
    
    if not username or not password:
        return redirect('/login.html?error=1')
    
    user_data = database.get_user_by_username(username)
    
    if user_data and user_data['password_hash'] == hash_password(password):
        user = User(user_data['id'], user_data['username'], user_data['role'])
        session.permanent = True
        login_user(user, remember=True, duration=timedelta(days=SESSION_DURATION))
        database.update_last_login(user_data['id'])
        database.add_log(user_data['id'], 'login', f'User logged in')
        return redirect(next_page)
    
    return redirect('/login.html?error=1')


@app.route('/login', methods=['GET'])
def login_get():
    """Handle login redirect from Flask-Login - serve login page directly"""
    if current_user.is_authenticated:
        return redirect('/dashboard.html')
    next_page = request.args.get('next', '/dashboard.html')
    error = request.args.get('error', '')
    with open(os.path.join(PROJECT_ROOT, 'frontend', 'login.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    html = html.replace('__NEXT_URL__', next_page)
    html = html.replace('__ERROR__', '1' if error else '0')
    html = html.replace('__ERROR_DISPLAY__', 'block' if error else 'none')
    return make_response(html, 200)


@app.route('/login')
@app.route('/login.html')
def catch_login():
    """Serve login page"""
    if current_user.is_authenticated:
        return redirect('/dashboard.html')
    next_page = request.args.get('next', '/dashboard.html')
    error = request.args.get('error', '')
    with open(os.path.join(PROJECT_ROOT, 'frontend', 'login.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    html = html.replace('__NEXT_URL__', next_page)
    html = html.replace('__ERROR__', '1' if error else '0')
    html = html.replace('__ERROR_DISPLAY__', 'block' if error else 'none')
    return make_response(html, 200)


@app.route('/logout')
@login_required
def logout():
    """Handle logout"""
    database.add_log(current_user.id, 'logout', f'User logged out')
    logout_user()
    return redirect('/login.html')


# ============================================
# Protected Page Routes
# ============================================

@app.route('/')
def index():
    """Redirect to dashboard or login"""
    if current_user.is_authenticated:
        return redirect('/dashboard.html')
    return redirect('/login.html')


@app.route('/dashboard.html')
@login_required
def dashboard():
    return send_from_directory('../frontend', 'dashboard.html')



@app.route('/mobile.html')
@login_required
def mobile():
    return send_from_directory('../frontend', 'mobile.html')


@app.route('/BarChart.html')
@login_required
def barchart():
    return send_from_directory('../frontend', 'BarChart.html')


@app.route('/adminsettings.html')
@login_required
def adminsettings():
    return send_from_directory('../frontend', 'adminsettings.html')


# ============================================
# Data File Routes
# ============================================

@app.route('/database/<path:filename>')
@login_required
def serve_database(filename):
    """Serve database files"""
    return send_from_directory(DATABASE_DIR, filename)


# ============================================
# Scan Routes
# ============================================

@app.route('/run-scan')
@login_required
def run_scan():
    """Run quick scan"""
    try:
        result = subprocess.run(
            ['python', 'backend/test.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        subprocess.run(
            ['python', 'backend/create_tickets.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        database.sync_tickets_from_json()
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        tickets = []
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        return jsonify({
            "status": "success",
            "message": "Scan completed",
            "output": result.stdout[-500:] if result.stdout else "",
            "data": tickets
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/run-scan-all')
@login_required
def run_scan_all():
    """Run full scan"""
    try:
        result = subprocess.run(
            ['python', 'backend/test_all.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        subprocess.run(
            ['python', 'backend/create_tickets.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        database.sync_tickets_from_json()
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        tickets = []
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        return jsonify({
            "status": "success",
            "message": "Full scan completed",
            "output": result.stdout[-500:] if result.stdout else "",
            "data": tickets
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/auto-scan', methods=['POST'])
@login_required
def toggle_auto_scan():
    """Toggle auto-scan on/off"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        database.set_setting('auto_scan_enabled', 'true' if enabled else 'false')
        return jsonify({
            "status": "success",
            "enabled": enabled,
            "message": "Auto-scan enabled" if enabled else "Auto-scan disabled"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/auto-scan-status', methods=['GET'])
@login_required
def get_auto_scan_status():
    """Get auto-scan status"""
    try:
        enabled = database.get_setting('auto_scan_enabled', 'false') == 'true'
        return jsonify({
            "status": "success",
            "enabled": enabled
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/auto-scan/one', methods=['POST'])
@login_required
def scan_one_email():
    """Poll and process ONE new unread email from Outlook"""
    try:
        result = subprocess.run(
            ['python', 'backend/outlook_one.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout.strip()
        
        if output == "NO_NEW_EMAIL":
            return jsonify({
                "status": "success",
                "new_email": False,
                "message": "No new unread emails"
            })
        
        if output.startswith("ERROR"):
            return jsonify({
                "status": "error",
                "message": output
            })
        
        # Parse the JSON output
        import json as json_module
        try:
            data = json_module.loads(output.replace("NEW_EMAIL_FOUND\n", "", 1))
        except:
            # Try to find JSON in output
            import re
            match = re.search(r'\{.*\}', output, re.DOTALL)
            if match:
                data = json_module.loads(match.group())
            else:
                return jsonify({"status": "error", "message": "Failed to parse email data"})
        
        if 'ticket' in data:
            ticket_data = data['ticket']
            
            # Add to ticket.json
            ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
            try:
                with open(ticket_path, 'r', encoding='utf-8') as f:
                    tickets = json_module.load(f)
            except:
                tickets = []
            
            # Check if ticket already exists
            ticket_num = ticket_data.get('ticket_number', '')
            exists = any(t.get('ticket_number') == ticket_num for t in tickets)
            
            if not exists:
                new_ticket = {
                    "ticket_number": ticket_data.get('ticket_number', ''),
                    "shop": ticket_data.get('shop', ''),
                    "description": ticket_data.get('description', ''),
                    "username": ticket_data.get('username', ''),
                    "phone": ticket_data.get('phone', ''),
                    "date": ticket_data.get('date', ''),
                    "ip": ticket_data.get('ip', ''),
                    "address": ticket_data.get('address', ''),
                    "problem": ticket_data.get('problem', ''),
                    "resolve_time": "",
                    "ph_rm_os": "",
                    "solution": "",
                    "fu_action": "",
                    "handled_by": "USE_MISSING",
                    "assigned_to": "",
                    "status": "in progress"
                }
                tickets.insert(0, new_ticket)
                
                with open(ticket_path, 'w', encoding='utf-8') as f:
                    json_module.dump(tickets, f, ensure_ascii=False, indent=2)
                
                return jsonify({
                    "status": "success",
                    "new_email": True,
                    "ticket": new_ticket,
                    "message": f"New ticket added: {ticket_num}"
                })
            else:
                return jsonify({
                    "status": "success",
                    "new_email": False,
                    "message": f"Ticket {ticket_num} already exists"
                })
        
        return jsonify({
            "status": "success",
            "new_email": False,
            "message": "No ticket data found in email"
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/sync-db', methods=['POST'])
@login_required
def sync_database():
    """Smart sync tickets from JSON to SQLite"""
    try:
        result = database.sync_tickets_from_json()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/sync-from-db', methods=['POST'])
@login_required
def sync_from_database():
    """Sync tickets from SQLite to JSON"""
    try:
        result = database.sync_tickets_to_json()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/column-widths', methods=['GET'])
@login_required
def get_column_widths():
    """Get user's column widths"""
    try:
        widths_json = database.get_setting(f'column_widths_{current_user.id}', '{}')
        import json
        widths = json.loads(widths_json) if widths_json else {}
        return jsonify({"status": "success", "widths": widths})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/column-widths', methods=['POST'])
@login_required
def save_column_widths():
    """Save user's column widths"""
    try:
        data = request.get_json()
        widths = data.get('widths', {})
        import json
        database.set_setting(f'column_widths_{current_user.id}', json.dumps(widths))
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
# ============================================
# Ticket API Routes
# ============================================

@app.route('/update-ticket', methods=['POST'])
@login_required
def update_ticket():
    """Update a ticket"""
    try:
        updated_ticket = request.get_json()
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        ticket_id = updated_ticket.get('id') or updated_ticket.get('ticket_number')
        for i, ticket in enumerate(tickets):
            ticket_key = ticket.get('id') or ticket.get('ticket_number')
            if ticket_key == ticket_id:
                if 'solution' in updated_ticket:
                    tickets[i]['solution'] = updated_ticket['solution']
                if 'resolve_time' in updated_ticket:
                    tickets[i]['resolve_time'] = updated_ticket['resolve_time']
                if 'ph_rm_os' in updated_ticket:
                    tickets[i]['ph_rm_os'] = updated_ticket['ph_rm_os']
                if 'fu_action' in updated_ticket:
                    tickets[i]['fu_action'] = updated_ticket['fu_action']
                if 'problem' in updated_ticket:
                    tickets[i]['problem'] = updated_ticket['problem']
                if 'handled_by' in updated_ticket:
                    tickets[i]['handled_by'] = updated_ticket['handled_by']
                if 'assigned_to' in updated_ticket:
                    tickets[i]['assigned_to'] = updated_ticket['assigned_to']
                if 'username' in updated_ticket:
                    tickets[i]['username'] = updated_ticket['username']
                if 'phone' in updated_ticket:
                    tickets[i]['phone'] = updated_ticket['phone']
                if 'status' in updated_ticket:
                    tickets[i]['status'] = updated_ticket['status']
                if 'ticket_number' in updated_ticket:
                    tickets[i]['ticket_number'] = updated_ticket['ticket_number']
                break
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/bulk-update-status', methods=['POST'])
@login_required
def bulk_update_status():
    """Bulk update status for multiple tickets"""
    try:
        data = request.get_json()
        tickets_to_update = data.get('tickets', [])
        new_status = data.get('status', 'in progress')
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        ticket_nums_to_update = {t.get('ticket_number') for t in tickets_to_update}
        
        for ticket in tickets:
            if ticket.get('ticket_number') in ticket_nums_to_update:
                ticket['status'] = new_status
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/delete-tickets', methods=['POST'])
@login_required
def delete_tickets():
    """Delete multiple tickets"""
    try:
        data = request.get_json()
        tickets_to_delete = data.get('tickets', [])
        delete_numbers = [t.get('ticket_number') for t in tickets_to_delete]
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        tickets = [t for t in tickets if t.get('ticket_number') not in delete_numbers]
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/bulk-delete', methods=['POST'])
@login_required
def api_bulk_delete():
    """Delete multiple tickets by ticket numbers"""
    try:
        data = request.get_json()
        ticket_numbers = data.get('ticket_numbers', [])
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        original_count = len(tickets)
        tickets = [t for t in tickets if t.get('ticket_number') not in ticket_numbers]
        deleted_count = original_count - len(tickets)
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success", "deleted": deleted_count})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/bulk-status', methods=['POST'])
@login_required
def api_bulk_status():
    """Bulk update status for multiple tickets"""
    try:
        data = request.get_json()
        ticket_numbers = data.get('ticket_numbers', [])
        new_status = data.get('status', 'in progress')
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        updated_count = 0
        for ticket in tickets:
            if ticket.get('ticket_number') in ticket_numbers:
                ticket['status'] = new_status
                updated_count += 1
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success", "updated": updated_count})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/add-ticket', methods=['POST'])
@login_required
def add_ticket():
    """Add a new ticket"""
    try:
        new_ticket = request.get_json()
        
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        
        # Keep ticket_number as null if empty
        if new_ticket.get('ticket_number') in ['', None]:
            new_ticket['ticket_number'] = None
        
        # Ensure required fields have defaults
        new_ticket.setdefault('problem', '')
        new_ticket.setdefault('resolve_time', '')
        new_ticket.setdefault('ph_rm_os', '')
        new_ticket.setdefault('solution', '')
        new_ticket.setdefault('fu_action', '')
        new_ticket.setdefault('handled_by', '')
        new_ticket.setdefault('status', 'in progress')
        
        # Add new ticket
        tickets.append(new_ticket)
        
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump(tickets, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success", "ticket": new_ticket})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ============================================
# Filter API Routes
# ============================================

@app.route('/api/filters', methods=['GET'])
@login_required
def get_filters():
    """Get all filters"""
    filters_path = os.path.join(DATABASE_DIR, "email_filters.json")
    try:
        with open(filters_path, 'r', encoding='utf-8') as f:
            filters = json.load(f)
        return jsonify(filters)
    except:
        return jsonify([])


@app.route('/api/filters', methods=['POST'])
@login_required
def add_filter():
    """Add a new filter"""
    data = request.get_json()
    filters_path = os.path.join(DATABASE_DIR, "email_filters.json")
    
    with open(filters_path, 'r', encoding='utf-8') as f:
        filters = json.load(f)
    
    new_id = max([f.get('id', 0) for f in filters], default=0) + 1
    new_filter = {
        "id": new_id,
        "name": data.get('name', ''),
        "from_email": data.get('from_email', ''),
        "subject_filter": data.get('subject_filter', ''),
        "body_filter": data.get('body_filter', ''),
        "to_email": data.get('to_email', ''),
        "action": data.get('action', ''),
        "description": data.get('description', ''),
        "enabled": data.get('enabled', True),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    }
    filters.append(new_filter)
    
    with open(filters_path, 'w', encoding='utf-8') as f:
        json.dump(filters, f, indent=2, ensure_ascii=False)
    
    return jsonify({"status": "success", "filter": new_filter})


@app.route('/api/filters/<int:filter_id>', methods=['PUT'])
@login_required
def update_filter(filter_id):
    """Update a filter"""
    data = request.get_json()
    filters_path = os.path.join(DATABASE_DIR, "email_filters.json")
    
    with open(filters_path, 'r', encoding='utf-8') as f:
        filters = json.load(f)
    
    updated = False
    for f in filters:
        if f.get('id') == filter_id:
            for key in ['name', 'from_email', 'subject_filter', 'body_filter', 'to_email', 'action', 'description', 'enabled']:
                if key in data:
                    f[key] = data[key]
            updated = True
            break
    
    if updated:
        with open(filters_path, 'w', encoding='utf-8') as f:
            json.dump(filters, f, indent=2, ensure_ascii=False)
    
    return jsonify({"status": "success" if updated else "error"})


@app.route('/api/filters/<int:filter_id>', methods=['DELETE'])
@login_required
def delete_filter(filter_id):
    """Delete a filter"""
    filters_path = os.path.join(DATABASE_DIR, "email_filters.json")
    
    with open(filters_path, 'r', encoding='utf-8') as f:
        filters = json.load(f)
    
    filters = [f for f in filters if f.get('id') != filter_id]
    
    with open(filters_path, 'w', encoding='utf-8') as f:
        json.dump(filters, f, indent=2, ensure_ascii=False)
    
    return jsonify({"status": "success"})


# ============================================
# Scan API Routes
# ============================================

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """Trigger scan via API"""
    data = request.get_json() or {}
    full_scan = data.get('full', False)
    
    try:
        script = 'backend/test_all.py' if full_scan else 'backend/test.py'
        result = subprocess.run(
            ['python', script],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        # Also run create_tickets.py to process emails
        subprocess.run(
            ['python', 'backend/create_tickets.py'],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        database.set_setting('last_scan', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        return jsonify({
            "status": "success",
            "message": "Scan completed successfully",
            "last_scan": database.get_setting('last_scan')
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ============================================
# Stats & Settings Routes
# ============================================

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """Get ticket statistics"""
    return jsonify(database.get_stats())


@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    """Get settings"""
    settings = database.get_all_settings()
    defaults = {
        "auto_refresh": "false",
        "refresh_interval": "60",
        "default_status": "in progress",
        "default_handler": "USE_MISSING",
        "last_scan": "",
        "auto_refresh_after_scan": "false",
        "delete_after_scan": "false"
    }
    for key, value in defaults.items():
        if key not in settings:
            settings[key] = value
    return jsonify(settings)


@app.route('/api/settings', methods=['POST'])
@login_required
def update_settings():
    """Update settings"""
    data = request.get_json()
    if data:
        for key, value in data.items():
            database.set_setting(key, str(value))
    return jsonify({"status": "success"})


# ============================================
# Backup & Clear Routes
# ============================================

@app.route('/api/backup', methods=['POST'])
@login_required
def backup():
    """Create backup of data"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(PROJECT_ROOT, 'backup', timestamp)
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup ticket.json
        ticket_src = os.path.join(DATABASE_DIR, "ticket.json")
        ticket_dst = os.path.join(backup_dir, "ticket.json")
        if os.path.exists(ticket_src):
            shutil.copy2(ticket_src, ticket_dst)
        
        # Backup outlook_emails.json
        email_src = os.path.join(DATABASE_DIR, "outlook_emails.json")
        email_dst = os.path.join(backup_dir, "outlook_emails.json")
        if os.path.exists(email_src):
            shutil.copy2(email_src, email_dst)
        
        return jsonify({"status": "success", "message": f"Backup created: {timestamp}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/clear-tickets', methods=['POST'])
@login_required
def clear_tickets():
    """Clear all tickets"""
    try:
        ticket_path = os.path.join(DATABASE_DIR, "ticket.json")
        with open(ticket_path, 'w', encoding='utf-8') as f:
            json.dump([], f)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/clear-emails', methods=['POST'])
@login_required
def clear_emails():
    """Clear all emails"""
    try:
        email_path = os.path.join(DATABASE_DIR, "outlook_emails.json")
        with open(email_path, 'w', encoding='utf-8') as f:
            json.dump([], f)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ============================================
# Site API Routes
# ============================================
@app.route('/api/sites', methods=['GET'])
@login_required
def get_sites():
    """Get all sites"""
    site_path = os.path.join(DATABASE_DIR, "site.json")
    try:
        if not os.path.exists(site_path):
            return jsonify([])
        with open(site_path, 'r', encoding='utf-8') as f:
            sites = json.load(f)
        return jsonify(sites)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/sites', methods=['POST'])
@login_required
def save_sites():
    """Save the updated sites list to site.json"""
    try:
        sites_data = request.get_json()
        if not isinstance(sites_data, list):
            return jsonify({"status": "error", "message": "Data must be a list"}), 400
        site_path = os.path.join(DATABASE_DIR, "site.json")
        with open(site_path, 'w', encoding='utf-8') as f:
            json.dump(sites_data, f, indent=2, ensure_ascii=False)
        return jsonify({"status": "success", "message": "Sites updated successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/sites/<shop_code>', methods=['PUT'])
@login_required
def update_site(shop_code):
    """Update an existing site"""
    try:
        updated_data = request.get_json()
        site_path = os.path.join(DATABASE_DIR, "site.json")
        
        if not os.path.exists(site_path):
             return jsonify({"status": "error", "message": "Site database not found"}), 404

        with open(site_path, 'r', encoding='utf-8') as f:
            sites = json.load(f)
            
        updated = False
        for i, site in enumerate(sites):
            if site.get('shop_code') == shop_code:
                if 'address' in updated_data:
                    sites[i]['address'] = updated_data['address']
                if 'ip' in updated_data:
                    sites[i]['ip'] = updated_data['ip']
                updated = True
                break
                
        if updated:
            with open(site_path, 'w', encoding='utf-8') as f:
                json.dump(sites, f, indent=2, ensure_ascii=False)
            return jsonify({"status": "success"})
        else:
             return jsonify({"status": "error", "message": "Site not found"}), 404

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/sites/<shop_code>', methods=['DELETE'])
@login_required
def delete_site(shop_code):
    """Delete a site"""
    try:
        site_path = os.path.join(DATABASE_DIR, "site.json")
        
        if not os.path.exists(site_path):
             return jsonify({"status": "error", "message": "Site database not found"}), 404

        with open(site_path, 'r', encoding='utf-8') as f:
            sites = json.load(f)
            
        initial_length = len(sites)
        sites = [s for s in sites if s.get('shop_code') != shop_code]
        
        if len(sites) < initial_length:
            with open(site_path, 'w', encoding='utf-8') as f:
                json.dump(sites, f, indent=2, ensure_ascii=False)
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Site not found"}), 404
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================
# User Management Routes
# ============================================

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (admin only)"""
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    users = database.get_all_users_with_permissions()
    return jsonify(users)


@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    """Create new user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'staff')
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400
    
    try:
        user_id = database.create_user(username, hash_password(password), role)
        # Add default permissions based on role
        database.add_default_permissions(user_id, role)
        database.add_log(current_user.id, 'create_user', f'Created user: {username}')
        return jsonify({"status": "success", "id": user_id})
    except Exception as e:
        if 'UNIQUE constraint' in str(e):
            return jsonify({"status": "error", "message": "Username already exists"}), 400
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    data = request.get_json()
    username = data.get('username', '').strip() if data.get('username') else None
    password = data.get('password', '').strip() if data.get('password') else None
    role = data.get('role', '').strip() if data.get('role') else None
    
    try:
        password_hash = hash_password(password) if password else None
        database.update_user(user_id, username=username, password_hash=password_hash, role=role)
        
        # If permissions are provided, update them
        if 'permissions' in data:
            database.set_user_permissions(user_id, data['permissions'])
        
        database.add_log(current_user.id, 'update_user', f'Updated user ID: {user_id}')
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    if user_id == current_user.id:
        return jsonify({"status": "error", "message": "Cannot delete yourself"}), 400
    
    try:
        database.delete_user(user_id)
        database.add_log(current_user.id, 'delete_user', f'Deleted user ID: {user_id}')
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/permissions', methods=['GET'])
@login_required
def get_permissions():
    """Get all available permissions"""
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    return jsonify(database.get_all_permissions_list())


@app.route('/api/my-permissions', methods=['GET'])
@login_required
def get_my_permissions():
    """Get current user's permissions"""
    return jsonify({
        "role": current_user.role,
        "permissions": current_user.permissions
    })


# ============================================
# Main Entry Point
# ====================================

if __name__ == "__main__":
    # Initialize database
    print("Initializing database...")
    database.init_database()
    init_default_user()
    
    # Auto-migrate from JSON if exists
    json_dir = os.path.join(PROJECT_ROOT, 'database')
    if os.path.exists(os.path.join(json_dir, 'ticket.json')):
        print("Migrating data from JSON to SQLite...")
        database.migrate_from_json()
    
    print("=" * 50)
    print("IT Ticket System - Flask Server")
    print("=" * 50)
    print(f"Starting server at http://localhost:8000")
    print(f"Default login: admin / cdcitd34")
    print(f"Session duration: {SESSION_DURATION} days")
    print("=" * 50)
    print("\nRoutes:")
    print("  /login.html    - Login page")
    print("  /dashboard.html - Main dashboard")
    print("  /mobile.html   - Mobile view")
    print("  /BarChart.html - Statistics")
    print("  /adminsettings.html - Settings")
    print("\nAPI Endpoints:")
    print("  /run-scan      - Quick scan")
    print("  /run-scan-all  - Full scan")
    print("  /update-ticket - Update ticket")
    print("  /api/*         - Various API endpoints")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=8000, debug=False)
