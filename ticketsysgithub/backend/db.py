import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(PROJECT_ROOT, 'database', 'tickets.db')

# Permission templates
PERMISSION_TEMPLATES = {
    'admin': ['*'],  # All permissions
    'staff': ['dashboard', 'tickets_view', 'tickets_create', 'emails_view']
}

# All available permissions
ALL_PERMISSIONS = [
    {'id': 'dashboard', 'name': 'Dashboard', 'description': 'View dashboard'},
    {'id': 'tickets_view', 'name': 'View Tickets', 'description': 'View ticket list'},
    {'id': 'tickets_create', 'name': 'Create Tickets', 'description': 'Create new tickets'},
    {'id': 'tickets_edit', 'name': 'Edit Tickets', 'description': 'Edit ticket details'},
    {'id': 'tickets_delete', 'name': 'Delete Tickets', 'description': 'Delete tickets'},
    {'id': 'tickets_bulk', 'name': 'Bulk Update', 'description': 'Bulk update ticket status'},
    {'id': 'emails_view', 'name': 'View Emails', 'description': 'View email list'},
    {'id': 'filters_manage', 'name': 'Manage Filters', 'description': 'Manage email filters'},
    {'id': 'sites_manage', 'name': 'Manage Sites', 'description': 'Manage site list'},
    {'id': 'users_manage', 'name': 'Manage Users', 'description': 'Manage user accounts'},
    {'id': 'settings_access', 'name': 'Access Settings', 'description': 'Access settings page'},
    {'id': 'scan_run', 'name': 'Run Scans', 'description': 'Run email scan'}
]

@contextmanager
def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_database():
    """Initialize database tables"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'staff',
                permissions TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Tickets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_number TEXT UNIQUE,
                shop TEXT,
                description TEXT,
                username TEXT,
                phone TEXT,
                date TEXT,
                ip TEXT,
                address TEXT,
                problem TEXT,
                resolve_time TEXT,
                ph_rm_os TEXT,
                solution TEXT,
                fu_action TEXT,
                handled_by TEXT,
                assigned_to TEXT,
                status TEXT DEFAULT 'in progress',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # Emails table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                date TEXT,
                subject TEXT,
                body TEXT,
                recipients TEXT,
                filter_actions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Sites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shop_code TEXT UNIQUE,
                ip TEXT,
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # Filters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                from_email TEXT,
                subject_filter TEXT,
                body_filter TEXT,
                to_email TEXT,
                action TEXT,
                description TEXT,
                enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Logs table for audit
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        
        # Add permissions column if it doesn't exist (for database migration)
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT "[]"')
            conn.commit()
            print("Added permissions column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        print("Database tables created successfully!")

# ============== User Functions ==============

def create_user(username, password_hash, role='staff'):
    """Create a new user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )
        user_id = cursor.lastrowid
        add_default_permissions(user_id, role)
        return user_id

def get_user_by_username(username):
    """Get user by username"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id):
    """Get user by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, created_at, last_login FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_all_users():
    """Get all users"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, created_at, last_login FROM users ORDER BY username')
        return [dict(row) for row in cursor.fetchall()]

def update_user(user_id, username=None, password_hash=None, role=None):
    """Update user"""
    with get_db() as conn:
        cursor = conn.cursor()
        if username:
            cursor.execute('UPDATE users SET username = ? WHERE id = ?', (username, user_id))
        if password_hash:
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        if role:
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))

def delete_user(user_id):
    """Delete user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

def get_user_permissions(user_id):
    """Get user permissions"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT permissions FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if not row:
            return []
        perms = json.loads(row['permissions'] or '[]')
        # If admin with '*', return all permissions
        if '*' in perms:
            return [p['id'] for p in ALL_PERMISSIONS]
        return perms

def set_user_permissions(user_id, permissions):
    """Set user permissions"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET permissions = ? WHERE id = ?', 
                      (json.dumps(permissions), user_id))

def get_user_with_permissions(user_id):
    """Get user with permissions"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, permissions, created_at, last_login FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        user = dict(row)
        perms = json.loads(user.get('permissions') or '[]')
        if '*' in perms:
            user['permissions'] = [p['id'] for p in ALL_PERMISSIONS]
        else:
            user['permissions'] = perms
        return user

def get_all_users_with_permissions():
    """Get all users with permissions"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, permissions, created_at, last_login FROM users ORDER BY username')
        users = []
        for row in cursor.fetchall():
            user = dict(row)
            perms = json.loads(user.get('permissions') or '[]')
            if '*' in perms:
                user['permissions'] = [p['id'] for p in ALL_PERMISSIONS]
            else:
                user['permissions'] = perms
            users.append(user)
        return users

def has_permission(user_id, permission):
    """Check if user has specific permission"""
    perms = get_user_permissions(user_id)
    return permission in perms

def add_default_permissions(user_id, role='staff'):
    """Add default permissions based on role"""
    if role in PERMISSION_TEMPLATES:
        set_user_permissions(user_id, PERMISSION_TEMPLATES[role])
    else:
        set_user_permissions(user_id, PERMISSION_TEMPLATES['staff'])

def get_all_permissions_list():
    """Get all available permissions"""
    return ALL_PERMISSIONS

def update_last_login(user_id):
    """Update last login time"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))

# ============== Ticket Functions ==============

def get_all_tickets():
    """Get all tickets"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tickets ORDER BY date DESC')
        return [dict(row) for row in cursor.fetchall()]

def get_ticket_by_number(ticket_number):
    """Get ticket by number"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tickets WHERE ticket_number = ?', (ticket_number,))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_ticket(ticket_number, **kwargs):
    """Update ticket"""
    allowed_fields = ['problem', 'resolve_time', 'ph_rm_os', 'solution', 'fu_action', 
                     'handled_by', 'assigned_to', 'status', 'ticket_number']
    fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not fields:
        return
    
    fields['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with get_db() as conn:
        cursor = conn.cursor()
        set_clause = ', '.join([f'{k} = ?' for k in fields.keys()])
        values = list(fields.values()) + [ticket_number]
        cursor.execute(f'UPDATE tickets SET {set_clause} WHERE ticket_number = ?', values)

def bulk_update_status(ticket_numbers, new_status):
    """Bulk update ticket status"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE ticket_number IN (%s)' 
            % ','.join('?' * len(ticket_numbers)),
            [new_status] + ticket_numbers
        )

def delete_tickets(ticket_numbers):
    """Delete tickets"""
    with get_db() as conn:
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(ticket_numbers))
        cursor.execute(f'DELETE FROM tickets WHERE ticket_number IN ({placeholders})', ticket_numbers)

def add_ticket(ticket_data):
    """Add new ticket"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO tickets (ticket_number, shop, description, username, phone, date, ip, address, 
                               problem, resolve_time, ph_rm_os, solution, fu_action, handled_by, assigned_to, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ticket_data.get('ticket_number'), ticket_data.get('shop'), ticket_data.get('description'),
            ticket_data.get('username'), ticket_data.get('phone'), ticket_data.get('date'),
            ticket_data.get('ip'), ticket_data.get('address'), ticket_data.get('problem'),
            ticket_data.get('resolve_time'), ticket_data.get('ph_rm_os'), ticket_data.get('solution'),
            ticket_data.get('fu_action'), ticket_data.get('handled_by'), ticket_data.get('assigned_to'),
            ticket_data.get('status', 'in progress')
        ))
        return cursor.lastrowid

# ============== Email Functions ==============

def get_all_emails():
    """Get all emails"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM emails ORDER BY date DESC')
        return [dict(row) for row in cursor.fetchall()]

def add_email(email_data):
    """Add new email"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO emails (sender, date, subject, body, recipients, filter_actions)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            email_data.get('sender'), email_data.get('date'), email_data.get('subject'),
            email_data.get('body'), json.dumps(email_data.get('recipients', [])),
            json.dumps(email_data.get('filter_actions', []))
        ))
        return cursor.lastrowid

def clear_emails():
    """Clear all emails"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM emails')

# ============== Site Functions ==============

def get_all_sites():
    """Get all sites"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sites ORDER BY shop_code')
        return [dict(row) for row in cursor.fetchall()]

def save_sites(sites_list):
    """Save all sites (replace)"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sites')
        for site in sites_list:
            cursor.execute('''
                INSERT INTO sites (shop_code, ip, address)
                VALUES (?, ?, ?)
            ''', (site.get('shop_code'), site.get('ip'), site.get('address')))

def add_site(site_data):
    """Add new site"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sites (shop_code, ip, address)
            VALUES (?, ?, ?)
        ''', (site_data.get('shop_code'), site_data.get('ip'), site_data.get('address')))
        return cursor.lastrowid

# ============== Filter Functions ==============

def get_all_filters():
    """Get all filters"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filters ORDER BY name')
        return [dict(row) for row in cursor.fetchall()]

def add_filter(filter_data):
    """Add new filter"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO filters (name, from_email, subject_filter, body_filter, to_email, action, description, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filter_data.get('name'), filter_data.get('from_email'), filter_data.get('subject_filter'),
            filter_data.get('body_filter'), filter_data.get('to_email'), filter_data.get('action'),
            filter_data.get('description'), filter_data.get('enabled', True)
        ))
        return cursor.lastrowid

def update_filter(filter_id, filter_data):
    """Update filter"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE filters SET name=?, from_email=?, subject_filter=?, body_filter=?, 
                           to_email=?, action=?, description=?, enabled=?
            WHERE id=?
        ''', (
            filter_data.get('name'), filter_data.get('from_email'), filter_data.get('subject_filter'),
            filter_data.get('body_filter'), filter_data.get('to_email'), filter_data.get('action'),
            filter_data.get('description'), filter_data.get('enabled', True), filter_id
        ))

def delete_filter(filter_id):
    """Delete filter"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM filters WHERE id = ?', (filter_id,))

# ============== Settings Functions ==============

def get_setting(key, default=None):
    """Get setting value"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row['value'] if row else default

def set_setting(key, value):
    """Set setting value"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?
        ''', (key, value, value))

def get_all_settings():
    """Get all settings"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM settings')
        return {row['key']: row['value'] for row in cursor.fetchall()}

# ============== Stats Functions ==============

def get_stats():
    """Get system statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM tickets')
        ticket_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tickets WHERE status = ?', ('completed',))
        completed = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tickets WHERE status = ?', ('in progress',))
        in_progress = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM emails')
        email_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM sites WHERE shop_code LIKE 'CDC%'")
        cdc_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM sites WHERE shop_code LIKE 'IK%'")
        ik_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM sites WHERE shop_code LIKE 'FW%'")
        fw_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM sites WHERE shop_code LIKE 'MX%'")
        mx_count = cursor.fetchone()['count']
        
        return {
            'total_tickets': ticket_count,
            'completed': completed,
            'in_progress': in_progress,
            'total_emails': email_count,
            'cdc_count': cdc_count,
            'ik_count': ik_count,
            'fw_count': fw_count,
            'mx_count': mx_count,
            'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# ============== Log Functions ==============

def add_log(user_id, action, details=''):
    """Add audit log"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
                      (user_id, action, details))

# ============== Migration Functions ==============

def migrate_from_json():
    """Migrate data from JSON files to SQLite"""
    json_dir = os.path.join(PROJECT_ROOT, 'database')
    
    # Migrate tickets
    ticket_path = os.path.join(json_dir, 'ticket.json')
    if os.path.exists(ticket_path):
        with open(ticket_path, 'r', encoding='utf-8') as f:
            tickets = json.load(f)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM tickets')
            for t in tickets:
                cursor.execute('''
                    INSERT OR REPLACE INTO tickets (ticket_number, shop, description, username, phone, date, ip, address,
                        problem, resolve_time, ph_rm_os, solution, fu_action, handled_by, assigned_to, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (t.get('ticket_number'), t.get('shop'), t.get('description'), t.get('username'),
                      t.get('phone'), t.get('date'), t.get('ip'), t.get('address'), t.get('problem'),
                      t.get('resolve_time'), t.get('ph_rm_os'), t.get('solution'), t.get('fu_action'),
                      t.get('handled_by'), t.get('assigned_to'), t.get('status', 'in progress')))
        print(f"Migrated {len(tickets)} tickets")
    
    # Migrate emails
    email_path = os.path.join(json_dir, 'outlook_emails.json')
    if os.path.exists(email_path):
        with open(email_path, 'r', encoding='utf-8') as f:
            emails = json.load(f)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM emails')
            for e in emails:
                cursor.execute('''
                    INSERT INTO emails (sender, date, subject, body, recipients, filter_actions)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (e.get('sender'), e.get('date'), e.get('subject'), e.get('body'),
                      json.dumps(e.get('recipients', [])), json.dumps(e.get('filter_actions', []))))
        print(f"Migrated {len(emails)} emails")
    
    # Migrate sites
    site_path = os.path.join(json_dir, 'site.json')
    if os.path.exists(site_path):
        with open(site_path, 'r', encoding='utf-8') as f:
            sites = json.load(f)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sites')
            for s in sites:
                cursor.execute('''
                    INSERT OR REPLACE INTO sites (shop_code, ip, address)
                    VALUES (?, ?, ?)
                ''', (s.get('shop_code'), s.get('ip'), s.get('address')))
        print(f"Migrated {len(sites)} sites")
    
    # Migrate filters
    filter_path = os.path.join(json_dir, 'email_filters.json')
    if os.path.exists(filter_path):
        with open(filter_path, 'r', encoding='utf-8') as f:
            filters = json.load(f)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM filters')
            for f in filters:
                cursor.execute('''
                    INSERT INTO filters (name, from_email, subject_filter, body_filter, to_email, action, description, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (f.get('name'), f.get('from_email'), f.get('subject_filter'), f.get('body_filter'),
                      f.get('to_email'), f.get('action'), f.get('description'), f.get('enabled', True)))
        print(f"Migrated {len(filters)} filters")
    
    print("Migration complete!")

def sync_tickets_from_json():
    """Smart sync tickets from JSON to SQLite - INSERT new, UPDATE existing"""
    import json
    
    json_path = os.path.join(PROJECT_ROOT, 'database', 'ticket.json')
    
    if not os.path.exists(json_path):
        return {"status": "error", "message": "ticket.json not found"}
    
    with open(json_path, 'r', encoding='utf-8') as f:
        json_tickets = json.load(f)
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT ticket_number FROM tickets')
        existing = set(row[0] for row in cursor.fetchall() if row[0])
        
        inserted = 0
        updated = 0
        
        for t in json_tickets:
            ticket_num = t.get('ticket_number')
            if not ticket_num:
                continue
            
            if ticket_num in existing:
                cursor.execute('''
                    UPDATE tickets SET
                        shop = ?, description = ?, username = ?, phone = ?,
                        date = ?, ip = ?, address = ?, problem = ?,
                        resolve_time = ?, ph_rm_os = ?, solution = ?,
                        fu_action = ?, handled_by = ?, assigned_to = ?,
                        status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE ticket_number = ?
                ''', (t.get('shop'), t.get('description'), t.get('username'),
                      t.get('phone'), t.get('date'), t.get('ip'), t.get('address'),
                      t.get('problem'), t.get('resolve_time'), t.get('ph_rm_os'),
                      t.get('solution'), t.get('fu_action'), t.get('handled_by'),
                      t.get('assigned_to'), t.get('status', 'in progress'), ticket_num))
                updated += 1
            else:
                cursor.execute('''
                    INSERT INTO tickets (ticket_number, shop, description, username, phone,
                        date, ip, address, problem, resolve_time, ph_rm_os, solution,
                        fu_action, handled_by, assigned_to, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (ticket_num, t.get('shop'), t.get('description'), t.get('username'),
                      t.get('phone'), t.get('date'), t.get('ip'), t.get('address'),
                      t.get('problem'), t.get('resolve_time'), t.get('ph_rm_os'),
                      t.get('solution'), t.get('fu_action'), t.get('handled_by'),
                      t.get('assigned_to'), t.get('status', 'in progress')))
                inserted += 1
    
    return {
        "status": "success",
        "inserted": inserted,
        "updated": updated,
        "total": len(json_tickets)
    }

def sync_tickets_to_json():
    """Sync tickets from SQLite to JSON from SQLite"""
    import json
    
    json_path = os.path.join(PROJECT_ROOT, 'database', 'ticket.json')
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ticket_number, shop, description, username, phone,
                date, ip, address, problem, resolve_time, ph_rm_os, solution,
                fu_action, handled_by, assigned_to, status
            FROM tickets ORDER BY date DESC
        ''')
        columns = [desc[0] for desc in cursor.description]
        tickets = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(tickets, f, ensure_ascii=False, indent=2)
    
    return {
        "status": "success",
        "total": len(tickets),
        "message": f"Exported {len(tickets)} tickets to ticket.json"
    }

if __name__ == '__main__':
    init_database()
