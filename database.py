
import sqlite3
from datetime import datetime, date

DB_NAME = "clinic.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS availability (
        avail_date TEXT PRIMARY KEY,
        is_available INTEGER DEFAULT 1,
        max_tokens INTEGER DEFAULT 25,
        booked_tokens INTEGER DEFAULT 0
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        booking_date TEXT NOT NULL,
        token_number INTEGER,
        status TEXT DEFAULT 'confirmed',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def is_valid_booking_date(booking_date_str):
    try:
        booking_date = datetime.strptime(booking_date_str, "%Y-%m-%d").date()
        today = date.today()
        
        if booking_date < today:
            return False, "Cannot book for past dates"
        
        # Allow booking for today only if time is before 5 PM
        now = datetime.now()
        if booking_date == today and now.hour >= 17:
            return False, "Today's booking window is closed (5 PM - 8 PM)"
            
        return True, ""
    except:
        return False, "Invalid date format"

def get_or_create_availability(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM availability WHERE avail_date = ?", (date_str,))
    row = c.fetchone()
    
    if not row:
        c.execute("""
            INSERT INTO availability (avail_date, is_available, max_tokens, booked_tokens)
            VALUES (?, 1, 25, 0)
        """, (date_str,))
        conn.commit()
        c.execute("SELECT * FROM availability WHERE avail_date = ?", (date_str,))
        row = c.fetchone()
    
    conn.close()
    return dict(row)

def can_book_on_date(date_str):
    avail = get_or_create_availability(date_str)
    return avail['is_available'] == 1 and avail['booked_tokens'] < avail['max_tokens']

def get_next_token(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT booked_tokens FROM availability WHERE avail_date = ?", (date_str,))
    booked = c.fetchone()['booked_tokens']
    
    new_token = booked + 1
    
    c.execute("""
        UPDATE availability 
        SET booked_tokens = booked_tokens + 1 
        WHERE avail_date = ?
    """, (date_str,))
    
    conn.commit()
    conn.close()
    
    return new_token

def create_booking(name, phone, date_str, token):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute("""
            INSERT INTO bookings (patient_name, phone, booking_date, token_number, status)
            VALUES (?, ?, ?, ?, 'confirmed')
        """, (name, phone, date_str, token))
        conn.commit()
        return True, "Booking successful!"
    except sqlite3.IntegrityError:
        return False, "This phone number is already registered for a token."
    finally:
        conn.close()

def get_all_bookings():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM bookings ORDER BY booking_date, token_number")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_bookings_for_date(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM bookings WHERE booking_date = ? AND status = 'confirmed' ORDER BY token_number", (date_str,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def cancel_all_today():
    today = date.today().isoformat()
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("UPDATE availability SET is_available = 0 WHERE avail_date = ?", (today,))
    c.execute("UPDATE bookings SET status = 'cancelled' WHERE booking_date = ? AND status = 'confirmed'", (today,))
    
    conn.commit()
    affected = c.rowcount
    conn.close()
    
    return affected

def disable_date(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        INSERT OR REPLACE INTO availability (avail_date, is_available, max_tokens, booked_tokens)
        VALUES (?, 0, 25, 0)
    """, (date_str,))
    
    conn.commit()

import sqlite3
from datetime import datetime, date

DB_NAME = "clinic.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS availability (
        avail_date TEXT PRIMARY KEY,
        is_available INTEGER DEFAULT 1,
        max_tokens INTEGER DEFAULT 25,
        booked_tokens INTEGER DEFAULT 0
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        booking_date TEXT NOT NULL,
        token_number INTEGER,
        status TEXT DEFAULT 'confirmed',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def is_valid_booking_date(booking_date_str):
    try:
        booking_date = datetime.strptime(booking_date_str, "%Y-%m-%d").date()
        today = date.today()
        
        if booking_date < today:
            return False, "Cannot book for past dates"
        
        # Allow booking for today only if time is before 5 PM
        now = datetime.now()
        if booking_date == today and now.hour >= 17:
            return False, "Today's booking window is closed (5 PM - 8 PM)"
            
        return True, ""
    except:
        return False, "Invalid date format"

def get_or_create_availability(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM availability WHERE avail_date = ?", (date_str,))
    row = c.fetchone()
    
    if not row:
        c.execute("""
            INSERT INTO availability (avail_date, is_available, max_tokens, booked_tokens)
            VALUES (?, 1, 25, 0)
        """, (date_str,))
        conn.commit()
        c.execute("SELECT * FROM availability WHERE avail_date = ?", (date_str,))
        row = c.fetchone()
    
    conn.close()
    return dict(row)

def can_book_on_date(date_str):
    avail = get_or_create_availability(date_str)
    return avail['is_available'] == 1 and avail['booked_tokens'] < avail['max_tokens']

def get_next_token(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT booked_tokens FROM availability WHERE avail_date = ?", (date_str,))
    booked = c.fetchone()['booked_tokens']
    
    new_token = booked + 1
    
    c.execute("""
        UPDATE availability 
        SET booked_tokens = booked_tokens + 1 
        WHERE avail_date = ?
    """, (date_str,))
    
    conn.commit()
    conn.close()
    
    return new_token

def create_booking(name, phone, date_str, token):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute("""
            INSERT INTO bookings (patient_name, phone, booking_date, token_number, status)
            VALUES (?, ?, ?, ?, 'confirmed')
        """, (name, phone, date_str, token))
        conn.commit()
        return True, "Booking successful!"
    except sqlite3.IntegrityError:
        return False, "This phone number is already registered for a token."
    finally:
        conn.close()

def get_all_bookings():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM bookings ORDER BY booking_date, token_number")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_bookings_for_date(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM bookings WHERE booking_date = ? AND status = 'confirmed' ORDER BY token_number", (date_str,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def cancel_all_today():
    today = date.today().isoformat()
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("UPDATE availability SET is_available = 0 WHERE avail_date = ?", (today,))
    c.execute("UPDATE bookings SET status = 'cancelled' WHERE booking_date = ? AND status = 'confirmed'", (today,))
    
    conn.commit()
    affected = c.rowcount
    conn.close()
    
    return affected

def disable_date(date_str):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        INSERT OR REPLACE INTO availability (avail_date, is_available, max_tokens, booked_tokens)
        VALUES (?, 0, 25, 0)
    """, (date_str,))
    
    conn.commit()

    conn.close()