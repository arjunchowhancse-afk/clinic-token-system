
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter

load_dotenv()

from twilio.rest import Client

app = Flask(__name__)
app.secret_key = "super-secret-key-clinic-2025-very-secure-change-this"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(10), nullable=False)
    doctor = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)     # YYYY-MM-DD
    time_slot = db.Column(db.String(20), nullable=False)
    token = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="confirmed")

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


with app.app_context():
    db.create_all()
    if not AdminUser.query.filter_by(username="admin").first():
        hashed = generate_password_hash("lavanys123")
        admin = AdminUser(username="admin", password_hash=hashed)
        db.session.add(admin)
        db.session.commit()
        print("Default admin created → username: admin | password: lavanys123")


TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = "+19143505214"

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def send_sms(phone, name, token, doctor, date_str, time_slot, extra=""):
    message = (
        f"Hello {name},\n"
        f"Your appointment is confirmed.\n"
        f"Doctor: {doctor}\n"
        f"Token No: {token}\n"
        f"Date: {date_str}\n"
        f"Time: {time_slot}\n"
        f"{extra}\n"
        f"- Lavanys Clinic"
    )
    try:
        msg = client.messages.create(body=message, from_=TWILIO_PHONE, to=f"+91{phone}")
        print("SMS SENT ✅", msg.sid)
    except Exception as e:
        print("SMS FAILED ❌", str(e))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = AdminUser.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid username or password"
    return render_template('admin_login.html', error=error)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    # Filters
    from_date = request.args.get('from_date')
    to_date   = request.args.get('to_date')
    doctor    = request.args.get('doctor')
    search    = request.args.get('search', '').strip()

    query = Appointment.query

    if from_date: query = query.filter(Appointment.date >= from_date)
    if to_date:   query = query.filter(Appointment.date <= to_date)
    if doctor:    query = query.filter(Appointment.doctor == doctor)
    if search:
        query = query.filter(
            db.or_(
                Appointment.name.ilike(f"%{search}%"),
                Appointment.phone.ilike(f"%{search}%")
            )
        )

    appointments = query.order_by(Appointment.date.desc(), Appointment.token).all()

    # Stats
    total = Appointment.query.count()
    today = datetime.now().strftime('%Y-%m-%d')
    today_count = Appointment.query.filter_by(date=today).count()
    week_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    week_count = Appointment.query.filter(Appointment.date >= week_start).count()
    cancelled_count = Appointment.query.filter_by(status='cancelled').count()
    doctor_counts = Counter(ap.doctor for ap in Appointment.query.all())
    top_doctor = doctor_counts.most_common(1)[0][0] if doctor_counts else "N/A"

    stats = {
        'total': total,
        'today': today_count,
        'week': week_count,
        'cancelled': cancelled_count,
        'top_doctor': top_doctor
    }

    return render_template('admin_dashboard.html', appointments=appointments, stats=stats)

@app.route('/admin/cancel/<int:appointment_id>', methods=['POST'])
def cancel_appointment(appointment_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    ap = Appointment.query.get_or_404(appointment_id)
    if ap.status == 'confirmed':
        ap.status = 'cancelled'
        db.session.commit()
        send_sms(ap.phone, ap.name, ap.token, ap.doctor, ap.date, ap.time_slot, "(CANCELLED by clinic)")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/complete/<int:appointment_id>', methods=['POST'])
def complete_appointment(appointment_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    ap = Appointment.query.get_or_404(appointment_id)
    if ap.status == 'confirmed':
        ap.status = 'completed'
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/booking-success')
def booking_success():
    return render_template('booking_success.html',
                          token=request.args.get('token'),
                          doctor=request.args.get('doctor'),
                          date=request.args.get('date'),
                          time_slot=request.args.get('time_slot'),
                          phone=request.args.get('phone'))

@app.route('/api/book', methods=['POST'])
def api_book():
    data = request.get_json()

    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    doctor = data.get('doctor')
    app_date = data.get('date')
    time_slot = data.get('time')

    if not phone or len(phone) != 10 or not phone.isdigit():
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    if not all([name, doctor, app_date, time_slot]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    existing_count = Appointment.query.filter_by(date=app_date).count()
    token = existing_count + 1

    new_booking = Appointment(
        name=name,
        phone=phone,
        doctor=doctor,
        date=app_date,
        time_slot=time_slot,
        token=token
    )

    db.session.add(new_booking)
    db.session.commit()

    send_sms(phone, name, token, doctor, app_date, time_slot)

    # Redirect to thank you page
    return jsonify({
        "success": True,
        "redirect": url_for('booking_success',
                           token=token,
                           doctor=doctor,
                           date=app_date,
                           time_slot=time_slot,
                           phone=phone)
    })

if __name__ == "__main__":
    print("Lavanys Clinic Server starting...")
    print("Database file: clinic.db")
    print("Patient page:     http://127.0.0.1:5000/")
    print("Admin login:      http://127.0.0.1:5000/admin/login")
    print("Credentials → username: admin | password: lavanys123")
    app.run(debug=True)

from flask import Flask, render_template, request, jsonify, session, redirect
from datetime import date, datetime, time

app = Flask(__name__)
app.secret_key = "clinic-secret-key"   # REQUIRED for session


MAX_TOKENS_PER_DAY = 30
SESSION_START_TIME = time(17, 0)   # 5:00 PM
SESSION_END_TIME   = time(20, 0)   # 8:00 PM

# In-memory storage
bookings = {}        # { date: [booking, booking] }
availability = {}    # { date: {available, booked_count} }

today_str = date.today().isoformat()


def get_availability(d):
    if d not in availability:
        availability[d] = {
            'available': True,
            'booked_count': 0
        }
    return availability[d]

def can_book_today():
    return datetime.now().time() < SESSION_START_TIME



@app.route('/')
def home():
    return render_template(
        'index.html',
        today=today_str,
        is_admin=session.get('admin_logged_in', False),
        bookings=bookings
    )


@app.route('/my-token')
def my_token():
    return render_template('my-token.html')


@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == "admin" and password == "admin123":
        session['admin_logged_in'] = True

    return redirect('/')


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/')


@app.route('/api/book', methods=['POST'])
def api_book():
    data = request.get_json()

    name  = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    b_date = data.get('date', '').strip()

    if not name or not phone or not b_date:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    if len(phone) != 10 or not phone.isdigit():
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    if b_date < today_str:
        return jsonify({"success": False, "message": "Cannot book past dates"}), 400

    if b_date == today_str and not can_book_today():
        return jsonify({"success": False, "message": "Booking window closed"}), 400

    avail = get_availability(b_date)

    if not avail['available']:
        return jsonify({"success": False, "message": "Bookings closed for this date"}), 400

    if avail['booked_count'] >= MAX_TOKENS_PER_DAY:
        return jsonify({"success": False, "message": "Tokens full"}), 400

    token_number = avail['booked_count'] + 1
    avail['booked_count'] += 1

    booking = {
        "name": name,
        "phone": phone,
        "token": token_number,
        "status": "confirmed",
        "booked_at": datetime.now().strftime("%H:%M")
    }

    bookings.setdefault(b_date, []).append(booking)

    return jsonify({
        "success": True,
        "message": "Token booked successfully",
        "token": token_number,
        "date": b_date
    })


@app.route('/api/close-today', methods=['POST'])
def close_today():
    availability[today_str] = {'available': False, 'booked_count': 0}

    if today_str in bookings:
        for b in bookings[today_str]:
            b['status'] = 'cancelled'

    return jsonify({"success": True, "message": "Today's OPD closed"})

@app.route('/api/check-token', methods=['POST'])
def check_token():
    data = request.get_json()
    phone = data.get('phone', '').strip()

    for d, blist in bookings.items():
        for b in blist:
            if b['phone'] == phone:
                return jsonify({
                    "success": True,
                    "found": True,
                    "name": b['name'],
                    "date": d,
                    "token": b['token'],
                    "status": b['status'],
                    "booked_at": b['booked_at']
                })

    return jsonify({"success": True, "found": False})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

