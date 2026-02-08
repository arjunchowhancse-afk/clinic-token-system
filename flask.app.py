from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import date, datetime, time
import requests

app = Flask(__name__)
app.secret_key = "clinic-secret-key"

MAX_TOKENS_PER_DAY = 30
SESSION_START_TIME = time(5:00)   # 5:00 PM
SESSION_END_TIME   = time(8:00)   # 8:00 PM


FAST2SMS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCIgOiAiMDhkMjJmOGItYzFmNy00OWMxLTk1OGEtYjQ5MDMzY2I2YmFiIiwgInJvbGUiIDogImFwaSIsICJ0eXBlIiA6ICJhcGkiLCAibmFtZSIgOiAiQXJqdW4gQ2hhdWhhbiIsICJleHAiIDogMjA4NTgyMjcxNiwgImlhdCIgOiAxNzcwMjg5OTE2LCAic3ViIiA6ICI0OWZkNTNmOC04OGIwLTRjM2YtYjMxNy03NWJiZTBjMTkyNTAiLCAiaXNzIiA6ICJwZXJpc2tvcGUuYXBwIiwgIm1ldGFkYXRhIiA6IHsic2NvcGVzIjogWyI5MTg5OTk1NDA2NzJAYy51cyJdfX0.uD1VK_3Onjnk4LewID83Qfhy55QrwR5zsrz6MAIUbH0"
FAST2SMS_URL = "https://www.fast2sms.com/dev/bulkV2"

# In-memory storage
bookings = {}          # {date: [booking1, booking2, ...]}
availability = {}

today_str = date.today().isoformat()

def get_availability(d):
    if d not in availability:
        availability[d] = {'available': True, 'booked_count': 0}
    return availability[d]

def can_book_today():
    now = datetime.now().time()
    return now < SESSION_START_TIME

def send_sms(phone, name, token, doctor, date_str, time_slot):
    message = (
        f"Hello {name},\n"
        f"Appointment Confirmed\n"
        f"Doctor: {doctor}\n"
        f"Token No: {token}\n"
        f"Date: {date_str}\n"
        f"Time: {time_slot}\n"
        f"Lavanys Clinic"
    )

    payload = {
        "route": "q",
        "language": "english",
        "numbers": phone,
        "message": message
    }

    headers = {
        "authorization": FAST2SMS_API_KEY,
        "Content-Type": "application/json"
    }

    try:
        res = requests.post(FAST2SMS_URL, json=payload, headers=headers)
        print("SMS Response:", res.status_code, res.text)
    except Exception as e:
        print("SMS Error:", str(e))

@app.route('/')
def home():
    return render_template('index.html', today=today_str)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('username') == "admin" and request.form.get('password') == "admin123":
            session['admin_logged_in'] = True
            return redirect('/admin/dashboard')
        else:
            return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')
    return render_template('admin_dashboard.html', bookings=bookings)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/')

@app.route('/api/book', methods=['POST'])
def api_book():
    data = request.get_json()

    doctor = data.get('doctor')
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    b_date = data.get('date', '').strip()
    time_slot = data.get('time')

    if not all([doctor, name, phone, b_date, time_slot]):
        return jsonify({"success": False, "message": "All required fields missing"}), 400

    if len(phone) != 10 or not phone.isdigit():
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    if b_date < today_str:
        return jsonify({"success": False, "message": "Cannot book past date"}), 400

    avail = get_availability(b_date)

    if not avail['available']:
        return jsonify({"success": False, "message": "Bookings closed for this date"}), 400

    if avail['booked_count'] >= MAX_TOKENS_PER_DAY:
        return jsonify({"success": False, "message": "All tokens booked for this date"}), 400

    token_number = avail['booked_count'] + 1
    avail['booked_count'] += 1

    booking = {
        "doctor": doctor,
        "name": name,
        "phone": phone,
        "token": token_number,
        "date": b_date,
        "time": time_slot,
        "status": "confirmed",
        "booked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    }

    bookings.setdefault(b_date, []).append(booking)

    # SMS bhej do
    send_sms(phone, name, token_number, doctor, b_date, time_slot)

    return jsonify({
        "success": True,
        "message": "Appointment confirmed",
        "token": token_number,
        "doctor": doctor,
        "date": b_date,
        "time": time_slot
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)s