from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from io import BytesIO
import pytz
import json

# ================== APP SETUP ==================
app = Flask(__name__)
app.secret_key = "eventedge_secret"

# ================== DATABASE ==================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventedge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ================== LOGIN ==================
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ================== EMAIL ==================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'eventedge.notifier@gmail.com'
app.config['MAIL_PASSWORD'] = 'YOUR_APP_PASSWORD'
app.config['MAIL_DEFAULT_SENDER'] = 'eventedge.notifier@gmail.com'
mail = Mail(app)

# ================== TIMEZONE ==================
IST = pytz.timezone("Asia/Kolkata")

# ================== MODELS ==================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(100))
    event_date = db.Column(db.String(50))
    head_name = db.Column(db.String(100), nullable=False)
    head_email = db.Column(db.String(120))
    faculty_name = db.Column(db.String(100))
    faculty_email = db.Column(db.String(120))
    description = db.Column(db.Text)
    first_meeting_date = db.Column(db.String(50))
    second_meeting_date = db.Column(db.String(50))
    group_link = db.Column(db.String(300))
    created_by = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    members = db.relationship(
        'EventMember',
        backref='event',
        cascade="all, delete",
        lazy=True
    )

class EventMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    name = db.Column(db.String(100))
    role = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))

# ================== LOAD USER ==================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================== LOGGING ==================
def log_activity(action):
    if current_user.is_authenticated:
        db.session.add(
            ActivityLog(
                user_email=current_user.email,
                action=action
            )
        )
        db.session.commit()

# ================== ROUTES ==================
@app.route('/')
def welcome():
    return render_template('welcome.html')

# ---------- AUTH ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash("Account already exists", "error")
            return redirect(url_for('login'))

        db.session.add(
            User(
                name=request.form['name'],
                email=request.form['email'],
                password=generate_password_hash(request.form['password'])
            )
        )
        db.session.commit()
        flash("Registration successful", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if not user or not check_password_hash(user.password, request.form['password']):
            flash("Invalid credentials", "error")
            return redirect(url_for('login'))

        login_user(user)
        log_activity("Logged in")
        return redirect(url_for('post_login'))
    return render_template('login.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = User.query.filter_by(
            email=request.form['email'],
            role="admin"
        ).first()

        if not user or not check_password_hash(user.password, request.form['password']):
            flash("Unauthorized admin login", "error")
            return redirect(url_for('admin_login'))

        login_user(user)
        log_activity("Admin logged in")
        return redirect(url_for('admin_splash'))
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity("Logged out")
    logout_user()
    return redirect(url_for('welcome'))

# ---------- DASHBOARD ----------
@app.route('/post-login')
@login_required
def post_login():
    return redirect(url_for('admin_splash')) if current_user.role == "admin" else render_template('post_login_splash.html')

@app.route('/admin-splash')
@login_required
def admin_splash():
    return render_template('admin_splash.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# ---------- EVENTS ----------
@app.route('/create-event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        session['event_data'] = {
            'event_name': request.form['event_name'],
            'department': request.form['department'],
            'event_date': request.form['event_date'],
            'head_name': request.form['head_name'],
            'head_email': request.form['head_email'],
            'faculty_name': request.form['faculty_name'],
            'faculty_email': request.form['faculty_email']
        }

        log_activity(f"Event '{request.form['event_name']}' initiated")
        return redirect(url_for('core_details'))
    return render_template('create_event.html')

@app.route('/core-details', methods=['GET', 'POST'])
@login_required
def core_details():
    if request.method == 'POST':
        session['members'] = json.loads(request.form.get('members_json', '[]'))
        log_activity("Core committee added")
        return redirect(url_for('meetings'))
    return render_template('core_details.html')

@app.route('/meetings')
@login_required
def meetings():
    return render_template('meetings.html')

@app.route('/schedule-meetings', methods=['POST'])
@login_required
def schedule_meetings():
    session['meeting_data'] = {
        'first_meeting': request.form['first_meeting'],
        'second_meeting': request.form['second_meeting'],
        'group_link': request.form['group_link']
    }
    log_activity("Meetings scheduled")
    return redirect(url_for('review_msg'))


@app.route('/review-msg')
@login_required
def review_msg():
    return render_template(
        'review_msg.html',
        event_data=session.get('event_data'),
        members=session.get('members'),
        meeting_data=session.get('meeting_data')
    )

# ---------- EMAIL ----------
def send_event_email(to_email, head, event, role, date, link):
    msg = Message(
        subject=f"[EventEdge] {event}",
        recipients=[to_email],
        html=render_template(
            'email_message.html',
            show_progress=False,
            head_name=head,
            event_name=event,
            role=role,
            first_meeting_date=date,
            group_link=link
        )
    )
    mail.send(msg)

@app.route('/send-messages', methods=['POST'])
@login_required
def send_messages():
    event_data = session.get('event_data')
    members = session.get('members')
    meeting_data = session.get('meeting_data')

    if not all([event_data, members, meeting_data]):
        flash("Incomplete event data", "error")
        return redirect(url_for('review_msg'))

    try:
        event = Event(
            name=event_data['event_name'],
            department=event_data['department'],
            event_date=event_data['event_date'],
            head_name=event_data['head_name'],
            head_email=event_data['head_email'],
            faculty_name=event_data['faculty_name'],
            faculty_email=event_data['faculty_email'],
            first_meeting_date=meeting_data['first_meeting'],
            second_meeting_date=meeting_data['second_meeting'],
            group_link=meeting_data['group_link'],
            created_by=current_user.email
        )

        db.session.add(event)
        db.session.flush()   # ✅ get event.id

        for m in members:
            db.session.add(
                EventMember(
                    event_id=event.id,
                    name=m['name'],
                    role=m['role'],
                    email=m['email'],
                    phone=m['phone']
                )
            )

        db.session.commit()

        # ✅ CLEAR SESSION FIRST
        session.pop('event_data', None)
        session.pop('members', None)
        session.pop('meeting_data', None)


        # ✅ REDIRECT IMMEDIATELY
        response = redirect(url_for('event_success'))

        # ✅ SEND EMAILS AFTER RESPONSE (SAFE)
        for m in members:
            try:
                send_event_email(
                    m['email'],
                    event.head_name,
                    event.name,
                    m['role'],
                    event.first_meeting_date,
                    event.group_link
                )
            except Exception as mail_error:
                print("EMAIL FAILED FOR:", m['email'], mail_error)

        log_activity(f"Event '{event.name}' created")

        return response

    except Exception as e:
        db.session.rollback()
        print("SEND MESSAGE ERROR:", e)
        flash("Failed while creating event", "error")
        return redirect(url_for('review_msg'))

# ---------- SUCCESS ----------
@app.route('/event-success')
@login_required
def event_success():
    return render_template('event_success.html')

# ---------- ADMIN ----------
from sqlalchemy import extract, or_
@app.route('/admin/view-events')
@login_required
def view_events():
    if current_user.role != "admin":
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))

    # ---- GET QUERY PARAMS ----
    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', '')
    month = request.args.get('month', '')

    # ---- BASE QUERY ----
    query = Event.query

    # ---- SEARCH FILTER ----
    if search:
        query = query.filter(
            or_(
                Event.name.ilike(f"%{search}%"),
                Event.department.ilike(f"%{search}%"),
                Event.head_name.ilike(f"%{search}%")
            )
        )

    # ---- MONTH FILTER (YYYY-MM) ----
    if month:
        year, mon = month.split('-')
        query = query.filter(
            extract('year', Event.created_at) == int(year),
            extract('month', Event.created_at) == int(mon)
        )

    # ---- SORT ----
    if sort == "az":
        query = query.order_by(Event.name.asc())
    elif sort == "za":
        query = query.order_by(Event.name.desc())
    else:
        query = query.order_by(Event.created_at.desc())

    # ---- EXECUTE QUERY ----
    events = query.all()

    return render_template(
        "view_events.html",
        events=events,
        search=search,
        sort=sort,
        month=month
    )


# ---------- DOWNLOAD EVENT DETAILS AS PDF ----------
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO

def generate_event_pdf(event):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 60

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawCentredString(width / 2, y, event.name.upper())

    y -= 40
    pdf.setFont("Helvetica", 11)

    pdf.drawString(50, y, f"Event Name: {event.name}")
    y -= 18
    pdf.drawString(50, y, f"Department: {event.department or 'N/A'}")
    y -= 18
    pdf.drawString(50, y, f"Event Date: {event.event_date or 'N/A'}")
    y -= 18
    pdf.drawString(50, y, f"Event Head Name: {event.head_name}")
    y -= 18
    pdf.drawString(50, y, f"Event Head Email: {event.head_email}")
    y -= 18
    pdf.drawString(50, y, f"Faculty Name: {event.faculty_name or 'N/A'}")
    y -= 18
    pdf.drawString(50, y, f"Faculty Email: {event.faculty_email or 'N/A'}")
    y -= 30

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "CORE COMMITTEE DETAILS")
    y -= 20
    pdf.setFont("Helvetica", 11)

    for m in event.members:
        pdf.drawString(
            60, y,
            f"- {m.name} | {m.role} | {m.email} | {m.phone}"
        )
        y -= 15
        if y < 60:
            pdf.showPage()
            y = height - 60

    y -= 20
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "MEETINGS")
    y -= 20
    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"First Meeting: {event.first_meeting_date}")
    y -= 18
    pdf.drawString(50, y, f"Second Meeting: {event.second_meeting_date}")
    y -= 30

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "COMMUNICATION")
    y -= 20
    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, event.group_link or "N/A")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer

@app.route('/admin/download-event/<int:event_id>')
@login_required
def download_event(event_id):
    if current_user.role != "admin":
        flash("Access denied", "error")
        return redirect(url_for('welcome'))

    event = Event.query.get_or_404(event_id)
    pdf_buffer = generate_event_pdf(event)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{event.name}_details.pdf",
        mimetype='application/pdf'
    )


# ------------------ CREATE ADMIN ------------------ 
@app.route('/create-admin') 
def create_admin(): 
    if User.query.filter_by(email="admin@eventedge.com").first(): 
        return "Admin exists" 
    admin = User( name="Admin", email="admin@eventedge.com", password=generate_password_hash("admin123"), role="admin" ) 
    db.session.add(admin) 
    db.session.commit() 
    return "Admin created"

@app.route('/test-download-route')
def test_download_route():
    return "Download route works"

# ---------- RUN ----------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
