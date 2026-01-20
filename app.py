from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
import json

# ------------------ APP SETUP ------------------
app = Flask(__name__)
app.secret_key = "eventedge_secret"

# ------------------ DATABASE ------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventedge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------ LOGIN MANAGER ------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------ EMAIL CONFIG ------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'eventedge.notifier@gmail.com'
app.config['MAIL_PASSWORD'] = 'cpiysjhvgekjiapd'  # App password
app.config['MAIL_DEFAULT_SENDER'] = 'eventedge.notifier@gmail.com'
mail = Mail(app)

# ------------------ TIMEZONE ------------------
IST = pytz.timezone('Asia/Kolkata')

# ------------------ MODELS ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    head_name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ LOGGING HELPER ------------------
def log_activity(action):
    if current_user.is_authenticated:
        log = ActivityLog(user_email=current_user.email, action=action)
        db.session.add(log)
        db.session.commit()

# ------------------ ROUTES ------------------

@app.route('/')
def welcome():
    return render_template('welcome.html')

# ------------------ REGISTER ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash("Account already exists", "error")
            return redirect(url_for('login'))

        user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=generate_password_hash(request.form['password'])
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------------ LOGIN ------------------
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

# ------------------ ADMIN LOGIN ------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email'], role="admin").first()
        if not user or not check_password_hash(user.password, request.form['password']):
            flash("You're not the admin", "error")
            return redirect(url_for('admin_login'))

        login_user(user)
        log_activity("Admin logged in")
        return redirect(url_for('admin_splash'))
    return render_template('admin_login.html')

# ------------------ POST LOGIN ------------------
@app.route('/post-login')
@login_required
def post_login():
    if current_user.role == "admin":
        return redirect(url_for('admin_splash'))
    return render_template('post_login_splash.html')

@app.route('/admin-splash')
@login_required
def admin_splash():
    return render_template('admin_splash.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# ------------------ VIEW EVENTS ------------------
@app.route('/admin/view-events')
@login_required
def view_events():
    if current_user.role != "admin":
        flash("Access denied", "error")
        return redirect(url_for('welcome'))

    events = Event.query.order_by(Event.created_at.desc()).all()
    return render_template("view_events.html", events=events)

# ------------------ ACTIVITY LOGS ------------------
@app.route('/admin/activity-logs')
@login_required
def activity_logs():
    if current_user.role != "admin":
        flash("Access denied", "error")
        return redirect(url_for('welcome'))

    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    for log in logs:
        log.display_time = log.timestamp.astimezone(IST).strftime('%d %b %Y • %I:%M %p')
    return render_template("activity_logs.html", logs=logs)

# ------------------ CREATE EVENT ------------------
@app.route('/create-event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        session['event_data'] = {
            'event_name': request.form['event_name'],
            'head_name': request.form['head_name'],
            'description': request.form.get('description', '')
        }
        log_activity(f"Event '{session['event_data']['event_name']}' created by {current_user.name}")
        return redirect(url_for('core_details'))
    return render_template('create_event.html')

# ------------------ CORE DETAILS ------------------
@app.route('/core-details', methods=['GET', 'POST'])
@login_required
def core_details():
    if request.method == 'POST':
        members_json = request.form.get('members_json', '[]')
        session['members'] = json.loads(members_json)
        log_activity(f"Core committee added for event '{session['event_data']['event_name']}'")
        return redirect(url_for('meetings'))
    return render_template('core_details.html')

# ------------------ MEETINGS ------------------
@app.route('/meetings')
@login_required
def meetings():
    log_activity("Scheduled meetings")
    return render_template('meetings.html')

@app.route('/schedule-meetings', methods=['POST'])
@login_required
def schedule_meetings():
    session['meeting_data'] = {
        'first_meeting': request.form.get('first_meeting'),
        'group_link': request.form.get('group_link')
    }
    log_activity(f"Meetings scheduled for event '{session['event_data']['event_name']}'")
    return redirect(url_for('review_msg'))

# ------------------ REVIEW MESSAGE ------------------
@app.route('/review-msg')
@login_required
def review_msg():
    return render_template(
        'review_msg.html',
        event_data=session.get('event_data', {}),
        members=session.get('members', []),
        meeting_data=session.get('meeting_data', {})
    )

# ------------------ SEND EMAILS ------------------
@app.route('/send-messages', methods=['POST'])
@login_required
def send_messages():
    event_data = session.get('event_data')
    members = session.get('members', [])
    meeting_data = session.get('meeting_data', {})

    if not event_data or not members or not meeting_data:
        flash("Incomplete event data", "error")
        return redirect(url_for('review_msg'))

    # Send emails safely
    for m in members:
        try:
            send_event_email(
                to_email=m['email'],
                head=event_data['head_name'],
                event=event_data['event_name'],
                role=m['role'],
                date=meeting_data['first_meeting'],
                link=meeting_data['group_link']
            )
        except Exception as e:
            print(f"Failed to send email to {m['email']}: {e}")

    # Save Event to DB
    event = Event(
        name=event_data['event_name'],
        head_name=event_data['head_name'],
        created_by=current_user.email
    )
    db.session.add(event)
    db.session.commit()

    log_activity(f"Event '{event_data['event_name']}' emails sent and saved")

    # Clear session
    session.pop('event_data', None)
    session.pop('members', None)
    session.pop('meeting_data', None)

    return redirect(url_for('event_success'))

def send_event_email(to_email, head, event, role, date, link):
    """Send email to a single member."""
    msg = Message(
        subject=f"[EventEdge] {event}",
        recipients=[to_email],
        html=render_template(
            "email_message.html",
            show_progress=False,
            head_name=head,
            event_name=event,
            role=role,
            first_meeting_date=date,
            group_link=link
        )
    )
    mail.send(msg)

@app.route('/email-preview')
@login_required
def email_preview():
    event_data = session.get('event_data')
    members = session.get('members')
    meeting_data = session.get('meeting_data')

    # preview with first member
    member = members[0]

    return render_template(
        'email_message.html',
        show_progress=True,   # 👈 SHOW progress bar
        head_name=event_data['head_name'],
        event_name=event_data['event_name'],
        role=member['role'],
        first_meeting_date=meeting_data['first_meeting'],
        group_link=meeting_data['group_link']
    )


# ------------------ EVENT SUCCESS ------------------
@app.route('/event-success')
@login_required
def event_success():
    log_activity("Event creation completed")
    return render_template('event_success.html')

# ------------------ LOGOUT ------------------
@app.route('/logout')
@login_required
def logout():
    log_activity("Logged out")
    logout_user()
    return redirect(url_for('welcome'))

# ------------------ CREATE ADMIN ------------------
@app.route('/create-admin')
def create_admin():
    if User.query.filter_by(email="admin@eventedge.com").first():
        return "Admin exists"

    admin = User(
        name="Admin",
        email="admin@eventedge.com",
        password=generate_password_hash("admin123"),
        role="admin"
    )
    db.session.add(admin)
    db.session.commit()
    return "Admin created"

# ------------------ RUN APP ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
