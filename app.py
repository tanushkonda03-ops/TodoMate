from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
# Database configuration
# Database configuration
db_url = os.getenv("DATABASE_URL")

# Fix for old-style URLs
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)

# Auto-detect Render environment
if os.getenv("RENDER"):  # Render sets this env var automatically
    print("Running on Render → using internal DB URL")
else:
    print("Running locally → make sure you exported the external DB URL")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

print("ATTEMPTING TO CREATE DATABASE TABLES...") # <-- Add this print statement
with app.app_context():
    db.create_all()
    print("db.create_all() EXECUTED.") # <-- Add this print statement
print("FINISHED DATABASE SETUP BLOCK.")

app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key")  # Needed for sessions to work securely
# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50), nullable=False)
    desc = db.Column(db.String(150), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(15), default='active')
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.Uid'), nullable=False)

class User(db.Model):
    Uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Uname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    otp = db.Column(db.String(6), nullable=True) 
    otp_created_at = db.Column(db.DateTime, nullable=True)
    

@app.route('/',methods=['GET', 'POST'])
def mainfun():
    authflag = session.get('logged_in', False)
    username = session.get('username', '')
    show_guest_modal = not authflag
    if request.method=='POST':
        title = request.form['title']
        desc = request.form['desc']
        due_date_str = request.form.get('due_date')  # from datetime-local input
        due_date = datetime.strptime(due_date_str, "%Y-%m-%dT%H:%M") if due_date_str else None
        if not title:
            error_message = "Please Fill in title field"
            return render_template('index.html', error_message=error_message, show_guest_modal=show_guest_modal)
        if authflag:
            user = User.query.filter_by(Uname=username).first()
            if user and not user.is_verified:
                return redirect(url_for('verify_page'))
            if user:
                todo = Todo(title=title, desc=desc, user_id=user.Uid, due_date=due_date)
                db.session.add(todo)
                db.session.commit()
        else:
            guest_todos = session.get('guest_todos', [])
            guest_todos.append({
                'id': len(guest_todos),
                'title': title,
                'desc': desc,
                'date_created': datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                'status': 'active',
                'due_date': due_date.strftime("%Y-%m-%d %H:%M") if due_date else None
            })
            session['guest_todos'] = guest_todos
        return redirect('/view')
    
    return render_template('index.html', authflag=authflag, username=username, show_guest_modal=show_guest_modal)


@app.route('/signin', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        Uname = request.form['Uname']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(email=email).first()
        if not Uname or not email or not password:
            error_message = "Please fill in all the fields: username, email, and password."
            return render_template('signin.html', error_message=error_message, Uname=Uname, email=email)
        if existing_user:
            error_message = "An account with this email already exists. Please log in instead."
            return render_template('signin.html', error_message=error_message)

        hashed_password = generate_password_hash(password)
        user = User(Uname=Uname, email=email, password=hashed_password, is_verified=False)
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_created_at = datetime.utcnow()
        db.session.add(user)
        db.session.commit()
        try:
            msg = Message('OTP for Todo App Verification', recipients=[email])
            msg.body = f"Your one-time password (OTP) for Todo website is: {otp}. It is valid for 5 minutes."
            mail.send(msg)
            session['logged_in'] = True
            session['username'] = Uname
            return redirect(url_for('verify_page'))

        except Exception as e:
            # Handle email sending failure
            db.session.rollback()
            error_message = f"Failed to send verification email. Please try again. Error: {e}"
            return render_template('signin.html', error_message=error_message)

    return render_template('signin.html')

@app.route('/verify')
def verify_page():
    if not session.get('logged_in'):
        return redirect(url_for('login_user'))
    
    username = session.get('username')
    user = User.query.filter_by(Uname=username).first()
    
    # If user is already verified, let them pass
    if user and user.is_verified:
        return redirect(url_for('mainfun'))
    
    # If user is not verified, show the OTP modal
    return render_template('signin.html', show_otp_modal=True)

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_otp = request.form.get('otp')
    username = session.get('username')
    user = User.query.filter_by(Uname=username).first()

    if not user:
        return redirect(url_for('create_user', error_message='Something went wrong. Please try signing up again.'))
    
    # Check if the OTP matches and is not expired (e.g., within 5 minutes)
    time_difference = datetime.utcnow() - user.otp_created_at
    if user_otp == user.otp and time_difference < timedelta(minutes=5):
        # Verification successful
        user.is_verified = True
        user.otp = None
        db.session.commit()
        msg = Message(f'Welcome to Todo App, {user.Uname}!', recipients=[user.email])
        msg.body = f"Hello {user.Uname},\n\nThank you for verifying your email. You can now use all the features of the Todo App.\n\nBest regards,\nYour Todo App Team"
        mail.send(msg)
        return redirect(url_for('view_todo'))
    else:
        # Verification failed
        error_message = "Invalid or expired OTP. Please try again."
        return render_template('signin.html', show_otp_modal=True, error_message=error_message)
    
@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    username = session.get('username')
    if not username:
        return redirect(url_for('create_user', error_message='Please sign up first to get an OTP.'))
    
    user = User.query.filter_by(Uname=username).first()
    if not user:
        return redirect(url_for('create_user', error_message='User not found.'))
    
    # Generate a new OTP and update the user record
    new_otp = str(random.randint(100000, 999999))
    user.otp = new_otp
    user.otp_created_at = datetime.utcnow()
    db.session.commit()

    # Send the new OTP email
    try:
        msg = Message('New OTP for Todo App Verification', recipients=[user.email])
        msg.body = f"A new one-time password (OTP) has been requested. Your new OTP is: {new_otp}. It is valid for 5 minutes."
        mail.send(msg)
        error_message = 'A new OTP has been sent to your email.'
    except Exception as e:
        error_message = f"Failed to resend verification email. Please try again. Error: {e}"

    return render_template('signin.html', show_otp_modal=True, error_message=error_message)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    message = request.args.get('message')
    if request.method == 'POST':
        name = request.form.get('Uname')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.email == email and check_password_hash(user.password, password) and user.Uname == name:
            # Authentication successfull
            session['logged_in'] = True
            session['username'] = user.Uname
            return redirect('/')
        else:
            # Authentication failed
            return render_template('login.html', authflag=False, message="Invalid username, email, or password.")

    return render_template('login.html', message=message)

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    Uname = request.form.get('Uname')
    email = request.form.get('email')

    user = User.query.filter_by(Uname=Uname, email=email).first()

    if user:
        # Generate a new OTP and send it
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_created_at = datetime.utcnow()
        db.session.commit()
        msg = Message('Password Reset OTP for Todo App', recipients=[email])
        msg.body = f"Your one-time password (OTP) to reset your password is: {otp}. It is valid for 5 minutes."
        mail.send(msg)
        # Store the user's username in a session for the next step
        session['reset_username'] = Uname
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Incorrect username or email.'})

@app.route('/reset_password_otp', methods=['POST']) 
def reset_password_otp():
    user_otp = request.form.get('otp')
    reset_username = session.get('reset_username')
    
    if not reset_username:
        return jsonify({'success': False, 'error': 'Session expired. Please try again.'})

    user = User.query.filter_by(Uname=reset_username).first()

    if not user:
        return jsonify({'success': False, 'error': 'Something went wrong. Please start the process again.'})

    time_difference = datetime.utcnow() - user.otp_created_at
    if user_otp == user.otp and time_difference < timedelta(minutes=5):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Invalid or expired OTP.'})
    
@app.route('/set_new_password', methods=['POST'])
def set_new_password():
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    reset_username = session.get('reset_username')

    if not reset_username:
        return jsonify({'success': False, 'error': 'Session expired. Please try again.'})
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match.'})

    user = User.query.filter_by(Uname=reset_username).first()
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'})
    
    # Update the password and clear the OTP
    hashed_new_password = generate_password_hash(new_password)
    user.password = hashed_new_password
    user.otp = None  # Clear the OTP after successful password reset
    db.session.commit()
    
    session.pop('reset_username', None) # Clear the temporary session variable
    
    return jsonify({'success': True, 'redirect_url': url_for('login_user', message="Password reset successfully! Please login.")})
        
@app.route('/view')
def view_todo():
    authflag = session.get('logged_in', False)
    username = session.get('username', '')

    if authflag:
        user = User.query.filter_by(Uname=username).first()
        if user and not user.is_verified:
            return redirect(url_for('verify_page'))
        if user:
            todos = Todo.query.filter_by(user_id=user.Uid).all()
        else:
            todos = []
        # Separate active and completed
        active_todos = [t for t in todos if t.status == 'active']
        completed_todos = [t for t in todos if t.status == 'completed']
    else:
        todos = session.get('guest_todos', [])
        # Convert guest string dates like "YYYY-MM-DD HH:MM" into datetime
        for t in todos:
            dd = t.get('due_date')
            if isinstance(dd, str) and dd.strip():
                try:
                    from datetime import datetime
                    t['due_date'] = datetime.strptime(dd, "%Y-%m-%d %H:%M")
                except ValueError:
                    t['due_date'] = None  # ignore bad/old formats safely

        active_todos = [t for t in todos if t.get('status') == 'active']
        completed_todos = [t for t in todos if t.get('status') == 'completed']

    from datetime import datetime
    # Use UTC for consistency with your model defaults
    now_utc = datetime.utcnow()
    return render_template(
        'view.html',
        authflag=authflag,
        username=username,
        todos=todos,
        now=now_utc,
        active_todos=active_todos,
        completed_todos=completed_todos
    )

#To help edit route
@app.template_filter('datetime_local_string')
def datetime_local_string(value):
    if not value:
        return ''
    return value.strftime('%Y-%m-%dT%H:%M')
@app.template_filter('fmt_dt')
def fmt_dt(value):
    """Format a datetime as 'YYYY-MM-DD HH:MM' without crashing if it's already a string/None."""
    from datetime import datetime
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M')
    return str(value)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_todo(id):
    authflag = session.get('logged_in', False)
    username = session.get('username', '')
    user = User.query.filter_by(Uname=username).first()
    todo = Todo.query.filter_by(id=id, user_id=user.Uid).first()
    if request.method=='POST':
        todo.title = request.form['title']
        todo.desc = request.form['desc']
        due_date = request.form.get('due_date')
        if due_date:
            todo.due_date = datetime.fromisoformat(due_date)
        db.session.commit()
        return redirect('/view')
    return render_template('edit.html', authflag=authflag, username=username, todo=todo)

@app.route('/complete/<int:id>')
def complete_todo(id):
    authflag = session.get('logged_in', False)
    if authflag: 
        todo = Todo.query.get(id)
        
        if todo:
            todo.status = 'completed'
            db.session.commit()
    else:
        guest_todos = session.get('guest_todos', [])
        for t in guest_todos:
            if t['id'] == id:
                t['status'] = 'completed'
        session['guest_todos'] = guest_todos
    return redirect(url_for('view_todo'))

@app.route('/retrieve/<int:id>')
def retrieve_todo(id):
    authflag = session.get('logged_in', False)
    if authflag:
        todo = Todo.query.get(id)
        if todo:
            todo.status = 'active'
            db.session.commit()
    else:
        guest_todos = session.get('guest_todos', [])
        for t in guest_todos:
            if t['id'] == id:
                t['status'] = 'active'
        session['guest_todos'] = guest_todos
    return redirect(url_for('view_todo'))

@app.route('/delete/<int:id>')
def delete(id):
    authflag = session.get('logged_in', False)
    username = session.get('username', '')
    if authflag:
        todo = Todo.query.filter_by(id=id).first()
        if todo:
            db.session.delete(todo)
            db.session.commit()
    else:
        guest_todos = session.get('guest_todos', [])
        guest_todos = [t for t in guest_todos if t['id'] != id]
        session['guest_todos'] = guest_todos
    return redirect('/view')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)   # Remove logged_in key from session
    session.pop('username', None)    # Remove username key from session
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)