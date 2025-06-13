import secrets
import smtplib
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from flask import Flask, abort, logging, render_template, request, jsonify, session, redirect, g, url_for, flash
import csv
import sqlite3
import pandas as pd
import os
import random
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import secrets
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

app.secret_key = 'sdfguvh6678u8978'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mduke0511@gmail.com'
app.config['MAIL_PASSWORD'] = 'hmek gvgz izbg kumo'  # Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'mduke0511@gmail.com'

mail = Mail(app)

DATABASE = 'video_library.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = get_db()
    if db is not None:
        db.close()

# sending OTP
def send_otp(email):
    otp = random.randint(100000, 999999,)
    session['otp'] = otp
    session['email'] = email
    msg = Message("Your OTP for Verification", recipients=[email])
    msg.body = f"Your OTP is: {otp}. It is valid for 5 minutes."

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
        
def generate_token():
    return secrets.token_urlsafe(32)

otp_store = {}

# Route for the forgot password page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT email FROM students WHERE username = ? UNION SELECT email FROM teachers WHERE username = ?", (username_or_email, username_or_email))
        user_email_row = cursor.fetchone()

        if user_email_row:
            user_email = user_email_row[0]
            if send_otp(user_email):
                otp_store[user_email] = {
                    'otp': session['otp'],
                    'expiry': datetime.now() + timedelta(minutes=5)  # OTP expires in 5 minutes
                }

                flash("An OTP has been sent to your email.", "success")
                return redirect(url_for('reset_password_otp'))
            else:
                return redirect(url_for('forgot_password'))
        else:
            flash("User not found.", "danger")
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

# Route for the reset password with OTP page
@app.route('/reset_password_otp', methods=['GET', 'POST'])
def reset_password_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        username_or_email = session['email'] 

        if username_or_email in otp_store:
            stored_otp_data = otp_store[username_or_email]
            if stored_otp_data['otp'] == int(otp) and stored_otp_data['expiry'] > datetime.now():
                if new_password == confirm_password:
                    db = get_db()
                    cursor = db.cursor()
                    cursor.execute("UPDATE students SET password = ? WHERE email = ?",(new_password, username_or_email))
                    cursor.execute("UPDATE teachers SET password = ? WHERE email = ?",(new_password, username_or_email))
                    db.commit()

                    del otp_store[username_or_email]

                    flash("Your password has been reset.", "success")
                    return redirect(url_for('login'))
                else:
                    flash("Passwords do not match.", "danger")
            else:
                flash("Invalid or expired OTP.", "danger")
        else:
            flash("OTP not found.", "danger")

    return render_template('reset_password_otp.html')

@app.route('/store_rating', methods=['POST'])
def store_rating():
    try:
        data = request.get_json()
        print("Received Rating Data:", data)  
        required_fields = ["username", "branch", "subject", "unit", "video_url", "video_name", "rating"]
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400
        conn = sqlite3.connect("video_library.db")
        cursor = conn.cursor()

        # Check if the user already rated this video
        cursor.execute("SELECT * FROM video_ratings WHERE username = ? AND video_url = ?", 
                       (data['username'], data['video_url']))
        existing_rating = cursor.fetchone()

        if existing_rating:
            return jsonify({'error': 'User has already rated this video'}), 400

        # Insert new rating
        cursor.execute('''
            INSERT INTO video_ratings (username, branch, subject, unit, video_url, video_name, rating)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (data['username'], data['branch'], data['subject'], data['unit'], data['video_url'], data['video_name'],
              data['rating']))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Rating stored successfully!'}), 200

    except Exception as e:
        print("Error:", str(e))  
        return jsonify({'error': str(e)}), 500

# API to fetch rated videos
@app.route('/get_user_ratings/<username>', methods=['GET'])
def get_user_ratings(username):
    try:
        conn = sqlite3.connect("video_library.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT video_url FROM video_ratings WHERE username = ?", (username,))
        rated_videos = cursor.fetchall()
        
        conn.close()
        
        rated_videos = [video[0] for video in rated_videos]

        return jsonify({'rated_videos': rated_videos}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

CSV_FILE = 'alumni_data.csv'

@app.route('/update_alumni', methods=['POST'])
def update_alumni():
    updated_row = request.json['row']
    rows = []

    with open(CSV_FILE, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        headers = next(reader)
        for row in reader:
            if row[0] == updated_row[0]:  # Match by Name
                rows.append(updated_row)
            else:
                rows.append(row)

    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)

    return jsonify({'status': 'success'})


@app.route('/add_alumni', methods=['POST'])
def add_alumni():
    new_row = request.json['row']
    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(new_row)
    return jsonify({'status': 'added'})

@app.route('/check_duplicate', methods=['POST'])
def check_duplicate():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    roll = data.get('roll')
    teacher_id = data.get('teacher_id')

    db = get_db()
    cursor = db.cursor()

    # Check for existing username in both tables
    if username:
        cursor.execute("SELECT * FROM students WHERE username = ? UNION SELECT * FROM teachers WHERE username = ?", (username, username))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Username already taken"}), 400

    # Check for existing email in both tables
    if email:
        cursor.execute("SELECT * FROM students WHERE email = ? UNION SELECT * FROM teachers WHERE email = ?", (email, email))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Email already registered"}), 400

    # Check for existing roll number (only students)
    if roll:
        cursor.execute("SELECT * FROM students WHERE roll = ?", (roll,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Roll number already registered"}), 400

    # Check for existing teacher ID (only teachers)
    if teacher_id:
        cursor.execute("SELECT * FROM teachers WHERE teacher_id = ?", (teacher_id,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Teacher ID already registered"}), 400

    return jsonify({"status": "ok"}), 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        db = get_db()
        cursor = db.cursor()

        if role == "student":
            roll = request.form.get('roll', '').strip()
            if not roll:
                flash("Roll number is required for students", "danger")
                return render_template('register.html', otp_sent=False, form_data=request.form)
            teacher_id = "N/A"
        else:  # Teacher
            teacher_id = request.form.get('teacher_id', '').strip()
            if not teacher_id:
                flash("Teacher ID is required for teachers", "danger")
                return render_template('register.html', otp_sent=False, form_data=request.form)
            roll = "N/A"

        # Password Confirmation Check
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template('register.html', otp_sent=False, form_data=request.form)

        # Check for existing user in the correct table
        if role == "student":
            cursor.execute("SELECT username, email, roll FROM students WHERE username = ? OR email = ? OR roll = ?", 
                           (username, email, roll))
        else:
            cursor.execute("SELECT username, email, teacher_id FROM teachers WHERE username = ? OR email = ? OR teacher_id = ?", 
                           (username, email, teacher_id))

        existing_user = cursor.fetchone()
        if existing_user:
            flash("Username, Email, or ID already exists. Please try a different one!", "danger")
            return render_template('register.html', otp_sent=False, form_data=request.form)

        if send_otp(email):
            session['name'] = name
            session['username'] = username
            session['email'] = email
            session['roll'] = roll
            session['teacher_id'] = teacher_id
            session['role'] = role
            session['password'] = password

            flash("OTP Sent to your Email!", "success")
            return render_template('register.html', otp_sent=True, form_data=request.form)
        else:
            flash("Error sending OTP. Try again!", "danger")

    return render_template('register.html', otp_sent=False, form_data={})


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered_otp = request.form['otp']

    if 'otp' in session and session['otp'] == int(entered_otp):
        try:
            db = get_db()
            cursor = db.cursor()

            # Get Data from Session
            name = session.get('name', '')
            username = session.get('username', '')
            email = session.get('email', '')
            role = session.get('role', '')
            password = session.get('password', '')
            roll = session.get('roll')
            teacher_id = session.get('teacher_id')

            
            if not all([name, username, email, roll, role, password]):
                flash("Error: Some required data is missing!", "danger")
                return redirect(url_for('register'))

           

            if role == 'student':
                cursor.execute("INSERT INTO students (name, username, email, password, roll) VALUES (?, ?, ?, ?, ?)", (name, username, email, password, roll))
            elif role == 'teacher':
                cursor.execute("INSERT INTO teachers (name, username, email, password, teacher_id) VALUES (?, ?, ?, ?, ?)", (name, username, email, password, teacher_id))

            db.commit()

            session.clear()

            # flash("Email Verified Successfully! Account Created.", "success")
            return render_template('login.html')

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for('register'))

    else:
        flash("Invalid OTP. Try Again!", "danger")

       
        form_data = {
            'name': session.get('name', ''),
            'username': session.get('username', ''),
            'email': session.get('email', ''),
            'roll': session.get('roll', ''),
            'role': session.get('role', ''),
            'password': session.get('password', ''),
            'confirm_password': session.get('confirm_password', '')
        }
        return render_template('register.html', otp_sent=True, form_data=form_data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        db = get_db()
        cursor = db.cursor()

        if role == "student":
            roll = request.form.get('roll', '').strip()  # Get roll number
            cursor.execute("SELECT * FROM students WHERE username = ? AND password = ? AND roll = ?", 
                           (username, password, roll))
        elif role == "teacher":
            teacher_id = request.form.get('teacher_id', '').strip()  # Get teacher ID
            cursor.execute("SELECT * FROM teachers WHERE username = ? AND password = ? AND teacher_id = ?", 
                           (username, password, teacher_id))
        elif role == "admin":
            cursor.execute("SELECT * FROM admin WHERE username = ? AND password = ?", (username, password))
        else:
            flash("Invalid role selected", "danger")
            return redirect(url_for('login'))

        user = cursor.fetchone()

        if user:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = role

            # flash("Login successful!", "success")
            return redirect(url_for('home', username=username))
        else:
            flash("Invalid credentials! Please check your username, password, and ID.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/user_list')
def user_list():
    if 'role' not in session or (session['role'] != 'admin' and session['role'] != 'teacher'):
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('home'))

    db = get_db()
    cursor = db.cursor()

    # Fetch students
    cursor.execute("SELECT id, name, username, email, roll FROM students")
    students = cursor.fetchall()

    # Fetch teachers
    cursor.execute("SELECT id, name, username, email, teacher_id FROM teachers")
    teachers = cursor.fetchall()
    role = session.get('role')

    return render_template('user_list.html', students=students, teachers=teachers, role=role)

# route to fetch user data
@app.route('/get_users/<role>')
def get_users(role):
    if 'role' not in session or (session['role'] != 'admin' and session['role'] != 'teacher'):
        return jsonify({'error': 'You do not have permission to access this data.'}), 403
    db = get_db()
    cursor = db.cursor()
    search_term = request.args.get('search', '').lower()
    current_role = session.get('role')

    if role == 'student':
        cursor.execute("""
            SELECT id, name, username, email, roll FROM students
            WHERE LOWER(name) LIKE ? OR LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(roll) LIKE ?
        """, ('%' + search_term + '%', '%' + search_term + '%', '%' + search_term + '%', '%' + search_term + '%'))
        users = cursor.fetchall()
    elif role == 'teacher' and current_role == 'admin':
        cursor.execute("""
            SELECT id, name, username, email, teacher_id FROM teachers
            WHERE LOWER(name) LIKE ? OR LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(teacher_id) LIKE ?
        """, ('%' + search_term + '%', '%' + search_term + '%', '%' + search_term + '%', '%' + search_term + '%'))
        users = cursor.fetchall()
    elif role == 'teacher' and current_role == 'teacher':
        return jsonify({'error': 'You do not have permission to access this data.'}), 403
    else:
        return jsonify({'error': 'Invalid role'}), 400

    return jsonify(users)


@app.route('/all_data')
def all_data():
    # Check if user is logged in and has the correct role
    if 'role' not in session or session['role'] not in ['admin', 'teacher']: 
        abort(403) 
    username = session['username']  
    role = session.get('role')

    target_username = request.args.get('username')
    return render_template('all_data.html', username=target_username, role=role)

@app.route('/get_table_data/<table_name>')
def get_table_data(table_name):
    # Corrected permission check: Allow both admin and teacher
    if 'role' not in session or session['role'] not in ['admin', 'teacher']:
        return jsonify({'error': 'You do not have permission to access this data.'}), 403

    db = get_db()
    cursor = db.cursor()
    username = request.args.get('username') 

    valid_tables = ['quiz_progress', 'feedback', 'video_progress', 'video_ratings']
    if table_name not in valid_tables:
        return jsonify({'error': 'Invalid table name'}), 400

    if table_name == 'quiz_progress':
        columns_to_select = "username, branch, subject, unit, quiz_status, score, timestamp"
    elif table_name == 'feedback':
        columns_to_select = "username, branch, subject, unit, video_name, message, timestamp"
    elif table_name == 'video_progress':
        columns_to_select = "username, video_name, video_url, branch, subject, unit, status, timestamp"
    elif table_name == 'video_ratings':
        columns_to_select = "username, branch, subject, unit, video_url, video_name, rating"
    else: 
         return jsonify({'error': 'Table configuration missing'}), 500

    
    if username:
        cursor.execute(f"SELECT {columns_to_select} FROM {table_name} WHERE username = ?", (username,))
    else:
       
         return jsonify({'error': 'Username parameter required when accessing specific user data'}), 400
        


    data = cursor.fetchall()
    columns = columns_to_select.split(", ") 

    return jsonify({'data': data, 'columns': columns})

# route to send reply email
@app.route('/send_reply', methods=['POST'])
def send_reply():
    if 'role' not in session or session['role'] != 'admin':
        return jsonify({'error': 'You do not have permission to access this data.'}), 403
    try:
        data = request.get_json()
        username = data['username']
        reply_message = data['replyMessage']

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT email FROM students WHERE username = ? UNION SELECT email FROM teachers WHERE username = ?", (username, username))
        user_email_row = cursor.fetchone()

        if not user_email_row:
            return jsonify({'error': 'User not found'}), 404

        user_email = user_email_row[0]

        msg = Message("Reply to your feedback", recipients=[user_email])
        msg.body = f"Your feedback has been received and we have a reply for you:\n\n{reply_message}"
        mail.send(msg)

        return jsonify({'message': 'Reply sent successfully!'}), 200
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'error': 'Error sending email'}), 500

def get_db_connection():
    """Establishes a connection to the database."""
    conn = sqlite3.connect('video_library.db')
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@app.route('/delete_all_user_data/<username>', methods=['POST'])
def delete_all_user_data(username):
    """
    Deletes all data associated with a specific username across multiple tables.
    Ensures atomicity using a transaction.
    """
    logging.info(f"Attempting deletion for username: {username}")
    logging.info(f"Session role: {session.get('role')}")

    if 'role' not in session or session['role'] != 'admin':
        logging.warning(f"Unauthorized deletion attempt for username: {username} by session: {session.get('user_id', 'N/A')}")
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('user_list')) 

    tables_to_clear = [
        'quiz_progress',
        'feedback',
        'video_progress',
        'video_ratings',
        'students',
        'teachers',
        
    ]
    primary_tables = ['student', 'teacher'] 

    conn = None 
    try:
        conn = get_db_connection()
        
        with conn:
            cursor = conn.cursor()
            logging.info(f"Starting transaction to delete data for username: {username}")

            # 1. Delete from related tables
            for table in tables_to_clear:
                try:
                    logging.info(f"Deleting from '{table}' where username = '{username}'")
                    cursor.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
                    logging.info(f"Rows affected in '{table}': {cursor.rowcount}")
                except sqlite3.Error as e:
                   
                    logging.error(f"Error deleting from table '{table}' for username '{username}': {e}")
                  

            # 2. Delete from primary user tables (student/teacher)
            deleted_from_primary = False
            for table in primary_tables:
                 try:
                    logging.info(f"Attempting to delete from '{table}' where username = '{username}'")
                    cursor.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
                    rows_affected = cursor.rowcount
                    logging.info(f"Rows affected in '{table}': {rows_affected}")
                    if rows_affected > 0:
                        deleted_from_primary = True
                        
                 except sqlite3.Error as e:
                     logging.error(f"Error deleting from primary table '{table}' for username '{username}': {e}")
                    
            if not deleted_from_primary:
                 logging.warning(f"Username '{username}' not found in primary tables ({', '.join(primary_tables)}), but related data deletion was attempted.")


        logging.info(f"Successfully committed deletions for username: {username}")
        flash(f'Successfully deleted all data for user {username}.', 'success')

    except sqlite3.Error as e:
        
        logging.error(f"Database transaction failed for username '{username}': {e}")
        flash(f'Database error occurred while deleting data for {username}. Changes rolled back.', 'danger')
    except Exception as e:
        logging.error(f"An unexpected error occurred during deletion for {username}: {e}", exc_info=True) # Log traceback
        flash(f'An unexpected error occurred while deleting data for {username}.', 'danger')
    finally:
        if conn:
            conn.close()
            logging.info(f"Database connection closed for {username} deletion process.")

    return redirect(url_for('user_list'))

# --- Remember to display flashed messages in your template ---
# Example in your base layout (e.g., layout.html):
# {% with messages = get_flashed_messages(with_categories=true) %}
#   {% if messages %}
#     {% for category, message in messages %}
#       <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
#         {{ message }}
#         <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
#       </div>
#     {% endfor %}
#   {% endif %}
# {% endwith %}








def update_csv_row(filepath, row_index, updated_row, is_new):
    """Updates a row in a CSV file."""
    print(f"Updating CSV: {filepath}")
    print(f"Row Index: {row_index}")
    print(f"Updated Row: {updated_row}")
    print(f"Is New: {is_new}")
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            data = list(reader)
            print(f"Original Data: {data}")

        # Update the row
        if is_new:
            data.append(updated_row)
        else:
            data[int(row_index)] = updated_row
        print(f"Updated Data: {data}")

        with open(filepath, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=updated_row.keys())
            writer.writeheader()
            writer.writerows(data)

        return True
    except Exception as e:
        print(f"Error updating CSV: {e}")
        return False

@app.route('/update_data', methods=['POST'])
def update_data():
    """API endpoint to update a row in link_data.csv or quiz_data.csv."""
    data = request.get_json()
    print(f"Received Data: {data}")
    row_type = data['rowType']
    row_index = data['rowIndex']
    updated_row = data['updatedRow']
    is_new = data['isNew']

    if row_type == 'link_data':
        filepath = 'link_data.csv'
    elif row_type == 'quiz_data':
        filepath = 'quiz_data.csv'
    else:
        return jsonify({'error': 'Invalid row type'}), 400

    if update_csv_row(filepath, row_index, updated_row, is_new):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Failed to update data'}), 500

@app.route('/data')
def data():
    """Renders the data.html page with data from link_data.csv and quiz_data.csv."""
    link_data_path = 'link_data.csv'  
    quiz_data_path = 'quiz_data.csv'  

    try:
        with open(link_data_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            link_data = list(reader)  
    except FileNotFoundError:
        flash("Failed to load data from link_data.csv.", "danger")
        return redirect(url_for('home'))  

    try:
        with open(quiz_data_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            quiz_data = list(reader)
    except FileNotFoundError:
        flash("Failed to load data from quiz_data.csv.", "danger")
        return redirect(url_for('home'))
    username = session['username']  
    role = session.get('role')

    return render_template('data.html', link_data=link_data, quiz_data=quiz_data, role=role)



@app.route('/')
@app.route('/landing')
def landing():
    try:
        df = pd.read_csv('link_data.csv', encoding='utf-8')
        df.columns = df.columns.str.strip()  # Clean column names

        
        if 'BRANCH' in df.columns and 'SUBJECT' in df.columns:
            
            branch_subject_map = df.groupby('BRANCH')['SUBJECT'].unique().apply(list).to_dict()
        else:
            branch_subject_map = {}

        return render_template('landing.html', branch_subject_map=branch_subject_map)

    except Exception as e:
        return f"Error loading data: {e}"

  


@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))  

   
    username = session['username']  
    role = session.get('role')
    return render_template('home.html', username=username, role=role)




@app.route('/contactus', methods=['GET', 'POST'])
def message():
    data = load_csv_data()

    branches = sorted(set(row['BRANCH'] for row in data))
    subjects = sorted(set(row['SUBJECT'] for row in data))
    units = sorted(set(row['UNIT'] for row in data))
    videos = sorted(set(row['TITLE'] for row in data))

    branch_to_subjects = {
        branch: sorted(set(row['SUBJECT'] for row in data if row['BRANCH'] == branch)) for branch in branches}
    subject_to_units = {
        subject: sorted(set(row['UNIT'] for row in data if row['SUBJECT'] == subject)) for subject in subjects}
    unit_to_videos = {unit: sorted(set(row['TITLE'] for row in data if row['UNIT'] == unit)) for unit in units}

    if 'username' not in session:
        return redirect(url_for('login'))  

    username = session['username']  
    timestamp = datetime.now()

    if request.method == 'POST':
        selected_branch = request.form['branch']
        selected_subject = request.form['subject']
        selected_unit = request.form['unit']
        selected_video = request.form['video_name']
        message = request.form['message']

        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO feedback (username, branch, subject, unit, video_name, message, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, selected_branch, selected_subject, selected_unit, selected_video, message, timestamp))

        db.commit()

        message = "Your query has been submitted successfully"

        print(
            f"Branch: {selected_branch}, Subject: {selected_subject}, Unit: {selected_unit}, Video: {selected_video}, Message: {message}")

        return render_template('contactus.html', branches=branches, subjects=subjects, units=units, videos=videos,
                               branch_to_subjects=branch_to_subjects, subject_to_units=subject_to_units,
                               unit_to_videos=unit_to_videos, message=message)

    return render_template('contactus.html', branches=branches, subjects=subjects, units=units, videos=videos,
                           branch_to_subjects=branch_to_subjects, subject_to_units=subject_to_units,
                           unit_to_videos=unit_to_videos)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


def load_csv_data():
    data = []
    try:
        with open('link_data.csv', 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if all(row[key] not in (None, '', ' ') for key in row):
                    data.append(row)
    except UnicodeDecodeError:
        with open('link_data.csv', 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if all(row[key] not in (None, '', ' ') for key in row):
                    data.append(row)
    return data


@app.route('/index')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))  

    username = session['username']  
    data = load_csv_data()
    branches = sorted(set(item['BRANCH'] for item in data))
    
    role = session.get('role')

    return render_template('index.html', branches=branches, username=username, role=role)


@app.route('/get_subjects/<branch>')
def get_subjects(branch):
    data = load_csv_data()
    subjects = set(item['SUBJECT'] for item in data if item['BRANCH'] == branch)
    return jsonify(list(subjects))


@app.route('/get_units/<branch>/<subject>')
def get_units(branch, subject):
    data = load_csv_data()
    units = sorted(set(item['UNIT'] for item in data if item['BRANCH'] == branch and item['SUBJECT'] == subject))
    return jsonify(list(units))


@app.route('/get_videos/<branch>/<subject>/<unit>')
def get_videos(branch, subject, unit):
    data = load_csv_data()
    videos = [item for item in data if
              item['BRANCH'] == branch and item['SUBJECT'] == subject and item['UNIT'] == unit]
    return jsonify(videos)


@app.route('/video_player')
def video_player():
    video_url = request.args.get('video_url')  
    return render_template('video_player.html', video_url=video_url)


@app.route('/alumni')
def alumni():
    alumni_data = pd.read_csv('alumni_data.csv')
    alumni_list = alumni_data.to_dict(orient='records')
    username = session['username']  
    role = session.get('role')
    
    return render_template('alumni.html', alumni_list=alumni_list, role=role)


def load_quiz_data():
    with open("quiz_data.csv", "r") as file:
        reader = csv.DictReader(file, delimiter="\t")
        return [row for row in reader]


@app.route('/get_video_progress/<username>')
def get_video_progress(username):
    conn = sqlite3.connect('video_library.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT video_name, video_url, status, timestamp
        FROM video_progress
        WHERE username = ?
    ''', (username,))
    progress = cursor.fetchall()
    conn.close()

    return jsonify(
        [{'video_name': row[0], 'video_url': row[1], 'status': row[2], 'timestamp': row[3]} for row in progress])

@app.route('/store_video_progress', methods=['POST'])
def store_video_progress():
    if 'username' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    username = session['username']
    user_role = session.get('role') 

    if user_role not in ['teacher', 'admin']:
        try:
            data = request.get_json()  
            required_fields = ['video_name', 'video_url', 'branch', 'subject', 'unit']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields in request data'}), 400

            video_name = data['video_name']
            video_url = data['video_url']
            branch = data['branch']
            subject = data['subject']
            unit = data['unit']
            
            # Get additional progress tracking fields if available
            current_position = data.get('current_position', 0)
            duration = data.get('duration', 0)
            percent_complete = data.get('percent_complete', 0)
            status = data.get('status', 'In Progress')  # Default to 'In Progress' if not provided

            # Connect to database
            db = get_db()
            cursor = db.cursor()

            # Check if we already have a record for this video/user combination
            cursor.execute('''
                SELECT id, status, current_position FROM video_progress 
                WHERE username = ? AND video_url = ?
            ''', (username, video_url))
            
            existing_record = cursor.fetchone()
            
            if existing_record:
                record_id, existing_status, existing_position = existing_record
                
                # Only update if the new position is greater than the existing one
                # or if we're marking it as completed
                if current_position > existing_position or status == 'Completed':
                    cursor.execute('''
                        UPDATE video_progress 
                        SET status = ?, current_position = ?, duration = ?, percent_complete = ?, timestamp = CURRENT_TIMESTAMP 
                        WHERE id = ?
                    ''', (status, current_position, duration, percent_complete, record_id))
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO video_progress 
                    (username, video_name, video_url, branch, subject, unit, status, current_position, duration, percent_complete) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (username, video_name, video_url, branch, subject, unit, status, 
                       current_position, duration, percent_complete))
                
            db.commit() 

            print(f"Video progress saved for user: {username}, role: {user_role}, position: {current_position}, status: {status}") 
            return jsonify({
                'message': 'Progress saved successfully!',
                'position': current_position,
                'percent_complete': percent_complete,
                'status': status
            }), 200

        except sqlite3.Error as db_err: 
            print(f"Database error storing video progress for {username}: {db_err}")
            return jsonify({'error': f'Database error: {db_err}'}), 500
        except Exception as e: 
            print(f"Error storing video progress for {username}: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        print(f"Video progress not saved for role: {user_role}, user: {username}")
        return jsonify({'message': 'Progress not stored for this role.'}), 200



@app.route('/mcq_test', methods=["GET", "POST"])
def mcq_test():
    
    api = request.args.get('branch')
    branch, subject, unit = api.split(',')

    quiz_data = load_quiz_data()

    processed_data = []

   
    for entry in quiz_data:
        for key, value in entry.items():
            columns = key.split(',')
            values = value.split(',')

            question_data = dict(zip(columns, values))

            processed_data.append(question_data)

    processed_data = pd.DataFrame(processed_data)

    print(f"branch: {branch}")
    print(f"subject: {subject}")
    print(f"unit: {unit}")

    processed_data = processed_data[(processed_data['BRANCH']==branch) & (processed_data['SUBJECT']==subject) & (processed_data['UNIT']==unit)]
    processed_data = processed_data.drop(columns=['BRANCH1', 'SUBJECT', 'YEAR', 'UNIT', 'BRANCH'])

    quiz_data = processed_data.to_dict(orient="records")

    print(quiz_data)
    return render_template("quiz.html", quiz_data=quiz_data, api=api)




@app.route('/result')
def result():
    score = request.args.get('score')  
    api = request.args.get('api')
    branch, subject, unit = api.split(',')

    quiz_status = 'Completed'
    timestamp = datetime.now()

    if 'username' not in session:
        flash("You must be logged in to save quiz results.", "warning")
        return redirect(url_for('login'))  

    username = session['username']  
    user_role = session.get('role') 

    if user_role not in ['teacher', 'admin']: 
        try:
           
            conn = sqlite3.connect('video_library.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quiz_progress (username, branch, subject, unit, quiz_status, score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, branch, subject, unit, quiz_status, score, timestamp))
            conn.commit()
            conn.close() 
            print(f"Quiz progress saved for user: {username}, role: {user_role}")
        except Exception as e:
            print(f"Error saving quiz progress for user {username}: {e}") 
            flash("An error occurred while saving your quiz progress.", "danger")
            
    else:
        print(f"Quiz progress not saved for role: {user_role}, user: {username}") 

    return render_template('result.html', score=score)




# Load video progress data from SQLite
def load_progress_data():
    try:
        conn = sqlite3.connect('video_library.db')
        query = "SELECT * FROM video_progress"
        progress_data = pd.read_sql_query(query, conn)
        conn.close()
        return progress_data.drop_duplicates()  
    except Exception as e:
        print(f"Error loading progress data: {e}")
        return pd.DataFrame()

# Route for the dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/progress_data', methods=['GET'])
def progress_data():

    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']  

    total_data = load_csv_data()
    progress_data = load_progress_data()

    df = pd.DataFrame(total_data)

    df_filtered = df
    df_filtered = df_filtered.drop(columns=['Video URL', 'BRANCH1', 'CHANNEL', 'ID', 'YEAR'])\
        .rename(columns={'SUBJECT': 'subject', 'Video URL': 'video_url', 'TITLE': 'video_name', 'UNIT': 'unit', 'BRANCH': 'branch'})


    videos_per_subject_unit_total = (
        df_filtered.groupby(['subject', 'unit', 'branch'])['video_name'].count().reset_index(name='videos_per_subject_unit_total')
    )

    progress_data_fitered = progress_data[progress_data['username'] == username]

    progress_data_fitered = progress_data_fitered.drop(columns=['id', 'video_url', 'status'])

    df_progress = (
        progress_data_fitered.groupby(["username", "video_name", "branch", "subject", "unit"], as_index=False)
        .agg({"timestamp": "max"})
    )

    df_progress['timestamp'] = pd.to_datetime(df_progress['timestamp'])

    videos_per_subject_unit = (
        df_progress.groupby(['subject', 'unit', 'branch'])['video_name'].count().reset_index(name='videos_per_subject_unit_progress')
    )

    merged_videos = pd.merge(videos_per_subject_unit, videos_per_subject_unit_total, on=['subject', 'branch', 'unit'], how='inner')

    merged_videos_per_subject = pd.merge(videos_per_subject_unit, videos_per_subject_unit_total, on=['subject', 'branch', 'unit'], how='inner')\
        .groupby(['subject', 'branch'], as_index=False)[['videos_per_subject_unit_progress', 'videos_per_subject_unit_total']].sum()

    merged_videos_per_subject = merged_videos_per_subject.rename(columns={
        'videos_per_subject_unit_progress': 'videos_per_subject_unit_progress_subject',
        'videos_per_subject_unit_total': 'videos_per_subject_unit_total_subject'
    })

    merged_videos['progress_percentage_unit'] = (merged_videos['videos_per_subject_unit_progress'] / merged_videos['videos_per_subject_unit_total']) * 100
    merged_videos_per_subject['progress_percentage_subject'] = (merged_videos_per_subject['videos_per_subject_unit_progress_subject'] / merged_videos_per_subject['videos_per_subject_unit_total_subject']) * 100

    merged_df = pd.merge(merged_videos, merged_videos_per_subject, on=['subject', 'branch'], suffixes=('_subject', '_unit'))

    branch_dict = {}

    for (subject, branch), group in merged_df.groupby(['subject', 'branch']):
        unit_progress = group[['unit', 'progress_percentage_unit']].to_dict(orient='records')
        
        subject_data = {
            'SUBJECT': subject,
            'progress_percentage': group['progress_percentage_subject'].iloc[0],  # Same for all units
            'unit_progress': unit_progress
        }
        
        if branch in branch_dict:
            branch_dict[branch]['subjects'].append(subject_data)
        else:
            branch_dict[branch] = {
                'branch': branch,
                'subjects': [subject_data]
            }

    result = list(branch_dict.values())

    print(result)
    return jsonify(result)


# Route for the quiz analytics dashboard
@app.route('/quiz_analytics')
def quiz_analytics():
    if 'role' not in session or session['role'] not in ['admin', 'teacher']:
        flash('Access denied. You need appropriate permissions to view this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('quiz_analytics.html', role=session.get('role'), username=session.get('username'))

# Route for dashboard data - a direct route for all_data.html
@app.route('/dashboard_data')
def dashboard_data():
    try:
        # Get username parameter
        username = request.args.get('username')
        if not username:
            return jsonify({'error': 'Username parameter is required'}), 400
            
        dashboard_result = {
            'quiz_data': [],
            'video_data': [],
            'rating_data': []
        }
        
        # Connect to database
        conn = sqlite3.connect('video_library.db')
        
        # 1. Get quiz_progress data
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quiz_progress WHERE username = ?", (username,))
            quiz_columns = [desc[0] for desc in cursor.description]  
            quiz_rows = cursor.fetchall()
            
            dashboard_result['quiz_data'] = {
                'columns': quiz_columns,
                'data': [list(row) for row in quiz_rows]
            }
        except Exception as e:
            print(f"Error getting quiz data: {e}")
            dashboard_result['quiz_data'] = {'error': str(e)}
        
        # 2. Get video_progress data
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM video_progress WHERE username = ?", (username,))
            video_columns = [desc[0] for desc in cursor.description]
            video_rows = cursor.fetchall()
            
            dashboard_result['video_data'] = {
                'columns': video_columns,
                'data': [list(row) for row in video_rows]
            }
        except Exception as e:
            print(f"Error getting video data: {e}")
            dashboard_result['video_data'] = {'error': str(e)}
        
        # 3. Get video_ratings data
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM video_ratings WHERE username = ?", (username,))
            rating_columns = [desc[0] for desc in cursor.description]
            rating_rows = cursor.fetchall()
            
            dashboard_result['rating_data'] = {
                'columns': rating_columns,
                'data': [list(row) for row in rating_rows]
            }
        except Exception as e:
            print(f"Error getting rating data: {e}")
            dashboard_result['rating_data'] = {'error': str(e)}
        
        conn.close()
        return jsonify(dashboard_result)
    
    except Exception as e:
        print(f"Error fetching dashboard data: {e}")
        return jsonify({'error': f'Error fetching dashboard data: {str(e)}'}), 500

# Get filter options for quiz analytics
@app.route('/quiz_filter_options', methods=['GET'])
def quiz_filter_options():
    # Fetch unique usernames, branches, and subjects from the database
    try:
        conn = sqlite3.connect('video_library.db')
        cursor = conn.cursor()
        
        # Get unique usernames
        cursor.execute('''
            SELECT DISTINCT username FROM quiz_progress
            WHERE username IS NOT NULL AND username != ''
            ORDER BY username
        ''')
        usernames = [row[0] for row in cursor.fetchall()]
        
        # Get unique branches
        cursor.execute('''
            SELECT DISTINCT branch FROM quiz_progress
            WHERE branch IS NOT NULL AND branch != ''
            ORDER BY branch
        ''')
        branches = [row[0] for row in cursor.fetchall()]
        
        # Get unique subjects
        cursor.execute('''
            SELECT DISTINCT subject FROM quiz_progress
            WHERE subject IS NOT NULL AND subject != ''
            ORDER BY subject
        ''')
        subjects = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'usernames': usernames,
            'branches': branches,
            'subjects': subjects
        })
        
    except Exception as e:
        print(f"Error fetching filter options: {e}")
        return jsonify({'error': str(e)}), 500

# Get subjects for a specific branch
@app.route('/quiz_subjects', methods=['GET'])
def quiz_subjects():
    try:
        branch = request.args.get('branch')
        if not branch:
            return jsonify({'error': 'Branch parameter is required'}), 400
            
        conn = sqlite3.connect('video_library.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT subject FROM quiz_progress WHERE branch = ? ORDER BY subject", (branch,))
        subjects = [row[0] for row in cursor.fetchall() if row[0]]
        
        conn.close()
        
        return jsonify({'subjects': subjects})
    except Exception as e:
        print(f"Error fetching subjects: {e}")
        return jsonify({'error': str(e)}), 500

# Get units for a specific branch and subject
@app.route('/quiz_units', methods=['GET'])
def quiz_units():
    try:
        branch = request.args.get('branch')
        subject = request.args.get('subject')
        
        if not branch or not subject:
            return jsonify({'error': 'Branch and subject parameters are required'}), 400
            
        conn = sqlite3.connect('video_library.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT unit FROM quiz_progress WHERE branch = ? AND subject = ? ORDER BY unit", (branch, subject))
        units = [row[0] for row in cursor.fetchall() if row[0]]
        
        conn.close()
        
        return jsonify({'units': units})
    except Exception as e:
        print(f"Error fetching units: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/quiz_performance_data', methods=['GET'])
def quiz_performance_data():
    try:
        # Get filter parameters
        username = request.args.get('username')
        branch = request.args.get('branch')
        subject = request.args.get('subject')
        unit = request.args.get('unit')
        
        # Build query and parameters
        query = "SELECT * FROM quiz_progress WHERE 1=1"
        params = []
        
        if username:
            query += " AND username = ?"
            params.append(username)
            
        if branch:
            query += " AND branch = ?"
            params.append(branch)
        
        if subject:
            query += " AND subject = ?"
            params.append(subject)
        
        if unit:
            query += " AND unit = ?"
            params.append(unit)
        
        # Connect to database
        conn = sqlite3.connect('video_library.db')
        cursor = conn.cursor()
        
        # Execute query
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        rows = cursor.fetchall()
        
        # Convert to list of dictionaries
        results = []
        for row in rows:
            result = {}
            for i, column in enumerate(columns):
                result[column] = row[i]
            results.append(result)
        
        # Calculate summary statistics
        total_quizzes = len(results)
        avg_score = 0
        min_score = 100
        max_score = 0
        passing_count = 0  # 60% threshold
        passing_count_33 = 0  # 33% threshold
        score_distribution = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
        
        if total_quizzes > 0:
            # Calculate average, min, max, and passing scores
            scores = []
            for result in results:
                if result['score'] is not None:
                    score_value = result['score']
                    # Try to extract percentage from formatted string
                    if isinstance(score_value, str) and '(' in score_value:
                        try:
                            # Extract percentage value from the string
                            percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                            scores.append(float(percentage_match))
                        except (IndexError, ValueError):
                            # Skip invalid values
                            pass
                    else:
                        # Try direct conversion
                        try:
                            scores.append(float(score_value))
                        except (TypeError, ValueError):
                            # Skip invalid values
                            pass
            if scores:
                avg_score = sum(scores) / len(scores)
                min_score = min(scores)
                max_score = max(scores)
                passing_count = sum(1 for score in scores if score >= 60)  # 60% as passing threshold
                passing_count_33 = sum(1 for score in scores if score >= 33)  # 33% as passing threshold
            
            # Calculate score distribution
            for result in results:
                # Handle formatted score strings like '2/3 (66.67%)'  
                score_value = result['score']
                if score_value is not None:
                    # Try to extract percentage from formatted string if it contains parentheses
                    if isinstance(score_value, str) and '(' in score_value:
                        try:
                            # Extract percentage value from the string
                            percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                            score = float(percentage_match)
                        except (IndexError, ValueError):
                            # If extraction fails, default to 0
                            score = 0
                    else:
                        # Try direct conversion or default to 0
                        try:
                            score = float(score_value)
                        except (TypeError, ValueError):
                            score = 0
                else:
                    score = 0
                if score <= 20:
                    score_distribution["0-20"] += 1
                elif score <= 40:
                    score_distribution["21-40"] += 1
                elif score <= 60:
                    score_distribution["41-60"] += 1
                elif score <= 80:
                    score_distribution["61-80"] += 1
                else:
                    score_distribution["81-100"] += 1
        
        # Calculate subject performance
        subject_performance = {}
        for result in results:
            subject_name = result['subject']
            
            # Handle formatted score strings
            score_value = result['score']
            if score_value is not None:
                # Try to extract percentage from formatted string
                if isinstance(score_value, str) and '(' in score_value:
                    try:
                        # Extract percentage value from the string
                        percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                        score = float(percentage_match)
                    except (IndexError, ValueError):
                        score = 0
                else:
                    # Try direct conversion
                    try:
                        score = float(score_value)
                    except (TypeError, ValueError):
                        score = 0
            else:
                score = 0
            
            if subject_name not in subject_performance:
                subject_performance[subject_name] = {'total': 0, 'sum': 0}
            
            subject_performance[subject_name]['total'] += 1
            subject_performance[subject_name]['sum'] += score
        
        subject_averages = {}
        for subject_name, data in subject_performance.items():
            if data['total'] > 0:
                subject_averages[subject_name] = data['sum'] / data['total']
        
        # Calculate unit comparison
        unit_performance = {}
        for result in results:
            unit_name = result['unit']
            
            # Handle formatted score strings
            score_value = result['score']
            if score_value is not None:
                # Try to extract percentage from formatted string
                if isinstance(score_value, str) and '(' in score_value:
                    try:
                        # Extract percentage value from the string
                        percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                        score = float(percentage_match)
                    except (IndexError, ValueError):
                        score = 0
                else:
                    # Try direct conversion
                    try:
                        score = float(score_value)
                    except (TypeError, ValueError):
                        score = 0
            else:
                score = 0
            
            if unit_name not in unit_performance:
                unit_performance[unit_name] = {'total': 0, 'sum': 0}
            
            unit_performance[unit_name]['total'] += 1
            unit_performance[unit_name]['sum'] += score
        
        unit_averages = {}
        for unit_name, data in unit_performance.items():
            if data['total'] > 0:
                unit_averages[unit_name] = data['sum'] / data['total']
        
        # Calculate performance trend (monthly averages)
        monthly_performance = {}
        for result in results:
            if result['timestamp']:
                date_key = result['timestamp'][:7]  # YYYY-MM format
                # Handle formatted score strings like '2/3 (66.67%)'  
                score_value = result['score']
                if score_value is not None:
                    # Try to extract percentage from formatted string if it contains parentheses
                    if isinstance(score_value, str) and '(' in score_value:
                        try:
                            # Extract percentage value from the string
                            percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                            score = float(percentage_match)
                        except (IndexError, ValueError):
                            # If extraction fails, default to 0
                            score = 0
                    else:
                        # Try direct conversion or default to 0
                        try:
                            score = float(score_value)
                        except (TypeError, ValueError):
                            score = 0
                else:
                    score = 0
                
                if date_key not in monthly_performance:
                    monthly_performance[date_key] = {'total': 0, 'sum': 0}
                
                monthly_performance[date_key]['total'] += 1
                monthly_performance[date_key]['sum'] += score
        
        trend_dates = sorted(monthly_performance.keys())
        trend_scores = [monthly_performance[date]['sum'] / monthly_performance[date]['total'] 
                        for date in trend_dates if monthly_performance[date]['total'] > 0]
        
        # Prepare detailed data showing individual quiz attempts with user information
        detailed_data = []
        
        for result in results:
            # Process score value to ensure it's in numeric format
            score_value = result['score']
            score_numeric = None
            
            if score_value is not None:
                # Try to extract percentage from formatted string
                if isinstance(score_value, str) and '(' in score_value:
                    try:
                        # Extract percentage value from the string like "2/3 (66.67%)"
                        percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                        score_numeric = float(percentage_match)
                    except (IndexError, ValueError):
                        score_numeric = 0
                else:
                    # Try direct conversion
                    try:
                        score_numeric = float(score_value)
                    except (TypeError, ValueError):
                        score_numeric = 0
            else:
                score_numeric = 0
            
            # Format the score for display
            formatted_score = f"{score_numeric:.1f}"
            
            # Add data for each individual quiz attempt
            detailed_data.append({
                'username': result['username'],
                'branch': result['branch'],
                'subject': result['subject'],
                'unit': result['unit'],
                'score': formatted_score,
                'timestamp': result['timestamp']
            })
        
        # Format response
        response = {
            'summary': {
                'total_quizzes': total_quizzes,
                'avg_score': avg_score,
                'min_score': min_score if total_quizzes > 0 else 0,
                'max_score': max_score if total_quizzes > 0 else 0,
                'pass_rate': (passing_count / total_quizzes * 100) if total_quizzes > 0 else 0,
                'pass_rate_33': (passing_count_33 / total_quizzes * 100) if total_quizzes > 0 else 0
            },
            'score_distribution': {
                'labels': list(score_distribution.keys()),
                'data': list(score_distribution.values())
            },
            'subject_performance': {
                'subjects': list(subject_averages.keys()),
                'averages': list(subject_averages.values())
            },
            'unit_comparison': {
                'units': list(unit_averages.keys()),
                'scores': list(unit_averages.values())
            },
            'performance_trend': {
                'dates': trend_dates,
                'scores': trend_scores
            },
            'detailed_data': detailed_data
        }
        
        conn.close()
        return jsonify(response)
        
    except Exception as e:
        print(f"Error generating quiz performance data: {e}")
        return jsonify({'error': str(e)}), 500
        
        for record in quiz_records:
            # Convert to dictionary with column names
            quiz_record = dict(zip(columns, record))
            
            branch = quiz_record['branch']
            subject = quiz_record['subject']
            unit = quiz_record['unit']
            score = float(quiz_record['score'])
            
            # Initialize branch if needed
            if branch not in branch_dict:
                branch_dict[branch] = {
                    'branch': branch,
                    'subjects': {}
                }
            
            # Initialize subject if needed
            if subject not in branch_dict[branch]['subjects']:
                branch_dict[branch]['subjects'][subject] = {
                    'SUBJECT': subject,
                    'quiz_count': 0,
                    'total_score': 0,
                    'average_score': 0,
                    'unit_scores': {}
                }
            
            # Update subject data
            branch_dict[branch]['subjects'][subject]['quiz_count'] += 1
            branch_dict[branch]['subjects'][subject]['total_score'] += score
            
            # Calculate average
            quiz_count = branch_dict[branch]['subjects'][subject]['quiz_count']
            total_score = branch_dict[branch]['subjects'][subject]['total_score']
            branch_dict[branch]['subjects'][subject]['average_score'] = round(total_score / quiz_count, 1)
            
            # Initialize unit if needed
            if unit not in branch_dict[branch]['subjects'][subject]['unit_scores']:
                branch_dict[branch]['subjects'][subject]['unit_scores'][unit] = {
                    'unit': unit,
                    'score_sum': 0,
                    'count': 0,
                    'score': 0
                }
            
            # Update unit data
            branch_dict[branch]['subjects'][subject]['unit_scores'][unit]['score_sum'] += score
            branch_dict[branch]['subjects'][subject]['unit_scores'][unit]['count'] += 1
            
            # Calculate unit average score
            unit_count = branch_dict[branch]['subjects'][subject]['unit_scores'][unit]['count']
            unit_sum = branch_dict[branch]['subjects'][subject]['unit_scores'][unit]['score_sum']
            branch_dict[branch]['subjects'][subject]['unit_scores'][unit]['score'] = round(unit_sum / unit_count, 1)
        
        # Convert dictionary structure to the expected format for the frontend
        result = []
        for branch_name, branch_data in branch_dict.items():
            # Convert subjects dict to list and sort by average score
            subjects_list = list(branch_data['subjects'].values())
            for subject in subjects_list:
                # Convert unit_scores dict to list
                subject['unit_scores'] = list(subject['unit_scores'].values())
                # Sort units by name
                subject['unit_scores'].sort(key=lambda x: x['unit'])
            
            # Sort subjects by average score in descending order
            subjects_list.sort(key=lambda x: x['average_score'], reverse=True)
            
            # Add to result
            result.append({
                'branch': branch_name,
                'subjects': subjects_list
            })
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error getting quiz performance data: {e}")
        return jsonify([])

# Student Quiz Analytics API
@app.route('/student_quiz_analytics', methods=['GET'])
def student_quiz_analytics():
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({'error': 'Username parameter is required'}), 400
            
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Fetch all quiz results for this student
        cursor.execute('''
            SELECT * FROM quiz_progress 
            WHERE username = ? 
            ORDER BY timestamp DESC
        ''', (username,))
        
        results = [dict(row) for row in cursor.fetchall()]
        
        if not results:
            return jsonify({
                'total_quizzes': 0,
                'avg_score': 0,
                'min_score': 0,
                'pass_rate': 0,
                'subject_scores': [],
                'recent_quizzes': []
            })
            
        # Calculate summary statistics
        total_quizzes = len(results)
        scores = []
        passing_count = 0
        
        # Subject performance tracking
        subjects = {}
        
        for result in results:
            # Process score value to ensure it's in numeric format
            score_value = result['score']
            score_numeric = None
            
            if score_value is not None:
                # Try to extract percentage from formatted string
                if isinstance(score_value, str) and '(' in score_value:
                    try:
                        # Extract percentage value from the string like "2/3 (66.67%)"
                        percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                        score_numeric = float(percentage_match)
                    except (IndexError, ValueError):
                        score_numeric = 0
                else:
                    # Try direct conversion
                    try:
                        score_numeric = float(score_value)
                    except (TypeError, ValueError):
                        score_numeric = 0
            else:
                score_numeric = 0
                
            scores.append(score_numeric)
            
            # Count passing scores (≥ 33%)
            if score_numeric >= 33:
                passing_count += 1
                
            # Track subject performance
            subject = result['subject']
            if subject not in subjects:
                subjects[subject] = {
                    'total': 0,
                    'sum': 0
                }
                
            subjects[subject]['total'] += 1
            subjects[subject]['sum'] += score_numeric
        
        # Calculate averages by subject
        subject_scores = []
        for subject, data in subjects.items():
            if data['total'] > 0:
                subject_scores.append({
                    'subject': subject,
                    'avg_score': round(data['sum'] / data['total'], 1)
                })
                
        # Sort by subject name
        subject_scores.sort(key=lambda x: x['subject'])
        
        # Format recent quizzes for display
        recent_quizzes = []
        for result in results[:10]:  # Get the 10 most recent quizzes
            score_value = result['score']
            score_numeric = 0
            
            if score_value is not None:
                if isinstance(score_value, str) and '(' in score_value:
                    try:
                        percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                        score_numeric = float(percentage_match)
                    except (IndexError, ValueError):
                        score_numeric = 0
                else:
                    try:
                        score_numeric = float(score_value)
                    except (TypeError, ValueError):
                        score_numeric = 0
            
            recent_quizzes.append({
                'timestamp': result['timestamp'],
                'subject': result['subject'],
                'unit': result['unit'],
                'score': round(score_numeric, 1)
            })
        
        # Calculate summary statistics
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        min_score = round(min(scores), 1) if scores else 0
        pass_rate = round((passing_count / total_quizzes) * 100, 1) if total_quizzes > 0 else 0
        
        # Get class average for comparison
        class_avg_score = 0
        try:
            # Fetch all quiz scores excluding this student
            cursor.execute('''
                SELECT score FROM quiz_progress 
                WHERE username != ? 
            ''', (username,))
            
            class_results = cursor.fetchall()
            class_scores = []
            
            for result in class_results:
                score_value = result['score']
                score_numeric = None
                
                if score_value is not None:
                    # Try to extract percentage from formatted string
                    if isinstance(score_value, str) and '(' in score_value:
                        try:
                            percentage_match = score_value.split('(')[1].split(')')[0].replace('%', '')
                            score_numeric = float(percentage_match)
                        except (IndexError, ValueError):
                            score_numeric = 0
                    else:
                        # Try direct conversion
                        try:
                            score_numeric = float(score_value)
                        except (TypeError, ValueError):
                            score_numeric = 0
                else:
                    score_numeric = 0
                    
                class_scores.append(score_numeric)
            
            # Calculate class average
            class_avg_score = round(sum(class_scores) / len(class_scores), 1) if class_scores else 0
        except Exception as e:
            print(f"Error calculating class average: {e}")
        
        response = {
            'total_quizzes': total_quizzes,
            'avg_score': avg_score,
            'min_score': min_score,
            'pass_rate': pass_rate,
            'subject_scores': subject_scores,
            'recent_quizzes': recent_quizzes,
            'class_avg_score': class_avg_score
        }
        
        conn.close()
        return jsonify(response)
        
    except Exception as e:
        print(f"Error generating student quiz analytics: {e}")
        return jsonify({'error': str(e)}), 500

# Student Video Analytics API
@app.route('/student_video_analytics', methods=['GET'])
def student_video_analytics():
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({'error': 'Username parameter is required'}), 400
            
        conn = sqlite3.connect('video_library.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Fetch all video progress for this student
        cursor.execute('''
            SELECT * FROM video_progress 
            WHERE username = ? 
            ORDER BY timestamp DESC
        ''', (username,))
        
        results = [dict(row) for row in cursor.fetchall()]
        
        if not results:
            return jsonify({
                'total_videos': 0,
                'completed_videos': 0,
                'avg_completion': 0,
                'subject_completion': [],
                'recent_videos': []
            })
            
        # Calculate summary statistics
        total_videos = len(results)
        completed_videos = sum(1 for r in results if r['status'] == 'Completed')
        
        # Calculate average completion percentage across all videos
        completion_percentages = []
        for result in results:
            percent = result.get('percent_complete', 0)
            if percent is None:
                percent = 0
            elif isinstance(percent, str):
                try:
                    percent = float(percent.strip('%'))
                except ValueError:
                    percent = 0
            completion_percentages.append(percent)
            
        avg_completion = round(sum(completion_percentages) / len(completion_percentages), 1) if completion_percentages else 0
        
        # Branch, subject, and unit completion tracking
        branches = {}
        subjects = {}
        units = {}
        
        for result in results:
            # Extract data
            branch = result.get('branch', 'Unknown')
            subject = result.get('subject', 'Unknown')
            unit = result.get('unit', 'Unknown')
            video_name = result.get('video_name', 'Unknown')
            
            # Get completion percentage
            percent = result.get('percent_complete', 0)
            if percent is None:
                percent = 0
            elif isinstance(percent, str):
                try:
                    percent = float(percent.strip('%'))
                except ValueError:
                    percent = 0
            
            # Track by subject
            if subject not in subjects:
                subjects[subject] = {
                    'total': 0,
                    'sum': 0
                }
            subjects[subject]['total'] += 1
            subjects[subject]['sum'] += percent
            
            # Track by branch
            if branch not in branches:
                branches[branch] = {}
            if subject not in branches[branch]:
                branches[branch][subject] = {
                    'total': 0,
                    'sum': 0
                }
            branches[branch][subject]['total'] += 1
            branches[branch][subject]['sum'] += percent
            
            # Track by unit
            unit_key = f"{branch}|{subject}|{unit}"
            if unit_key not in units:
                units[unit_key] = {
                    'branch': branch,
                    'subject': subject,
                    'unit': unit,
                    'videos': {}
                }
            
            if video_name not in units[unit_key]['videos']:
                units[unit_key]['videos'][video_name] = {
                    'completion_percentage': percent,
                    'timestamp': result.get('timestamp')
                }
        
        # Calculate averages by subject
        subject_completion = []
        for subject, data in subjects.items():
            if data['total'] > 0:
                subject_completion.append({
                    'subject': subject,
                    'avg_completion': round(data['sum'] / data['total'], 1)
                })
        
        # Calculate by branch and subject
        branch_subject_completion = []
        for branch, branch_data in branches.items():
            for subject, data in branch_data.items():
                if data['total'] > 0:
                    branch_subject_completion.append({
                        'branch': branch,
                        'subject': subject,
                        'avg_completion': round(data['sum'] / data['total'], 1)
                    })
        
        # Process unit data for chart display
        unit_progress = []
        for unit_key, unit_data in units.items():
            for video_name, video_data in unit_data['videos'].items():
                unit_progress.append({
                    'branch': unit_data['branch'],
                    'subject': unit_data['subject'],
                    'unit': unit_data['unit'],
                    'video_title': video_name,
                    'completion_percentage': video_data['completion_percentage']
                })
        
        # Sort by subject name
        subject_completion.sort(key=lambda x: x['subject'])
        branch_subject_completion.sort(key=lambda x: (x['branch'], x['subject']))
        
        # Format recent videos for display
        recent_videos = []
        for result in results[:10]:  # Get the 10 most recent videos
            # Get completion percentage
            percent = result.get('percent_complete', 0)
            if percent is None:
                percent = 0
            elif isinstance(percent, str):
                try:
                    percent = float(percent.strip('%'))
                except ValueError:
                    percent = 0
                    
            recent_videos.append({
                'timestamp': result['timestamp'],
                'video_name': result['video_name'],
                'subject': result['subject'],
                'percent_complete': round(percent, 1),
                'status': result['status']
            })
        
        response = {
            'total_videos': total_videos,
            'completed_videos': completed_videos,
            'avg_completion': avg_completion,
            'subject_completion': branch_subject_completion,  # Using enhanced data with branch info
            'recent_videos': recent_videos,
            'unit_progress': unit_progress  # Adding unit progress data for charts
        }
        
        conn.close()
        return jsonify(response)
        
    except Exception as e:
        print(f"Error generating student video analytics: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':

    app.run(debug=True)
