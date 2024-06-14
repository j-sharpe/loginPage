from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_session import Session
from cachelib import FileSystemCache
from flask_bcrypt import Bcrypt
from email_validator import validate_email, EmailNotValidError
from twilio.rest import Client
import sqlite3, os


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SESSION_TYPE'] = 'cachelib'
app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir='flask_session_cache', threshold=500)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
server_session = Session(app)

account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)


@app.route('/', methods=['GET', 'POST'])
def index():
    if session.get('email') != None:
        return redirect(url_for('welcome'))

    if request.method == "POST":

        try:
            email_info = validate_email(request.form.get('userEmail', ''), check_deliverability=False)
        except EmailNotValidError as e:
            print(str(e))
            flash("Invalid Email Address.")
            return redirect(url_for('index'))

        user_exists = check_user_exists(email_info.normalized)

        if user_exists == 0:
            flash("No Account Linked to this Email. Please sign-up for an account.")
            return render_template('base.html', TestLogic=request.form.get('userEmail'))

        validate_password = check_password()

        if not validate_password:
            flash("Incorrect Password.")
            return render_template('base.html', TestLogic=validate_password)

        session['email'] = request.form.get('userEmail', '')
        return redirect(url_for('welcome'))

    return render_template('base.html', TestLogic="unknown")

@app.route('/welcome')
def welcome():
    print(session)
    if session.get('email') == None:
        flash("Please Login to view other pages.")
        return redirect(url_for('index'))
    return render_template('welcome.html', EMail=session['email'])

@app.route('/logout')
def logout():
    flash("You have been logged out.")
    session.pop('email')
    return redirect(url_for('index'))

@app.route('/verify-new-user', methods = ['POST', 'GET'])
def verify_new_user():

    if request.method == 'POST':

        try:
            email_info = validate_email(request.form.get('newAcctEmail', ''), check_deliverability=False)
        except EmailNotValidError as e:
            print(str(e))
            flash("Invalid Email Address.")
            return redirect(url_for('verify_new_user'))

        user_exists = check_user_exists(email_info.normalized)

        if user_exists == 1:
            flash("An account is already linked to this email. Please login.")
            return redirect(url_for('verify_new_user'))

        verification = client.verify\
                            .v2\
                            .services('VA4f40ef1d760fc1d05ae1f3b5fec96f19')\
                            .verifications\
                            .create(channel_configuration={
                                'substitutions': {
                                    'localhost': 'http://127.0.0.1:5000',
                                    'verify_code_url': '/verify-code'
                                }
                            }, to=request.form.get('newAcctEmail'), channel='email')
        print(verification)
        session['newEmail'] = email_info.normalized
        #request.form.get('newAcctEmail')
        print(session)
    return render_template('verifyNewUser.html')

@app.route('/verify-code<code>')
def verify_code(code):
    newEmail = session.get('newEmail')
    verification_checks = client.verify \
                        .v2 \
                        .services('VA4f40ef1d760fc1d05ae1f3b5fec96f19') \
                        .verification_checks \
                        .create(to=newEmail, code=code)


    if verification_checks.status == "approved":
        print("approved")
        return redirect(url_for('create_password'))

    return render_template('verifyFailed.html')


@app.route('/create-password', methods=['GET', 'POST'])
def create_password():

    if request.method == "POST":
        new_password = request.form.get('newAcctPW')
        confirmed_password = request.form.get('confirmNewAcctPW')

        if confirmed_password == new_password:
            #flash("Valid Password")
            try:
                #Get normalized email from session
                newEmail = session['newEmail']
                #Hash new password
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                #Use SQL (parameterized) to create new entry in user db (email, hashed pw)
                conn = get_db_connection()
                conn.execute('INSERT INTO user_credentials (email, password) VALUES (?, ?)',
                             (newEmail, hashed_password))
                conn.commit()
                conn.close()
            except sqlite3.IntegrityError as e:
                print(e)
                return
            #redirect to login page
            session.pop('newEmail')
            return redirect(url_for('index'))
        else:
            flash("Passwords don't match")

    return render_template('createPassword.html')

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def check_user_exists(user_email:str):
    #user_email = request.form.get('userEmail', '')

    conn = get_db_connection()
    user_exists_cursor = conn.execute('SELECT EXISTS (SELECT 1 FROM user_credentials WHERE email = ?)', (user_email,))
    user_exists = user_exists_cursor.fetchone()[0]

    conn.commit()
    conn.close()
    return user_exists

def check_password():
    user_email = request.form.get('userEmail', '')
    userPassword = request.form.get('userPassword', '')

    conn = get_db_connection()
    stored_pw_cursor = conn.execute('SELECT password FROM user_credentials WHERE email = ?',
                                    (user_email,))
    stored_pw = stored_pw_cursor.fetchone()[0]

    password_is_valid = bcrypt.check_password_hash(stored_pw, userPassword)
    conn.commit()
    conn.close()

    return password_is_valid


