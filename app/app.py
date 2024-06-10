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
    #Check if user session still active. Redirect since now sign in required.
    if session.get('email') != None:
        return redirect(url_for('welcome'))

    #Handle post request from sign-in page form.
    if request.method == "POST":

        # Check format of user input email
        try:
            email_info = validate_email(request.form.get('userEmail', ''), check_deliverability=False)
        except EmailNotValidError as e:
            print(str(e))
            flash("Invalid Email Address.")
            return redirect(url_for('index'))

        #Check that normalized email already in db --> shows user has account
        user_exists = check_user_exists(email_info.normalized)

        #Handle nonexisting user
        if user_exists == 0:
            flash("No Account Linked to this Email. Please sign-up for an account.")
            return render_template('base.html', TestLogic=request.form.get('userEmail'))

        #Check hashed version of user input for password matches hashed password stored in db
        validate_password = check_password()

        #Handle case where hashed user input doesn't match hashed pw in db
        if not validate_password:
            flash("Incorrect Password.")
            return render_template('base.html', TestLogic=validate_password)

        #When user fully validated store email in session var and redirect to welcome user page
        session['email'] = request.form.get('userEmail', '')
        return redirect(url_for('welcome'))

    #Handle initial GET requests
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

        #Check that normalized email already in db --> shows user has account
        user_exists = check_user_exists(email_info.normalized)

        #Handle nonexisting user
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
        session['newEmail'] = request.form.get('newAcctEmail')
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
        return redirect(url_for('create_password'))
        print ("approved")

    return render_template('verifyFailed.html')


@app.route('/create-password')
def create_password():
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

