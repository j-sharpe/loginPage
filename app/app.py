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
    if session.get('user') != None:
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

        session['user'] = request.form.get('userEmail', '')
        return redirect(url_for('welcome'))

    return render_template('base.html', TestLogic="unknown")

@app.route('/welcome')
def welcome():
    print(session)
    if session.get('user') == None:
        flash("Please Login to view other pages.")
        return redirect(url_for('index'))
    return render_template('welcome.html', User=session['user'])

@app.route('/logout')
def logout():
    flash("You have been logged out.")
    session.pop('user')
    return redirect(url_for('index'))

@app.route('/verify-new-user', methods = ['POST', 'GET'])
def verify_new_user():

    if request.method == 'POST':

        try:
            email_info = validate_email(request.form.get('acctEmail', ''), check_deliverability=False)
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
                                    'verify_code_url': '/new-user-code',
                                    'action_item': 'Creating Your Account!'
                                }
                            }, to=request.form.get('acctEmail'), channel='email')
        #print(verification)
        session['email'] = email_info.normalized
        #request.form.get('newAcctEmail')
        #print(session)
    return render_template('verifyUser.html', appService="Create User")


@app.route("/verify-current-user", methods=["POST", "GET"])
def verify_current_user():

    if request.method == 'POST':

        try:
            email_info = validate_email(request.form.get('acctEmail', ''), check_deliverability=False)
        except EmailNotValidError as e:
            print(str(e))
            flash("Invalid Email Address.")
            return redirect(url_for('verify_current_user'))

        user_exists = check_user_exists(email_info.normalized)

        if user_exists == 0:
            flash("No account linked with this email. Please create a new account.")
            return redirect(url_for('verify_current_user'))

        verification = client.verify \
            .v2 \
            .services('VA4f40ef1d760fc1d05ae1f3b5fec96f19') \
            .verifications \
            .create(channel_configuration={
            'substitutions': {
                'localhost': 'http://127.0.0.1:5000',
                'verify_code_url': '/update-user-code',
                'action_item': 'Updating your Password!'
            }
        }, to=request.form.get('acctEmail'), channel='email')

        session['email'] = email_info.normalized
        print(verification)
    return render_template('verifyUser.html', appService="Verify User To Update Password")

@app.route('/new-user-code<code>')
def new_user_code(code):
    toEmail = session.get('email')
    verification_checks = client.verify \
                        .v2 \
                        .services('VA4f40ef1d760fc1d05ae1f3b5fec96f19') \
                        .verification_checks \
                        .create(to=toEmail, code=code)


    if verification_checks.status == "approved":
        print("approved")
        return redirect(url_for('create_password'))

    return render_template('verifyFailed.html')


@app.route('/update-user-code<code>')
def update_user_code(code):
    toEmail = session.get('email')
    verification_checks = client.verify \
                        .v2 \
                        .services('VA4f40ef1d760fc1d05ae1f3b5fec96f19') \
                        .verification_checks \
                        .create(to=toEmail, code=code)


    if verification_checks.status == "approved":
        print("approved")
        return redirect(url_for('change_password'))

    return render_template('verifyFailed.html')

@app.route('/create-password', methods=['GET', 'POST'])
def create_password():

    if request.method == "POST":
        new_password = request.form.get('newAcctPW')
        confirmed_password = request.form.get('confirmNewAcctPW')

        if confirmed_password == new_password:
            try:
                new_email = session['email']
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                conn = get_db_connection()
                conn.execute('INSERT INTO user_credentials (email, password) VALUES (?, ?)',
                             (new_email, hashed_password))
                conn.commit()
                conn.close()
            except sqlite3.IntegrityError as e:
                print(e)
                return

            session.pop('email')
            return redirect(url_for('index'))
        else:
            flash("Passwords don't match.")

    return render_template('createPassword.html')


@app.route('/change-password', methods=["POST", "GET"])
def change_password():

    if request.method == "POST":
        updated_password = request.form.get('updatedAcctPW')
        confirmed_password = request.form.get('confirmUpdatedAcctPW')

        if confirmed_password == updated_password:
            user_email = session['email']
            hashed_password = bcrypt.generate_password_hash(updated_password).decode('utf-8')
            conn = get_db_connection()
            conn.execute('UPDATE user_credentials SET password = ? WHERE email = ?',
                         (hashed_password, user_email ))
            conn.commit()
            conn.close()

            session.pop('email')
            return redirect(url_for('index'))
        else:
            flash("Passwords don't match.")

    return render_template('changePassword.html')


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


