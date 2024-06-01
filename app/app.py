from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'j48f903jo3ewrv9i324njkkfaerj5lk34r'


@app.route('/', methods=['GET', 'POST'])
def index():
    #Hashes password and checks that hashed pw is valid for a given password
    if request.method == "POST":
        user_exists = check_user_exists()

        if user_exists == 0:
            flash("No Account Linked to this Email. Please sign-up for an account.")
            return render_template('base.html', TestLogic=user_exists)

        validate_password = check_password()

        #return render_template('base.html', TestLogic=validate_password)
        if not validate_password:
            flash("Incorrect Password.")
            return render_template('base.html', TestLogic=validate_password)

        session['email'] = request.form.get('userEmail', '')
        return redirect(url_for('welcome'))

    session.pop('email', None)
    print(session)
    return render_template('base.html', TestLogic="unknown")

@app.route('/welcome')
def welcome():
    if session.get('email') == None:
        flash("Please Login to view other pages.")
        return redirect(url_for('index'))
    return render_template('welcome.html', EMail=session['email'])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def check_user_exists():
    user_email = request.form.get('userEmail', '')

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

    hashIsHash = bcrypt.check_password_hash(stored_pw, userPassword)
    conn.commit()
    conn.close()

    return hashIsHash

