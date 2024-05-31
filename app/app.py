from flask import Flask, render_template, request, flash
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'j48f903jo3ewrv9i324njkkfaerj5lk34r'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET', 'POST'])
def index():
    #Hashes password and checks that hashed pw is valid for a given password

    if request.method == "POST":
        user_email = request.form.get('userEmail', '')

        #userPassword = request.form.get('userPassword', '')

        conn = get_db_connection()
        cursor = conn.execute('SELECT EXISTS (SELECT 1 FROM user_credentials WHERE email = ?)', (user_email,))
        user_exists = cursor.fetchone()[0]

        conn.commit()
        conn.close()

        if user_exists == 0:
            flash("No Account Linked to this Email. Please sign-up for an account.")

        return render_template('base.html', userExists=user_exists)

    return render_template('base.html', userExists="unknown")

""" password = 'password'
pw_for_false = 'dog'
hashed_password = (bcrypt.generate_password_hash
                   (password).decode('utf-8'))
is_valid = (bcrypt.check_password_hash
            (hashed_password, password))

return render_template('base.html',
                hashedpassword=hashed_password,
                password = password,
                valid=is_valid)"""
