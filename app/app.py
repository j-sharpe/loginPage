from flask import Flask, render_template
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    #Hashes password and checks that hashed pw is valid for a given password

    password = 'password'
    pw_for_false = 'dog'
    hashed_password = (bcrypt.generate_password_hash
                       (password).decode('utf-8'))
    is_valid = (bcrypt.check_password_hash
                (hashed_password, pw_for_false))

    return render_template('base.html',
                    hashedpassword=hashed_password,
                    password = password,
                    valid=is_valid)

