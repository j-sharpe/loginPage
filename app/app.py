from flask import Flask, render_template
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    render_template('index.html')