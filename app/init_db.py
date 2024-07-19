import sqlite3
from flask_bcrypt import Bcrypt

connection = sqlite3.connect('database.db')


with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO user_credentials (email, password) VALUES (?, ?)",
            ("john_smith@gmail.com", "$2b$12$bYjnAlAmoaGugnlGIZzXIOuYaZecSd5odpD/y5Kx0HB3kVDme288W")) #hash for 'abcd1234'

cur.execute("INSERT INTO user_credentials (email, password) VALUES (?, ?)",
            ("littlejmics@gmail.com", "$2b$12$bYjnAlAmoaGugnlGIZzXIOuYaZecSd5odpD/y5Kx0HB3kVDme288W")) #hash for 'abcd1234'

connection.commit()
connection.close()