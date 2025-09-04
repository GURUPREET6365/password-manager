from flask import Flask
import mysql.connector
from dotenv import load_dotenv
import os


load_dotenv()  # Load variables from .env

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# ---- MySQL Connection Function ----
def get_db_connection():
    connection = mysql.connector.connect(
        host="localhost",  # Host is hardcoded as you requested
        user=os.environ.get('MYSQL_USER'),
        password=os.environ.get('MYSQL_PASSWORD'),
        database=os.environ.get('MYSQL_DB')
    )
    return connection

from pswd_manager import routes