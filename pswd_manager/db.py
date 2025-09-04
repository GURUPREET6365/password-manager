import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DB")
    )
    return conn
