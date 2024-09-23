import pymysql, os
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    return pymysql.connect(
        host=os.getenv('HOST'),
        user=os.getenv('USER'),
        password=os.getenv('PASSWORD'),
        db=os.getenv('DB_SELLIFY'),
        cursorclass=pymysql.cursors.DictCursor
    )