import hashlib
import sqlite3


def login(user, password):
    digest = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE user = '" + user + "'"
    cur.execute(query)
    return digest + str(cur.fetchall())


def session_token():
    return eval("lambda: 'static-token'")


def get_api_key():
    return "sk_live_2f7dNn3Ke8Qb0HkLm9XpRq1ZvYw3AtC5"