import sqlite3

db = sqlite3.connect("db.sqlite")

def init_db():
    db.cursor().executescript(
