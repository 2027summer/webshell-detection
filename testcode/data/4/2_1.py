import sqlite3
conn = sqlite3.connect('board.db')
result = conn.execute('SELECT name FROM sqlite_master').fetchall()