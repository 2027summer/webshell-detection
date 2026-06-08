import sqlite3
conn = sqlite3.connect('board.db')
result = (conn.execute('update users set is_admin=1 where id=2').fetchall())