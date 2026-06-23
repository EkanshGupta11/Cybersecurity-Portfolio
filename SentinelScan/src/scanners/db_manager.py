import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="security_suite.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        # Added 'risk TEXT' to the table definition
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS scans 
            (id INTEGER PRIMARY KEY, timestamp TEXT, target TEXT, port INTEGER, status TEXT, banner TEXT, risk TEXT)''')
        self.conn.commit()

    def log(self, target, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Added 'risk' to the insert statement
        self.cursor.execute("INSERT INTO scans (timestamp, target, port, status, banner, risk) VALUES (?, ?, ?, ?, ?, ?)",
                            (timestamp, target, data['port'], data['status'], data['banner'], data.get('risk', 'LOW')))
        self.conn.commit()