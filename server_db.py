import sqlite3


class Server_DB:
    def __init__(self, path=':memory:'):
        try:
            self.db = sqlite3.connect(path)
        except FileNotFoundError