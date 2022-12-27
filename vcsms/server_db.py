import sqlite3
import os
from . import keys


class Server_DB:
    """A connection to the server sqlite3 database"""
    def __init__(self, path='server.db', pubkey_directory='client_public_keys'):
        """Initialise a server database connection

        Args:
            path (str, optional): The path to the sqlite3 database file. Defaults to 'server.db'.
            pubkey_directory (str, optional): The directory in which to store all client public keys. Defaults to 'client_public_keys'.
        """
        self._db = sqlite3.connect(path)
        self._pubkeys = pubkey_directory

    def setup_db(self):
        """Setup the database if it has not already been setup"""
        self._db.execute("create table if not exists connection_log (id text, time text)")
        self._db.execute("create table if not exists logged_in (id text unique, connected integer)")
        self._db.execute("update logged_in set connected=0")
        self._db.commit()

    def user_known(self, id: str) -> bool:
        """Check whether a given client ID is 'known' (i.e. whether a public key for them is stored)

        Args:
            id (str): The client ID to lookup 

        Returns:
            bool: Whether the client is known
        """
        return os.path.exists(os.path.join(self._pubkeys, id))

    def user_login(self, id: str, pubkey: tuple):
        """Register a given client ID as logged in and store their public key.

        Args:
            id (str): The client ID to login. 
            pubkey (tuple): The client's public key.
        """
        if not self.user_known(id):
            keys.write_key(pubkey, os.path.join(self._pubkeys, id))

        self._db.execute("insert into connection_log values(?, datetime('now', 'localtime'))", (id, ))
        self._db.execute("replace into logged_in values(?, 1)", (id, ))
        self._db.commit()

    def user_logout(self, id: str):
        """Register a given client ID as logged out.

        Args:
            id (str): The client ID to logout
        """
        self._db.execute("replace into logged_in values(?, 0)", (id, ))
        self._db.commit()

    def is_logged_in(self, id: str) -> bool:
        """Check whether a given client ID is currently logged in.

        Args:
            id (str): The client ID to lookup. 

        Returns:
            bool: Whether the client is currently logged in 
        """
        cursor = self._db.execute("select connected from logged_in where id=?", (id, ))
        values = cursor.fetchone()
        if values is None or values[0] == 0:
            return False
        return True

    def get_pubkey(self, id: str) -> tuple[int, int]:
        """Get the stored public key for a given user.

        Args:
            id (str): The client ID of the user to lookup. 

        Raises:
            Exception: The user is not known (has no stored public key).

        Returns:
            tuple[int, int]: The client's public key in the form (exponent, modulus)
        """
        if os.path.exists(os.path.join(self._pubkeys, id)):
            key = keys.load_key(os.path.join(self._pubkeys, id))
            return key
        raise Exception("User not found")

    def close(self):
        """Close the connection to the database"""
        self._db.close()
