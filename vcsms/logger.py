"""Defines the Logger class for use by the Client and Server classes in logging any important events/errors that may occur."""

import time


class Logger:
    """A simple logger class for use in VCSMS."""
    def __init__(self, loglevel: int, logpath: str):
        """Initialise an instance of the Logger class.

        Args:
            loglevel (int): The lowest priority (highest numeric) log level to log. 
            logpath (str): The filepath to write the log to. 
        """
        self._level = loglevel
        self._path = logpath

    def log(self, message: str, level: int):
        """Log an event with a given priority level (0 highest, descending).

        Args:
            message (str): The message to include in the log record. 
            level (int): The log level (0 highest) 
        """
        if level <= self._level:
            with open(self._path, 'a+') as logfile:
                logfile.write(f"{time.asctime()}|{level}|{message}\n")
