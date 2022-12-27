import time


class Logger:
    def __init__(self, loglevel, logpath):
        self.level = loglevel
        self.path = logpath
    def log(self, message: str, level: int):
        if level <= self.level:
            with open(self.path, 'a+') as logfile:
                logfile.write(f"{time.asctime()}|{level}|{message}\n")

