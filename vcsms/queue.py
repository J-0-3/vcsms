from threading import Lock
class Queue:
    def __init__(self):
        self.queue = []
        self.lock = Lock()
    def put(self, item: any):
        self.lock.acquire()
        self.queue.append(item)
        self.lock.release()
    def get(self) -> any:
        while True:
            self.lock.acquire()
            if len(self.queue) != 0:
                item = self.queue.pop(0)
                self.lock.release()
                return item
            self.lock.release()

    def empty(self) -> bool:
        self.lock.acquire()
        isempty = len(self.queue) == 0
        self.lock.release()
        return isempty