from threading import Lock

class Queue:
    def __init__(self):
        self.queue = []
        self.lock = Lock()

    def push(self, item: any):
        """Push an item to the back of the queue
        
        Args:
            item (any): The item to push.
        """
        self.lock.acquire()
        self.queue.append(item)
        self.lock.release()

    def pop(self) -> any:
        """Pop the item at the front of the queue.
        If the queue is empty, block until an item is available.

        Returns:
            any: The first item in the queue. 
        """
        while True:
            self.lock.acquire()
            if len(self.queue) != 0:
                item = self.queue.pop(0)
                self.lock.release()
                return item
            self.lock.release()

    @property
    def empty(self) -> bool:
        """Whether the queue currently contains 0 elements"""
        self.lock.acquire()
        isempty = len(self.queue) == 0
        self.lock.release()
        return isempty
