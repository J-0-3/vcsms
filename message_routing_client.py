from threading import Thread
from queue import Queue
import socket
import sys


def recv_thread(sock, message_queue, request_queue, stopped):
    while not stopped():
        data = sock.recv(2048)
        if data[:3] == b'MSG':
            recipient, msg_data = data[3:].split(b'DAT', 1)
            message_queue.put((str(recipient[0], 'utf-8'), str(msg_data[1], 'utf-8')))
        else:
            request_queue.put(data)


def message_process_thread(message_queue, stopped):
    while not stopped():
        if not message_queue.empty():
            recipient, data = message_queue.get()
            print(f"\rNEW MESSAGE: \n{str(data, 'utf-8')}\n\nFROM: {str(recipient, 'utf-8')}")


def send_thread(sock, request_queue, send_queue):
    while True:
        receiver, data = send_queue.get()
        if receiver == "QUIT":
            sock.send(b'QUIT')
            break
        sock.send(b'TO' + receiver.encode())
        if request_queue.get() == b'data':  # queue.get() blocks until a piece of data is available
            sock.send(data.encode())
            if request_queue.get() == b'OK':
                print("Message Sent Successfully")
            else:
                print("server indicated error in sending message")

        else:
            print(f"server rejected message request to {receiver}")


class Messenger:
    def __init__(self):
        self.t_recv = None
        self.t_msg = None
        self.t_send = None
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.msg_queue = Queue()
        self.send_queue = Queue()
        self.req_queue = Queue()
        self.stopped = False

    def connect(self, ip: str, port: int, username: str):
        self.s.connect((ip, port))
        self.s.send(name.encode())
        status = self.s.recv(1024)
        if status != b'OK':
            self.s.close()
            return status

        self.t_send = Thread(
            target=send_thread,
            args=(self.s, self.req_queue, self.send_queue)
        )
        self.t_msg = Thread(
            target=message_process_thread,
            args=(self.msg_queue, lambda: self.stopped)
        )
        self.t_recv = Thread(
            target=recv_thread,
            args=(self.s, self.msg_queue, self.req_queue, lambda: self.stopped)
        )
        self.t_send.start()
        self.t_msg.start()
        self.t_recv.start()

    def exit(self):
        self.send_queue.put(("QUIT", None))
        self.t_send.join()
        self.stopped = True
        self.t_msg.join()
        self.t_recv.join()
        self.s.close()

    def send(self, to: str, text: str):
        self.send_queue.put((to, text))

    def read(self, block=True):

        if not self.msg_queue.empty() or block:
            return self.msg_queue.get()
        else:
            return None, None


if __name__ == "__main__":
    name = input("What is your name?")

    print("Type a user's name and press enter to send them a message! Type QUIT to quit!")
    messenger = Messenger()
    messenger.connect("127.0.0.1", int(sys.argv[1]), name)
    messenger.send("bob", "hello bob!")
    message = messenger.read()
    print(f"NEW MESSAGE: \n{message[1]}\n FROM {message[0]}")
    messenger.exit()
