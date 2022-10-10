from threading import Thread
from queue import Queue
import socket
import sys


def process_incoming_messages(sock, msg_queue, stopped):
    while not stopped():
        if not msg_queue.empty():
            msg = msg_queue.get()
            print(f"sending message: {msg}")
            sock.send(b'MSG' + msg[0] + b'DAT' + msg[1])


def process_outgoing_messages(sock, msg_queue_dict, username, stopped):
    while not stopped():
        request = sock.recv(1024)
        if request[:2] != b'TO':
            if request == b'QUIT':
                sock.close()
                break
        else:
            recipient = request[2:]
            if recipient not in msg_queue_dict:
                msg_queue_dict[recipient] = Queue()

            sock.send(b'data')
            data = sock.recv(2048)
            msg_queue_dict[recipient].put((username, data))
            print(f"Message to {str(recipient, 'utf-8')} from {str(username, 'utf-8')}: {str(data, 'utf-8')}")
            sock.send(b'OK')


def accept_user(sock, msg_queue_dict):
    user_name = sock.recv(1024)
    print(f"NEW USER: {str(user_name, 'utf-8')}")
    sock.send(b'OK')
    if user_name not in msg_queue_dict:
        msg_queue_dict[user_name] = Queue()
    stopped = False
    t_incoming = Thread(
        target=process_incoming_messages,
        args=(sock, msg_queue_dict[user_name], lambda: stopped)
    )
    t_outgoing = Thread(
        target=process_outgoing_messages,
        args=(sock, msg_queue_dict, user_name, lambda: stopped)
    )
    t_incoming.start()
    t_outgoing.start()
    t_outgoing.join()
    stopped = True
    t_incoming.join()


def accept_new_users(sock, msg_queue_dict):
    while True:
        c, addr = sock.accept()
        t_new_user = Thread(
            target=accept_user,
            args=(c, msg_queue_dict)
        )
        t_new_user.start()


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", int(sys.argv[1])))
    s.listen(50)

    msg_queues = {}
    t_accept = Thread(
        target=accept_new_users,
        args=(s, msg_queues)
    )
    t_accept.start()
    t_accept.join()
