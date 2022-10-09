from threading import Thread
from queue import Queue
import socket

def send_data_thread(sock, outgoing_queue):
    while True:
        outgoing_queue.put(sock.recv(1024))

def recv_data_thread(sock, incoming_queue):
    while True:
        sock.send(incoming_queue.get())

def thread_func(sock, outgoing, incoming):
    outgoing_msg_thread = Thread(
        target = send_data_thread,
        args=(sock, outgoing)
    )
    incoming_msg_thread = Thread(
        target = recv_data_thread,
        args=(sock, incoming)
    )
    outgoing_msg_thread.start()
    incoming_msg_thread.start()

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 4444))
    s.listen(10)
    c1_msg = Queue()
    c2_msg = Queue()

    c1_sock, addr = s.accept()
    c2_sock, addr = s.accept()
    c1_thread = Thread(
            target=thread_func,
            args=(c1_sock, c2_msg, c1_msg)
    )
    c2_thread = Thread(
            target=thread_func,
            args=(c2_sock, c1_msg, c2_msg)
    )
    c1_thread.start()
    c2_thread.start()

    c1_thread.join()
    c2_thread.join()

