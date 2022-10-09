from threading import Thread
import socket


def send_thread(sock):
    while True:
        sock.send(input("Prompt:> ").encode())

def recv_thread(sock):
    while True:
        print('\n' + str(sock.recv(2048), 'utf-8') + "\nPrompt:> ", end='')

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 4444))
    t_send = Thread(
            target=send_thread,
            args=(s, )
    )
    t_recv = Thread(
            target=recv_thread,
            args=(s, )
    )
    t_send.start()
    t_recv.start()
    t_send.join()
    t_recv.join()

