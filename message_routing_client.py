from threading import Thread
from queue import Queue
import socket
import sys

def recv_thread(sock, message_queue, request_queue, stopped):
    while not stopped():
        data = sock.recv(2048)
        if data[:3] == b'MSG':
            message = data[3:].split(b'DAT',1) 
            message_queue.put((str(message[0], 'utf-8'), str(message[1], 'utf-8')))
        else:
            request_queue.put(data)

def message_process_thread(message_queue, stopped):
    while not stopped():
            if not message_queue.empty():
                message = message_queue.get()
                print(f"\rNEW MESSAGE: \n{message[1]}\n\nFROM: {message[0]}")


def send_thread(sock, request_queue):
    while True:
        receiver = input()
        if receiver == "QUIT":
            sock.send(b'QUIT')
            break
        sock.send(b'TO'+receiver.encode())
        if request_queue.get() == b'data': # queue.get() blocks until a piece of data is available
            message = input("Msg: ")
            sock.send(message.encode())
            if request_queue.get() == b'OK':
                print("Message Sent Successfully")
            else:
                print("server indicated error in sending message")

        else:    
            print(f"server rejected message request to {receiver}")

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", int(sys.argv[1])))
    name = input("What is your name? ")
    s.send(name.encode())
    if s.recv(1024) != b'OK':
        print("could not authenticate to server")
        s.close()
        exit()
   
    print("Type a user's name and press enter to send them a message! Type QUIT to quit!")
    msg_queue = Queue()
    req_queue = Queue()
    stopped = False

    t_send = Thread(
            target=send_thread,
            args=(s, req_queue)
    )
    t_msg = Thread(
            target=message_process_thread,
            args=(msg_queue, lambda: stopped)
    )
    t_recv = Thread(
            target=recv_thread,
            args=(s, msg_queue, req_queue, lambda: stopped)
    )
    t_send.start()
    t_recv.start()
    t_msg.start()

    t_send.join()
    stopped = True
    t_msg.join()
    t_recv.join()
    s.close()

