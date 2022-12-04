import json
import threading
import argparse

from vcsms.client import Client


def send_thread(client: Client):
    while client.running:
        action = input("vcsms:> ").lower()
        if action == "msg":
            recipient = input("To: ")
            message = input("Message: ")
            client.send(recipient, message.encode())
        elif action == 'name':
            name = input("name: ")
            id = input("id: ")
            client.add_contact(name, id)

        elif action == "quit":
            client.quit()


def receive_thread(client: Client):
    while client.running:
        if client.new_message():
            sender, message = client.receive()
            print(f"New message from {sender}: {message}\nvcsms:> ", end='')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="The ip address of the server to connect to")
    parser.add_argument("config", type=str, help="The server's connection file (.vcsms)")
    parser.add_argument("-d", "--directory", type=str, default="vcsms", help="The location to store application files")
    args = parser.parse_args()

    with open(args.config, 'r') as conf:
        server = json.loads(conf.read())

    program = Client(args.ip, server["port"], server["fingerprint"], args.directory)
    t_send = threading.Thread(target=send_thread, args=(program,))
    t_recv = threading.Thread(target=receive_thread, args=(program,))
    program.run()
    t_recv.start()
    t_send.start()


