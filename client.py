import json
import sys
import threading

from client_class import Client


def send_thread(client: Client):
    while True:
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
            client.server.send(b"0:QUIT")
            client.quit()
            break


if __name__ == "__main__":
    with open("server.conf", 'r') as conf:
        server = json.loads(conf.read())

    application_directory = sys.argv[1]

    program = Client("server.conf", application_directory)
    t_send = threading.Thread(target=send_thread, args=(program,))
    program.run()
    t_send.start()


