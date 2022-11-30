import time
from client_class import Client

if __name__ == "__main__":
    target = input("Enter spam target id: ")
    client = Client("server.conf", "spam_bot")
    client.run()
    while True:
        client.send(target, b"heeeheeeheeheehheheheheheheheh")
        print("sent.")
        time.sleep(0.01)