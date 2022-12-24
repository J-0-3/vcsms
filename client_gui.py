from vcsms.client import Client
from vcsms.logger import Logger
import curses
import curses.textpad
import argparse
import json
import os

class Application:
    def __init__(self, client: Client):
        self.client = client
        self.top_bar = None
        self.bottom_bar = None
        self.left_panel = None
        self.main_panel = None
        self.message_buffer = []

    def draw_top_bar(self):
        self.top_bar.clear()
        self.top_bar.addstr(1, 1, f"Your ID: {self.client.get_id()}")
        self.top_bar.border()
        self.top_bar.refresh()

    def draw_bottom_bar(self, message: str = "(n)ew message, (a)dd contact, (q)uit"):
        self.bottom_bar.clear()
        self.bottom_bar.addstr(1, 1, message) 
        self.bottom_bar.border()
        self.bottom_bar.refresh()

    def draw_left_panel(self):
        self.left_panel.clear()
        contacts = self.client.get_contacts()
        for i in range(len(contacts)):
            self.left_panel.addstr(i + 1, 1, contacts[i])
        self.left_panel.border()
        self.left_panel.refresh(0, 0, 0, 0, curses.LINES, 25)

    def draw_main_panel(self):
        self.main_panel.clear()
        num_to_display = curses.LINES - 8
        for i in range(min(len(self.message_buffer), num_to_display)):
            self.main_panel.addstr(i, 1, self.message_buffer[i]) 
        self.main_panel.refresh(0, 0, 4, 26, curses.LINES-4, curses.COLS)
    
    def ask_input(self, label: str):
        self.draw_bottom_bar(f"{label}: ")
        textbox_container = curses.newwin(1, curses.COLS-(26 + len(label) + 3), curses.LINES-2, (26 + len(label) + 3))
        textbox = curses.textpad.Textbox(textbox_container)
        self.stdscr.refresh()
        textbox.edit()
        return textbox.gather()

    def add_new_client(self):
        nickname = self.ask_input("Name").strip()
        id = self.ask_input("ID").strip() 
        self.client.add_contact(nickname, id)
        self.draw_bottom_bar()
        self.draw_left_panel()

    def send_message(self):
        recipient = self.ask_input("To").strip()
        message = self.ask_input("Message").strip()
        self.client.send(recipient, message.encode())
        self.message_buffer.append(f"TO {recipient}: {message}")
        self.draw_bottom_bar()
        self.draw_left_panel()
        self.draw_main_panel()

        
    def main(self, stdscr):
        self.left_panel = curses.newpad(curses.LINES, 25)
        self.bottom_bar = curses.newwin(3, curses.COLS-26, curses.LINES-3, 26)
        self.top_bar = curses.newwin(3, curses.COLS-26, 0, 26)
        self.main_panel = curses.newpad(curses.LINES-6, curses.COLS-26)
        self.stdscr = stdscr
        self.stdscr.refresh()
        self.stdscr.nodelay(True)
        self.draw_bottom_bar()
        self.draw_top_bar()
        self.draw_left_panel()
        self.draw_main_panel()
        while True:
            if self.client.new_message():
                msg = self.client.receive()
                self.message_buffer.append(f"FROM {msg[0]}: {msg[1]}")
                self.draw_main_panel()
            try:
                key = stdscr.getch()
            except:
                key = -1

            if key == ord('q'):
                self.client.quit()
                break
            elif key == ord('a'):
                self.add_new_client()
            elif key == ord('n'):
                self.send_message()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="The ip address of the server to connect to")
    parser.add_argument("config", type=str, help="The server's .vcsms config file")
    parser.add_argument("-d", "--directory", type=str, default="vcsms", help="Where to store application-generated files")
    args = parser.parse_args()
    with open(args.config, 'r') as conf:
        serverconf = json.loads(conf.read())
    logger = Logger(5, os.path.join(args.directory, "log.txt"))
    client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, logger)
    client.run()
    application = Application(client)
    curses.wrapper(application.main)

    
