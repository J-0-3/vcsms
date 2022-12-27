#!/bin/python
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
        self.stdscr = None
        self.top_bar = None
        self.bottom_bar = None
        self.left_panel = None
        self.main_panel = None
        self.left_panel_bottom_bar = None
        self.new_message = {}
        self.message_buffer = []
        self.focused_user = ""
        contacts = client.get_contacts()
        if len(contacts) > 0:
            self.focused_user = contacts[0] 

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

    def draw_left_panel_bottom_bar(self, message: str = "h <- -> l"):
        self.left_panel_bottom_bar.clear()
        self.left_panel_bottom_bar.addstr(1, 1, message)
        self.left_panel_bottom_bar.border()
        self.left_panel_bottom_bar.refresh()

    def draw_left_panel(self):
        self.left_panel.clear()
        contacts = self.client.get_contacts()
        self.left_panel.addstr(1, 1, "Contacts: ")
        for i, contact in enumerate(contacts):
            if contact == self.focused_user:
                self.left_panel.addstr(i + 2, 1, f"[{contact}]")
            else:
                if contact in self.new_message and self.new_message[contact]:
                    self.left_panel.addstr(i + 2, 1, f"*{contact}")
                else:
                    self.left_panel.addstr(i + 2, 1, contact)
        self.left_panel.border()
        self.left_panel.refresh(0, 0, 0, 0, curses.LINES - 3, 26)

    def draw_main_panel(self):
        self.main_panel.clear()
        num_to_display = curses.LINES - 8
        messages = self.client.get_messages(self.focused_user, num_to_display)
        for i,m in enumerate(messages):
            self.main_panel.addstr(i, 1, f"{'TO' if m[1] else 'FROM'} {self.focused_user}: {m[0].decode('utf-8')}")
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
        if not self.focused_user:
            self.focused_user = nickname
            self.draw_main_panel()
        self.draw_bottom_bar()
        self.draw_left_panel()

    def send_message(self):
        message = self.ask_input("Message").strip()
        self.client.send(self.focused_user, message.encode())
        self.draw_bottom_bar()
        self.draw_left_panel()
        self.draw_main_panel()

    def main(self, stdscr):
        self.left_panel = curses.newpad(curses.LINES - 3, 26)
        self.bottom_bar = curses.newwin(3, curses.COLS-26, curses.LINES-3, 26)
        self.left_panel_bottom_bar = curses.newwin(3, 26, curses.LINES - 3, 0)
        self.top_bar = curses.newwin(3, curses.COLS-26, 0, 26)
        self.main_panel = curses.newpad(curses.LINES-6, curses.COLS-26)
        self.stdscr = stdscr
        self.stdscr.refresh()
        self.stdscr.nodelay(True)
        self.draw_bottom_bar()
        self.draw_top_bar()
        self.draw_left_panel()
        self.draw_left_panel_bottom_bar()
        self.draw_main_panel()
        while True:
            if self.client.new_message():
                sender, _ = self.client.receive()
                if not self.focused_user:
                    self.focused_user = sender
                self.new_message[sender] = True
                self.draw_left_panel()
                self.draw_main_panel()

            try:
                key = stdscr.getkey()
            except curses.error:
                key = ""
            match key:
                case 'q':
                    self.client.quit()
                    break
                case 'a':
                    self.add_new_client()
                case 'n':
                    self.send_message()
                case 'l':
                    contacts = self.client.get_contacts()
                    current_contact_index = contacts.index(self.focused_user)
                    next_index = (current_contact_index + 1) % len(contacts)
                    self.focused_user = contacts[next_index]
                    self.new_message[self.focused_user] = False
                    self.draw_left_panel()
                    self.draw_main_panel()
                case 'h':
                    contacts = self.client.get_contacts()
                    current_contact_index = contacts.index(self.focused_user)
                    prev_index = (current_contact_index - 1) % len(contacts)
                    self.focused_user = contacts[prev_index]
                    self.new_message[self.focused_user] = False
                    self.draw_left_panel()
                    self.draw_main_panel()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="The ip address of the server to connect to")
    parser.add_argument("config", type=str, help="The server's .vcsms config file")
    parser.add_argument("-d", "--directory", type=str, default="vcsms", help="Where to store application-generated files")
    parser.add_argument("-p", "--password", type=str, help="The application master password")
    args = parser.parse_args()
    with open(args.config, 'r', encoding='utf-8') as conf:
        serverconf = json.load(conf)
    logger = Logger(5, os.path.join(args.directory, "log.txt"))
    if args.password:
        client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, args.password, logger)
    else:
        client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, input("Enter master password: "), logger)
    client.run()
    application = Application(client)
    curses.wrapper(application.main)
