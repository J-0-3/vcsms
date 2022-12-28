#!/bin/python
import curses
import curses.textpad
import argparse
import json
import os
from vcsms.client import Client
from vcsms.logger import Logger
from vcsms.exceptions.client import IncorrectMasterKeyException


class Application:
    """A curses based client application for VCSMS"""
    def __init__(self, client: Client):
        """Instantiate the application

        Args:
            client (Client): An instance of vcsms.client.
                Provides the actual client functionality.
        """
        self._client = client
        self._stdscr = None
        self._top_bar = None
        self._bottom_bar = None
        self._left_panel = None
        self._main_panel = None
        self._left_panel_bottom_bar = None
        self._cur_scroll_position = 0
        self._new_message = {}
        self._max_scroll_position = 0
        self._message_buffer_oldest = 0
        self._running = False
        self._message_buffer = []
        self._focused_user = ""
        contacts = client.get_contacts()
        if len(contacts) > 0:
            self._focused_user = contacts[0]

    def _draw_top_bar(self):
        """Draw the top bar which displays the user's client ID"""
        self._top_bar.clear()
        self._top_bar.addstr(1, 1, f"Your ID: {self._client.get_id()}")
        self._top_bar.border()
        self._top_bar.refresh()

    def _draw_bottom_bar(self, message: str = ""):
        """Draw the bottom bar containing an optional non-default message.

        By default displays dynamic usage instructions
        Args:
            message (str, optional): The message to display.
        """
        self._bottom_bar.clear()
        if message:
            self._bottom_bar.addstr(1, 1, message)
        else:
            instructions = ""
            if self._focused_user:
                instructions += "(n)ew message "
            instructions += "(a)dd contact (q)uit "
            if self._cur_scroll_position > 0:
                instructions += "j \u2193 "
            if self._cur_scroll_position < self._max_scroll_position:
                instructions += "k \u2191"
            self._bottom_bar.addstr(1, 1, instructions)
        self._bottom_bar.border()
        self._bottom_bar.refresh()

    def _draw_left_panel_bottom_bar(self, message: str = "h <- -> l"):
        """Draw the bottom bar below the left panel containing an optional
        non-default message.

        Args:
            message (str, optional): The message to display.
                Defaults to "h <- -> l".
        """
        self._left_panel_bottom_bar.clear()
        self._left_panel_bottom_bar.addstr(1, 1, message)
        self._left_panel_bottom_bar.border()
        self._left_panel_bottom_bar.refresh()

    def _draw_left_panel(self):
        """Draw the left panel containing the user's contacts."""
        self._left_panel.clear()
        contacts = self._client.get_contacts()
        self._left_panel.addstr(1, 1, "Contacts: ")
        for i, contact in enumerate(contacts):
            if contact == self._focused_user:
                self._left_panel.addstr(i + 2, 1, f"[{contact}]")
            else:
                if contact in self._new_message and self._new_message[contact]:
                    self._left_panel.addstr(i + 2, 1, f"*{contact}")
                else:
                    self._left_panel.addstr(i + 2, 1, contact)
        self._left_panel.border()
        self._left_panel.refresh(0, 0, 0, 0, curses.LINES - 3, 26)

    def _draw_main_panel(self):
        """Draw the main panel containing messages from the
        currently focused user.
        """
        self._main_panel.clear()
        num_to_display = curses.LINES - 8
        if self._cur_scroll_position + num_to_display > self._message_buffer_oldest:
            self._message_buffer = self._client.get_messages(self._focused_user, self._cur_scroll_position + num_to_display + 20)
            self._message_buffer_oldest = self._cur_scroll_position + num_to_display + 20
        messages_to_show = self._message_buffer[self._cur_scroll_position:self._cur_scroll_position + num_to_display]
        
        for i, message in enumerate(messages_to_show[::-1]):
            direction = 'TO' if message[1] else 'FROM'
            message_text = message[0].decode('utf-8')
            self._main_panel.addstr(i, 1, f"{direction} {self._focused_user}: {message_text}")
        self._main_panel.refresh(0, 0, 4, 26, curses.LINES-4, curses.COLS)

    def _ask_input(self, prompt: str) -> str:
        """Ask for input given a specific prompt.

        Args:
            label (str): The prompt given to the user.

        Returns:
            str: The input typed by the user
        """
        self._draw_bottom_bar(f"{prompt}: ")
        textbox_height = 1
        textbox_width = curses.COLS - (26 + len(prompt) + 3)
        textbox_x = 26 + len(prompt) + 3
        textbox_y = curses.LINES - 2
        textbox_container = curses.newwin(textbox_height, textbox_width, textbox_y, textbox_x)
        textbox = curses.textpad.Textbox(textbox_container)
        self._stdscr.refresh()
        textbox.edit()
        return textbox.gather()

    def _add_new_contact(self):
        """Add a new contact with user supplied nickname and client ID"""
        nickname = self._ask_input("Name").strip()
        client_id = self._ask_input("ID").strip() 
        self._client.add_contact(nickname, client_id)
        if not self._focused_user:
            self._focused_user = nickname
            self._draw_main_panel()
        self._draw_bottom_bar()
        self._draw_left_panel()

    def _send_message(self):
        """Prompt the user to send a message to the currently focused user.

        Cancelled if the user does not enter a message or there is no
        currently focused user.
        """
        if self._focused_user:
            message = self._ask_input("Message").strip()
            if message:
                self._client.send(self._focused_user, message.encode())
                self._max_scroll_position += 1
                self._message_buffer_oldest = 0
                self._cur_scroll_position = 0
            self._draw_left_panel()
            self._draw_bottom_bar()
            self._draw_main_panel()

    @property
    def running(self) -> bool:
        """Get whether the program is currently running

        Returns:
            bool: If the program is running
        """
        return self._running

    def run(self, stdscr: curses.window):
        """The main function to run the application.

        Invoked via curses.wrapper

        Args:
            stdscr (curses.window): The curses screen.
                Provided by curses.wrapper
        """
        self._left_panel = curses.newpad(curses.LINES - 3, 26)
        self._bottom_bar = curses.newwin(3, curses.COLS-26, curses.LINES-3, 26)
        self._left_panel_bottom_bar = curses.newwin(3, 26, curses.LINES - 3, 0)
        self._top_bar = curses.newwin(3, curses.COLS-26, 0, 26)
        self._main_panel = curses.newpad(curses.LINES-6, curses.COLS-26)
        self._max_scroll_position = self._client.message_count(self._focused_user) - (curses.LINES - 8)
        self._stdscr = stdscr
        self._stdscr.refresh()
        self._stdscr.nodelay(True)
        if self._focused_user:
            self._draw_bottom_bar()
        else:
            self._draw_bottom_bar("(a)dd contact, (q)uit")
        self._draw_top_bar()
        self._draw_left_panel()
        self._draw_left_panel_bottom_bar()
        self._draw_main_panel()
        self._running = True
        while self._running:
            if self._client.new_message():
                sender, _ = self._client.receive()
                if not self._focused_user:
                    self._focused_user = sender
                self._new_message[sender] = True
                if self._focused_user == sender:
                    self._max_scroll_position += 1
                    self._message_buffer_oldest = 0
                    self._cur_scroll_position = 0
                self._draw_left_panel()
                self._draw_main_panel()
            self._handle_input()


    def _handle_input(self):
        """Read one character from the keyboard and perform the appropriate action."""

        try:
            key = self._stdscr.getkey()
        except curses.error:
            key = ""
        match key:
            case 'q':
                self._client.quit()
                self._running = False
            case 'a':
                self._add_new_contact()
            case 'n':
                self._send_message()
            case 'l':
                contacts = self._client.get_contacts()
                current_contact_index = contacts.index(self._focused_user)
                next_index = (current_contact_index + 1) % len(contacts)
                self._focused_user = contacts[next_index]
                self._new_message[self._focused_user] = False
                self._max_scroll_position = self._client.message_count(self._focused_user) - (curses.LINES - 8)
                self._cur_scroll_position = 0
                self._message_buffer = []
                self._message_buffer_oldest = 0
                self._draw_left_panel()
                self._draw_main_panel()
            case 'h':
                contacts = self._client.get_contacts()
                current_contact_index = contacts.index(self._focused_user)
                prev_index = (current_contact_index - 1) % len(contacts)
                self._focused_user = contacts[prev_index]
                self._new_message[self._focused_user] = False
                self._max_scroll_position = self._client.message_count(self._focused_user) - (curses.LINES - 8)
                self._cur_scroll_position = 0
                self._message_buffer = []
                self._message_buffer_oldest = 0
                self._draw_left_panel()
                self._draw_main_panel()
            case 'j':
                if self._focused_user:
                    if self._cur_scroll_position > 0:
                        self._cur_scroll_position -= 1
                    self._draw_main_panel()
                    self._draw_bottom_bar()
            case 'k':
                if self._focused_user:
                    if self._cur_scroll_position < self._max_scroll_position:
                        self._cur_scroll_position += 1
                    self._draw_main_panel()
                    self._draw_bottom_bar()

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
        vcsms_client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, args.password, logger)
    else:
        password = input("Enter master password")
        vcsms_client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, password, logger)
    try:
        vcsms_client.run()
    except IncorrectMasterKeyException:
        print("Master password incorrect. Please try again.")
    application = Application(vcsms_client)
    curses.wrapper(application.run)
