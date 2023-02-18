#!/bin/python
import curses
import curses.textpad
import argparse
import json
import os
import time
from vcsms.client import Client
from vcsms.logger import Logger
from vcsms.exceptions.client import IncorrectMasterKeyException, ClientException

class ScrollableTextBox:
    def __init__(self, y: int, x: int, height: int, width: int):
        self._y = y
        self._x = x
        self._height = height
        self.scroll = 0
        self._width = width
        self._line_buf = []
        self.pad = curses.newpad(30000, width)
    
    @property
    def num_lines(self): return len(self._line_buf)

    @property
    def y(self): return self._y

    @property
    def x(self): return self._x

    @property
    def height(self): return self._height

    @property
    def width(self): return self._width

    def display(self):
        top_line = max(0, self.num_lines - self._height - self.scroll)
        self.pad.clear()
        for i, v in enumerate(self._line_buf):
            self.pad.addstr(i, 1, v)
        self.pad.refresh(top_line, 0, self._y, self._x, self._y + self._height, self._x + self._width)

    def add_string(self, string: str):
        lines = string.split('\n')
        for line in lines:
            while len(line) > self._width - 1:
                self._line_buf.append(line[:self._width - 1])
                line = line[self._width - 1:]
            self._line_buf.append(line)

    def scroll_down(self, amount: int):
        self.scroll = max(0, self.scroll - amount)
    
    def scroll_up(self, amount: int):
        self.scroll = min(self.scroll + amount, self.get_max_scroll())

    def get_max_scroll(self) -> int:
        return len(self._line_buf) - self._height

    def clear(self):
        self.pad.clear()
        self.scroll = 0
        self._line_buf.clear()

class Application:
    """A curses based client application for VCSMS"""
    def __init__(self, stdscr: curses.window, client: Client):
        """Instantiate the application

        Args:
            client (Client): An instance of vcsms.client.
                Provides the actual client functionality.
        """
        self._stdscr = stdscr
        self._client = client
        self._id = client.id
        self._new_message = {}
        self._running = False
        self.__focused_user = ""
        self._focused_user_index = 0
        self._panel_sizes = {}
        self._contacts = client.get_contacts()
        if len(self._contacts) > 0:
            self.__focused_user = self._contacts[0][0]
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        self._left_panel = curses.newpad(curses.LINES - 3, 26)
        self._bottom_bar = curses.newwin(3, curses.COLS - 26, curses.LINES - 3, 26)
        self._left_panel_bottom_bar = curses.newwin(3, 26, curses.LINES - 3, 0)
        self._top_bar = curses.newwin(3, curses.COLS - 26, 0, 26)
        self._main_panel = ScrollableTextBox(3, 26, curses.LINES - 7, curses.COLS - 27)
        self._panel_sizes = {
            "main": (curses.LINES - 6, curses.COLS - 26),
            "left": (curses.LINES - 3, 26),
            "bottom": (3, curses.COLS - 26),
            "top": (3, curses.COLS - 26),
            "left_bottom": (3, 26)
        }
        self._stdscr.refresh()
        self._stdscr.nodelay(True)

    @property
    def _focused_user(self) -> str:
        """Get the name of the currently focused user.

        Setting this automatically resets the scroll position and
        redraws the left panel, main panel, and bottom bar if required.
        """
        return self.__focused_user

    @_focused_user.setter
    def _focused_user(self, user: str):
        bottom_bar_redraw = bool(user) != bool(self.__focused_user)
        # bottom bar should be redrawn if a user was previously or currently unfocused
        self.__focused_user = user
        if user:
            self._new_message[user] = False

        self._draw_left_panel()
        self._draw_main_panel(True)
        if bottom_bar_redraw:
            self._draw_bottom_bar()


    def _draw_top_bar(self):
        """Draw the top bar which displays the user's client ID"""
        self._top_bar.clear()
        self._top_bar.addstr(1, 1, f"Your ID: {self._client.id}")
        self._top_bar.border()
        self._top_bar.refresh()

    def _draw_bottom_bar(self, message: str = "", color_pair: int = 0):
        """Draw the bottom bar containing an optional non-default message.

        By default displays dynamic usage instructions
        Args:
            message (str, optional): The message to display.
            color_pair (int, optional): The curses color pair to use.
        """
        self._bottom_bar.clear()
        if message:
            self._bottom_bar.addstr(1, 1, message, curses.color_pair(color_pair))
        else:
            instructions = ""
            if self._focused_user:
                instructions += "(n)ew msg (r)ename (d)elete (c)reate grp "
            instructions += "(a)dd (q)uit "
            if self._main_panel.scroll > 0:
                instructions += "j \u2193 "
            if self._main_panel.scroll < self._main_panel.get_max_scroll():
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

    def _flash_error(self, error: str):
        self._draw_bottom_bar(error, 1)
        time.sleep(0.5)
        self._draw_bottom_bar()

    def _draw_left_panel(self):
        """Draw the left panel containing the user's contacts."""
        self._left_panel.clear()
        self._left_panel.addstr(1, 1, "Contacts: ")
        for i, contact in enumerate(self._contacts):
            contact_name, is_group = contact
            display_name = contact_name
            if contact_name == self._focused_user:
                display_name = f"[{display_name}]"
            if is_group:
                display_name = f"%{display_name}"
            if contact_name in self._new_message and self._new_message[contact_name]:
                if contact_name == self._focused_user:
                    self._new_message[contact_name] = False
                else:
                    display_name = f"*{display_name}"
            self._left_panel.addstr(i + 2, 1, display_name)

        self._left_panel.border()
        self._left_panel.refresh(0, 0, 0, 0, curses.LINES - 3, 26)

    def _create_group(self):
        """Prompt the user to create a group chat."""
        name = self._ask_input("Name")
        users = []
        if name:
            while True:
                user = self._ask_input("User")
                if not user:
                    break
                users.append(user)
        
        if len(users) > 0:
            try:
                self._client.create_group(name, *users)
            except ClientException as e:
                self._flash_error(e.message)
                return

        self._contacts = self._client.get_contacts()
        self._draw_left_panel()
        if not self._focused_user:
            self._focused_user = name

    def _draw_main_panel(self, reload_messages = False):
        """Draw the main panel containing messages from the
        currently focused user.
        """
        if reload_messages:
            self._main_panel.clear()
            self._message_buffer = self._client.get_messages(self._focused_user)[::-1]
            for message, sender in self._message_buffer:
                if sender == self._id:
                    self._main_panel.add_string(f"TO {self._focused_user}: {message.decode('utf-8')}")
                else:
                    self._main_panel.add_string(f"FROM {sender}: {message.decode('utf-8')}")
        self._main_panel.display()

    def _ask_input(self, prompt: str, height: int = 1) -> str:
        """Ask for input given a specific prompt.

        Args:
            label (str): The prompt given to the user.
            height (int): The height of the textbox.

        Returns:
            str: The input typed by the user
        """
        self._draw_bottom_bar(f"{prompt}: ")
        textbox_width = curses.COLS - (26 + len(prompt) + 3)
        textbox_x = 26 + len(prompt) + 3
        textbox_y = curses.LINES - (height + 1)
        textbox_container = curses.newwin(height, textbox_width, textbox_y, textbox_x)
        textbox = curses.textpad.Textbox(textbox_container)
        self._stdscr.refresh()
        textbox.edit()
        self._draw_bottom_bar()
        return textbox.gather().strip()

    def _add_new_contact(self):
        """Add a new contact with user supplied nickname and client ID"""
        nickname = self._ask_input("Name")
        client_id = self._ask_input("ID")
        try:
            self._client.add_contact(nickname, client_id)
        except ClientException as e:
            self._flash_error(e.message)
            return

        self._contacts = self._client.get_contacts()
        if self._focused_user == client_id or not self._focused_user:
            self._focused_user = nickname
        else:
            self._draw_left_panel()  # setting focused user does this automatically but needs to be done.

    def _send_message(self):
        """Prompt the user to send a message to the currently focused user.

        Cancelled if the user does not enter a message or there is no
        currently focused user.
        """
        if self._focused_user:
            message = self._ask_input("Message")
            if message:
                try:
                    self._client.send(self._focused_user, message.encode())
                except ClientException as e:
                    self._flash_error(e.message)
                    return
            self._draw_main_panel(True)

    def _rename_contact(self):
        """Prompt the user to enter a new name for the currently focused user.

        Cancelled if the user does not enter a name.
        """
        if self._focused_user:
            new_name = self._ask_input("New Name")
            if new_name:
                try:
                    self._client.rename_contact(self._focused_user, new_name)
                except ClientException as e:
                    self._flash_error(e.message)
                self._contacts = self._client.get_contacts()
                self._focused_user = new_name

    def _delete_contact(self):
        if self._focused_user:
            confirm = self._ask_input(f"Delete {self._focused_user}? (y/N)")
            if confirm.lower() in {'y', 'yes'}:
                self._client.delete_contact(self._focused_user)
                self._contacts = self._client.get_contacts()
                if len(self._contacts) > 0:
                    self._focused_user = self._contacts[0][0]
                else:
                    self._focused_user = ""

    def _cycle_focused_user(self, increment: int):
        if self._focused_user:
            next_index = (self._focused_user_index + increment) % len(self._contacts)
            self._focused_user = self._contacts[next_index][0]
            self._focused_user_index = next_index

    @property
    def running(self) -> bool:
        """Get whether the program is currently running

        Returns:
            bool: If the program is running
        """
        return self._running

    def run(self):
        """The main function to run the application.

        Invoked via curses.wrapper

        Args:
            stdscr (curses.window): The curses screen.
                Provided by curses.wrapper
        """
        if curses.COLS < 102 or curses.LINES < 9:
            self._client.quit()
            raise Exception("Window too small. Resize your terminal.")
        if self._focused_user:
            self._draw_main_panel(True)
            self._draw_bottom_bar()
        else:
            self._draw_main_panel()
            self._draw_bottom_bar("(a)dd contact, (q)uit")
        self._draw_top_bar()
        self._draw_left_panel()
        self._draw_left_panel_bottom_bar()
        self._running = True
        last_poll = 0
        while self._running:
            if time.time() - last_poll >= 1:
                last_poll = time.time()
                while self._client.new_message():
                    sender, group, _ = self._client.receive()
                    contact_name = group or sender
                    self._new_message[contact_name] = True
                    if self._focused_user == contact_name:
                        self._draw_main_panel(True)
                    if (contact_name, bool(group)) not in self._contacts:
                        self._contacts.append((contact_name, bool(group)))
                    if not self._focused_user:
                        self._focused_user = contact_name
                    self._draw_left_panel()
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
            case 'r':
                self._rename_contact()
            case 'd':
                self._delete_contact()
            case 'l':
                self._cycle_focused_user(1)
            case 'h':
                self._cycle_focused_user(-1)
            case 'j':
                if self._focused_user:
                    self._main_panel.scroll_down(1)
                    self._draw_main_panel()
                    self._draw_bottom_bar()
            case 'k':
                if self._focused_user:
                    self._main_panel.scroll_up(1)
                    self._draw_main_panel()
                    self._draw_bottom_bar()
            case 'c':
                self._create_group()

def run(stdscr: curses.window, client: Client):
    app = Application(stdscr, client)
    app.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=str, help="The server's .vcsms config file")
    parser.add_argument("-d", "--directory", type=str, default="vcsms", help="Where to store application-generated files")
    parser.add_argument("-p", "--password", type=str, help="The application master password")
    args = parser.parse_args()
    with open(args.config, 'r', encoding='utf-8') as conf:
        serverconf = json.load(conf)
    logger = Logger(5, os.path.join(args.directory, "client.log"))
    if args.password:
        vcsms_client = Client(serverconf["ip"], serverconf["port"], serverconf["fingerprint"], args.directory, args.password, logger)
    else:
        password = input("Enter master password: ")
        vcsms_client = Client(serverconf["ip"], serverconf["port"], serverconf["fingerprint"], args.directory, password, logger)
    try:
        vcsms_client.run()
    except IncorrectMasterKeyException:
        print("Master password incorrect. Please try again.")
        quit()
    except ClientException:
        print(f"Client failed to connect to server. See log.txt for more information.")
        quit()
    curses.wrapper(run, vcsms_client)
