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
        self.y = y
        self.x = x
        self.height = height
        self.cur_scroll = 0
        self.lines = []
        self.width = width
        self.pad = curses.newpad(height, width)
    
    def display(self):
        top_line = max(0, len(self.lines) - y - self.cur_scroll)
        self.pad.refresh(top_line, 0, y, x, y + height, x + width)

    def add_string(self, string: str):
        while string > self.width:
            self.lines.append(string[:self.width])
            string = string[self.width:]
        self.lines.append(string)

    def scroll_down(amount: int):
        self.cur_scroll = max(0, self.cur_scroll - amount)
    
    def scroll_up(amount: int):
        self.cur_scroll = max(self.cur_scroll + amount, len(self.lines) - y)

class Application:
    """A curses based client application for VCSMS"""
    def __init__(self, client: Client):
        """Instantiate the application

        Args:
            client (Client): An instance of vcsms.client.
                Provides the actual client functionality.
        """
        self._client = client
        self._id = client.get_id()
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
        self.__focused_user = ""
        self._focused_user_index = 0
        self._panel_sizes = {}
        self._contacts = client.get_contacts()
        if len(self._contacts) > 0:
            self.__focused_user = self._contacts[0][0]

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
            self._max_scroll_position = self._client.message_count(user) - (curses.LINES - 8)
        else:
            self._max_scroll_position = 0
        self._cur_scroll_position = 0
        self._message_buffer = []
        self._message_buffer_oldest = 0
        self._draw_left_panel()
        self._draw_main_panel()
        if bottom_bar_redraw:
            self._draw_bottom_bar()


    def _draw_top_bar(self):
        """Draw the top bar which displays the user's client ID"""
        self._top_bar.clear()
        self._top_bar.addstr(1, 1, f"Your ID: {self._client.get_id()}")
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
                instructions += "(n)ew message (r)ename (d)elete "
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

    def _flash_error(self, error: str):
        self._draw_bottom_bar(error, 1)
        time.sleep(1)
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
            if contact_name in self._new_message and self._new_message[contact_name] and self._focused_user != contact_name:
                display_name = f"*{display_name}"
            self._left_panel.addstr(i + 2, 1, display_name)

        self._left_panel.border()
        self._left_panel.refresh(0, 0, 0, 0, curses.LINES - 3, 26)

    def _get_message_lines(self, name: str, count: int):
        """Get the last *count* messages in ascending time order propertly formatted and split into lines
        """
        messages = self._client.get_messages(name, count)[::-1]
        lines = []
        max_width = self._panel_sizes["main"][1]
        for m, s in messages:
            if s == self._id:
                display_format = f"TO {name}: {m.decode('utf-8')}"
            else:
                display_format = f"FROM {s}: {m.decode('utf-8')}"
            while len(display_format) > max_width:
                lines.append(display_format[:max_width])
                display_format = display_format[max_width:]
            lines.append(display_format)
        return lines

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

    def _draw_main_panel(self):
        """Draw the main panel containing messages from the
        currently focused user.
        """
        self._main_panel.clear()
        num_to_display = curses.LINES - 8
        if self._cur_scroll_position + num_to_display > self._message_buffer_oldest:
            num_to_load = self._cur_scroll_position + num_to_display + 20
            self._message_buffer = self._get_message_lines(self._focused_user, num_to_load)
            self._message_buffer_oldest = len(self._message_buffer)

        end = self._cur_scroll_position + num_to_display
        messages_to_show = self._message_buffer[self._cur_scroll_position:end]

        for i, message in enumerate(messages_to_show):
            self._main_panel.addstr(i, 1, message)
        self._main_panel.refresh(0, 0, 4, 26, curses.LINES-4, curses.COLS-1)

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
            message = self._ask_input("Message", 3)
            if message:
                try:
                    self._client.send(self._focused_user, message.encode())
                except ClientException as e:
                    self._flash_error(e.message)
                    return
                self._max_scroll_position += 1
                self._message_buffer_oldest = 0
                self._cur_scroll_position = 0
            self._draw_main_panel()

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

    def _init_ui(self):
        self._left_panel = curses.newpad(curses.LINES - 3, 26)
        self._bottom_bar = curses.newwin(3, curses.COLS - 26, curses.LINES - 3, 26)
        self._left_panel_bottom_bar = curses.newwin(3, 26, curses.LINES - 3, 0)
        self._top_bar = curses.newwin(3, curses.COLS - 26, 0, 26)
        self._main_panel = curses.newpad(curses.LINES - 6, curses.COLS - 26)
        self._panel_sizes = {
            "main": (curses.LINES - 6, curses.COLS - 26),
            "left": (curses.LINES - 3, 26),
            "bottom": (3, curses.COLS - 26),
            "top": (3, curses.COLS - 26),
            "left_bottom": (3, 26)
        }
        self._stdscr.refresh()
        self._stdscr.nodelay(True)

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

    def run(self, stdscr: curses.window):
        """The main function to run the application.

        Invoked via curses.wrapper

        Args:
            stdscr (curses.window): The curses screen.
                Provided by curses.wrapper
        """
        self._stdscr = stdscr
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        if curses.COLS < 102 or curses.LINES < 9:
            self._client.quit()
            raise Exception("Window too small. Resize your terminal.")
        self._init_ui()
        self._max_scroll_position = self._client.message_count(self._focused_user) - (curses.LINES - 8)
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
                sender, group, _ = self._client.receive()
                contact_name = group or sender
                self._new_message[contact_name] = True
                if self._focused_user == contact_name:
                    self._max_scroll_position += 1
                    self._message_buffer_oldest = 0
                    self._cur_scroll_position = 0
                    self._draw_main_panel()
                if (contact_name, bool(group)) not in self._contacts:
                    self._contacts.append((contact_name, bool(group)))
                if not self._focused_user:
                    self._focused_user = chat_name
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
            case 'c':
                self._create_group()

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
        password = input("Enter master password: ")
        vcsms_client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory, password, logger)
    try:
        vcsms_client.run()
    except IncorrectMasterKeyException:
        print("Master password incorrect. Please try again.")
        quit()
    application = Application(vcsms_client)
    curses.wrapper(application.run)
