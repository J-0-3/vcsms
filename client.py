#!/usr/bin/env python3
import curses
import argparse
import getpass
import json
import os
import time
from vcsms.client import Client
from vcsms.logger import Logger
from vcsms.exceptions.client import IncorrectMasterKeyException, ClientException

class UIComponent:
    def __init__(self, screen: curses.window, 
                 y: int, x: int, height: int, width: int,
                 pad_internal_height: int, pad_internal_width: int, 
                 border: bool):

        self._y = y
        self._x = x
        self._width = width
        self._height = height
        if border:
            self._width -= 2
            self._height -= 2
        self._screen = screen
        self._border = border
        self._pad = curses.newpad(pad_internal_height, pad_internal_width)
        screen.refresh()
    
    @property
    def x(self) -> int: return self._x
    
    @property
    def y(self) -> int: return self._y
    
    @property
    def width(self) -> int: return self._width
    
    @property
    def height(self) -> int: return self._height
    
    def display(self):
        self._pad.clear()
        if self._border:
            self._pad.border()
        self._pad.refresh(0, 0, self._y, self._x, self._y + self._height, self._x + self._width)
    
class ScrollingTextBox(UIComponent):
    """A simple one line horizontal scrolling text input box"""
    MAXCHARS = 16384
    def __init__(self, window: curses.window, y: int, x: int, width: int):
        """Construct a ScrollingTextBox
        
        Args:
            window (window): The curses main screen (stdscr)
            y (int): The y coordinate of the top left corner of the box.
            x (int): The x coordinate of the top left corner of the box.
            width (int): The width of the textbox.
        """
        super().__init__(window, y, x, 1, width, 1, self.MAXCHARS, False)
        self._scroll = 0
        self._contents = ""

    @property
    def contents(self) -> str: return self._contents

    def display(self):
        self._pad.clear()
        self._pad.addstr(self._contents)
        self._pad.refresh(0, self._scroll, self._y, self._x, self._y + 1, self._x + self._width)

    def input(self):
        """Accept input from the user until the enter key is pressed.
        
        Returns:
            str: The text that was entered
        """
        self._screen.nodelay(False)
        while (key := self._screen.getkey()) not in ('\n', "KEY_ENTER"):
            if key in ('KEY_BACKSPACE', '\b'):
                if len(self._contents) > self._width:
                    self._scroll -= 1
                self._contents = self._contents[:-1]
            elif len(key) == 1:
                self._contents += key
                if len(self._contents) > self._width:
                    self._scroll += 1
            self.display()
        self._screen.nodelay(True)
        return self._contents
    
    def clear(self):
        self._contents = ""
        self.display()

class ScrollablePad(UIComponent):
    """A vertically scrollable text pad"""
    MAXLINES = 30000
    def __init__(self, screen: curses.window, y: int, x: int, height: int, width: int, border: bool):
        """Construct a ScrollablePad
        
        Args:
            y (int): The y coordinate of the top-left corner of the pad.
            x (int): The x coordinate of the top-left corner of the pad.
            height (int): The height of the pad.
            width (int): The width of the pad.
        """
        super().__init__(screen, y, x, height, width, self.MAXLINES, width, border)
        self.scroll = 0
        self._line_buf = []
    
    @property
    def num_lines(self) -> int: return len(self._line_buf)

    @property
    def max_scroll(self) -> int: return len(self._line_buf) - self._height

    def display(self):
        """Redraw the pad on the screen to reflect the current contents."""
        top_line = max(0, self.num_lines - self._height - self.scroll)
        self._pad.clear()
        if self._border:
            self._pad.border()
            for i, v in enumerate(self._line_buf):
                self._pad.addstr(i + 1, 1, v)
            self._pad.refresh(
                top_line - 1, 0, 
                self._y, self._x, 
                self._y + self._height + 2, self._x + self._width + 2
            )
        else:
            for i, v in enumerate(self._line_buf):
                self._pad.addstr(i, 1, v)
            self._pad.refresh(
                top_line, 0, 
                self._y, self._x, 
                self._y + self._height, self._x + self._width
            )

    def add_string(self, string: str):
        """Append a string to the end of the pad.
        If the string is longer than the width of the pad it will be split
        into multiple lines.
        
        Args:
            string (str): The string to add
        """
        lines = string.split('\n')
        for line in lines:
            while len(line) > self._width - 1:
                if len(self._line_buf) < self.MAXLINES:
                    self._line_buf.append(line[:self._width - 1])
                line = line[self._width - 1:]
            if len(self._line_buf) < self.MAXLINES:
                self._line_buf.append(line)

    def scroll_down(self, amount: int):
        """Scroll the view of the pad down.
        
        Args:
            amount (int): The amount of lines to scroll the pad by.
        """
        self.scroll = max(0, self.scroll - amount)
    
    def scroll_up(self, amount: int):
        """Scroll the view of the pad up.
        
        Args:
            amount (int): The amount of lines to scroll the pad by.
        """
        self.scroll = min(self.scroll + amount, self.max_scroll)

    def clear(self):
        """Delete all contents from the pad."""
        self._pad.clear()
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
        self.__focused_user_name = ""
        self._focused_user_index = 0
        self._panel_sizes = {}
        self._contacts = client.contacts
        if len(self._contacts) > 0:
            self.__focused_user_name = self._contacts[0][0]
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        self._panel_sizes = {
            "main": (curses.LINES - 7, curses.COLS - 27),
            "left": (curses.LINES - 4, 26),
            "bottom": (3, curses.COLS - 27),
            "top": (3, curses.COLS - 27),
            "left_bottom": (3, 26)
        }
        self._left_panel = ScrollablePad(stdscr, 0, 0, *(self._panel_sizes["left"]), True)
        self._bottom_bar = curses.newwin(*self._panel_sizes["bottom"], curses.LINES - 3, 26)
        self._left_panel_bottom_bar = curses.newwin(*self._panel_sizes["left_bottom"], curses.LINES - 3, 0)
        self._top_bar = curses.newwin(*self._panel_sizes["top"], 0, 26)
        self._main_panel = ScrollablePad(self._stdscr, 3, 26, *self._panel_sizes["main"], False)
        self._stdscr.refresh()
        self._stdscr.nodelay(True)

    @property
    def _focused_user_name(self) -> str:
        """Get the name of the currently focused user.

        Setting this automatically resets the scroll position and
        redraws the left panel, main panel, and bottom bar if required.
        """
        return self.__focused_user_name

    @_focused_user_name.setter
    def _focused_user_name(self, user: str):
        bottom_bar_redraw = user != self.__focused_user_name
        # bottom bar should be redrawn if a user was previously or currently unfocused
        self.__focused_user_name = user
        if user:
            self._new_message[user] = False

        self._draw_left_panel()
        self._draw_main_panel(True)
        if bottom_bar_redraw:
            self._draw_bottom_bar()

    def _draw_top_bar(self):
        """Draw the top bar which displays the user's client ID"""
        self._top_bar.clear()
        id = self._client.id
        id_formatted = ':'.join([id[i:i+4] for i in range(0, len(id), 4)])
        self._top_bar.addstr(1, 1, f"Your ID: {id_formatted}")
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
            if self._focused_user_name:
                instructions += "(n)ew msg (r)ename (d)elete (c)reate grp "
            instructions += "(a)dd (q)uit "
            if self._main_panel.scroll > 0:
                instructions += "j \u2193 "
            if self._main_panel.scroll < self._main_panel.max_scroll:
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
        self._left_panel.add_string("Contacts:")
        self._left_panel.add_string("")
        focused_line = 0
        for i, contact in enumerate(self._contacts):
            contact_name, is_group = contact
            display_name = contact_name
            if contact_name == self._focused_user_name:
                display_name = f"[{display_name}]"
                focused_line = i + 2
            if is_group:
                display_name = f"%{display_name}"
            if contact_name in self._new_message and self._new_message[contact_name]:
                if contact_name == self._focused_user_name:
                    self._new_message[contact_name] = False
                else:
                    display_name = f"*{display_name}"
            self._left_panel.add_string(display_name)
        self._left_panel.scroll_up(self._left_panel.max_scroll)
        if focused_line >= self._left_panel.height:
            self._left_panel.scroll_down(focused_line - self._left_panel.height + 1)

        self._left_panel._pad.border()
        self._left_panel.display()

    def _create_group(self):
        """Prompt the user to create a group chat."""
        name = self._ask_input("Name")
        users = []
        if name:
            while True:
                user = self._ask_input("User")
                if not user:
                    break
                if user == self._id:
                    self._flash_error("Cannot add yourself to a group")
                    continue
                users.append(user)
        
        if len(users) > 0:
            try:
                self._client.create_group(name, *users)
            except ClientException as e:
                self._flash_error(e.message)
                return

            self._contacts = self._client.contacts
            if not self._focused_user_name:
                self._focused_user_name = name
                self._draw_bottom_bar()
            self._draw_left_panel()

    def _draw_main_panel(self, reload_messages = False):
        """Draw the main panel containing messages from the
        currently focused user.
        """
        if reload_messages:
            self._main_panel.clear()
            self._message_buffer = self._client.get_messages(self._focused_user_name)[:ScrollablePad.MAXLINES][::-1]
            for message, sender in self._message_buffer:
                if sender == self._id:
                    self._main_panel.add_string(f"TO {self._focused_user_name}: {message.decode('utf-8')}")
                else:
                    self._main_panel.add_string(f"FROM {sender}: {message.decode('utf-8')}")
        self._main_panel.display()

    def _ask_input(self, prompt: str) -> str:
        """Ask for input given a specific prompt.

        Args:
            label (str): The prompt given to the user.
            height (int): The height of the textbox.

        Returns:
            str: The input typed by the user
        """
        self._draw_bottom_bar(f"{prompt}: ")
        textbox_width = self._panel_sizes["bottom"][1] - (len(prompt) + 3)
        textbox_x = self._panel_sizes["left"][1] + (len(prompt) + 3)
        textbox_y = curses.LINES - 2
        textbox = ScrollingTextBox(self._stdscr, textbox_y, textbox_x, textbox_width)
        textbox.display()
        textbox.input()
        self._draw_bottom_bar()
        return textbox.contents

    def _add_new_contact(self):
        """Add a new contact with user supplied nickname and client ID"""
        nickname = self._ask_input("Name")
        client_id = self._ask_input("ID").replace(':', '')
        try:
            self._client.add_contact(nickname, client_id)
        except ClientException as e:
            self._flash_error(e.message)
            return

        self._contacts = self._client.contacts
        if self._focused_user_name == client_id or not self._focused_user_name:
            self._focused_user_name = nickname
        else:
            self._draw_left_panel()  # setting focused user does this automatically but needs to be done.

    def _send_message(self):
        """Prompt the user to send a message to the currently focused user.

        Cancelled if the user does not enter a message or there is no
        currently focused user.
        """
        if self._focused_user_name:
            message = self._ask_input("Message")
            if message:
                try:
                    self._client.send(self._focused_user_name, message.encode())
                except ClientException as e:
                    self._flash_error(e.message)
                    return
            self._draw_main_panel(True)

    def _rename_contact(self):
        """Prompt the user to enter a new name for the currently focused user.

        Cancelled if the user does not enter a name.
        """
        if self._focused_user_name:
            new_name = self._ask_input("New Name")
            if new_name:
                try:
                    self._client.rename_contact(self._focused_user_name, new_name)
                except ClientException as e:
                    self._flash_error(e.message)
                self._contacts = self._client.contacts
                self._focused_user_name = new_name

    def _delete_contact(self):
        if self._focused_user_name:
            confirm = self._ask_input(f"Delete {self._focused_user_name}? (y/N)")
            if confirm.lower() in {'y', 'yes'}:
                self._client.delete_contact(self._focused_user_name)
                self._contacts = self._client.contacts
                if len(self._contacts) > 0:
                    self._focused_user_name = self._contacts[0][0]
                else:
                    self._focused_user_name = ""

    def _cycle_focused_user(self, increment: int):
        if self._focused_user_name:
            next_index = (self._focused_user_index + increment) % len(self._contacts)
            self._focused_user_name = self._contacts[next_index][0]
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
        if self._focused_user_name:
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
                while self._client.new:
                    event, info = self._client.receive()
                    if event == "ERROR":
                        self._flash_error(info)
                    
                    elif event == "DISCONNECT":
                        self._flash_error("Server unexpectedly closed the connection.")
                        self._flash_error("Shutting down program...")
                        self._running = False
                        break

                    elif event == "MESSAGE":
                        sender, group, _ = info
                        contact_name = group or sender
                        self._new_message[contact_name] = True
                        if self._focused_user_name == contact_name:
                            self._draw_main_panel(True)
                            self._draw_bottom_bar()
                        if (contact_name, bool(group)) not in self._contacts:
                            self._contacts.append((contact_name, bool(group)))
                        if not self._focused_user_name:
                            self._focused_user_name = contact_name
                        self._draw_left_panel()

                    else:
                        self._contacts = self._client.contacts
                        if event == "RENAMEGROUP":
                            old_name, new_name = info
                            if old_name in self._new_message and self._new_message[old_name]:
                                self._new_message.pop(old_name)
                                self._new_message[new_name] = True
                            if self._focused_user_name == old_name:
                                self._focused_user_name = new_name

                        elif event == "DELETEGROUP":
                            if self._focused_user_name == info:
                                if len(self._contacts) > 0:
                                    self._focused_user_name = self._contacts[0][0]
                                else:
                                    self._focused_user_name = ""
                        
                        self._draw_left_panel()
                        self._draw_main_panel(True)
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
                if self._focused_user_name:
                    self._main_panel.scroll_down(1)
                    self._draw_main_panel()
                    self._draw_bottom_bar()
            case 'k':
                if self._focused_user_name:
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
    parser.add_argument("-d", "--directory", type=str, default="vcsms_client", help="where to store application-generated files")
    parser.add_argument("-c", "--config", type=str, help="the server's .vcsms config file (ignores -i, -p and -f)")
    parser.add_argument("-i", "--ip", type=str, help="the server's IP address (must be used in combination with -p and -f)")
    parser.add_argument("-p", "--port", type=str, help="the server's port (must be used in combination with -i and -f)")
    parser.add_argument("-f", "--fingerprint", type=str, help="the server's fingerprint (must be used in combination with -i and -p)")
    args = parser.parse_args()
    logger = Logger(5, os.path.join(args.directory, "log.txt"))
    if args.config:
        with open(args.config, 'r', encoding='utf-8') as conf:
            serverconf = json.load(conf)
            vcsms_client = Client(serverconf["ip"], serverconf["port"], serverconf["fingerprint"], args.directory, logger)
    else:
        if args.ip and args.port and args.fingerprint:
            vcsms_client = Client(args.ip, args.port, args.fingerprint, args.directory, logger)
        else:
            print("Error: No configuration file is not supplied and the -i, -p and -f flags have not been used.")
            quit()
    password = getpass.getpass(prompt="Enter master password: ")
    try:
        vcsms_client.run(password)
    except IncorrectMasterKeyException:
        print("Master password incorrect. Please try again.")
        quit()
    except ClientException:
        print("Client failed to connect to server. See log.txt for more information.")
        quit()
    curses.wrapper(run, vcsms_client)
