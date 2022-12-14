from vcsms.client import Client
import curses
import argparse
import json

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

    def draw_bottom_bar(self):
        self.bottom_bar.clear()
        self.bottom_bar.addstr(1, 1, "(n)ew message, (a)dd contact, (q)uit")
        self.bottom_bar.border()
        self.bottom_bar.refresh()

    def draw_left_panel(self):
        self.left_panel.clear()
        for i in range(5):
            self.left_panel.addstr(i + 1, 1, f"Contact #{i+1}")
        self.left_panel.border()
        self.left_panel.refresh(0, 0, 0, 0, curses.LINES, 25)

    def draw_main_panel(self):
        self.main_panel.clear()
        for i in range(len(self.message_buffer)):
            self.main_panel.addstr(i, 1, self.message_buffer[i]) # this crashes when the messages no longer fit on the screen. probably should limit them.
        self.main_panel.refresh(0, 0, 4, 26, curses.LINES-4, curses.COLS)

    def main(self, stdscr):
        self.left_panel = curses.newpad(curses.LINES, 25)
        self.bottom_bar = curses.newwin(3, curses.COLS-26, curses.LINES-3, 26)
        self.top_bar = curses.newwin(3, curses.COLS-26, 0, 26)
        self.main_panel = curses.newpad(curses.LINES-6, curses.COLS-26)
        stdscr.refresh()
        stdscr.nodelay(True)
        self.draw_bottom_bar()
        self.draw_top_bar()
        self.draw_left_panel()
        self.draw_main_panel()
        while True:
            if self.client.new_message():
                msg = self.client.receive()
                self.message_buffer.append(f"{msg[0]}: {msg[1]}")
                self.draw_main_panel()
            try:
                key = stdscr.getch()
            except:
                key = -1

            if key == 113:
                self.client.quit()
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="The ip address of the server to connect to")
    parser.add_argument("config", type=str, help="The server's .vcsms config file")
    parser.add_argument("-d", "--directory", type=str, default="vcsms", help="Where to store application-generated files")
    args = parser.parse_args()
    with open(args.config, 'r') as conf:
        serverconf = json.loads(conf.read())
    client = Client(args.ip, serverconf["port"], serverconf["fingerprint"], args.directory)
    client.run()
    application = Application(client)
    curses.wrapper(application.main)

    
