"""Simple display library for check-your-pulse."""

# Standard Python Libraries
import itertools
import os
import shutil
import sys
import threading
import time


class Color:
    """Provide us with a means of making colored text."""

    @staticmethod
    def _red(line: str) -> str:
        return f"\x1b[1;31m{line}\x1b[0m"

    @staticmethod
    def _green(line: str) -> str:
        return f"\x1b[1;32m{line}\x1b[0m"

    @staticmethod
    def _blue(line: str) -> str:
        return f"\x1b[1;34m{line}\x1b[0m"

    @staticmethod
    def _violet(line: str) -> str:
        return f"\x1b[1;35m{line}\x1b[0m"

    @staticmethod
    def _yellow(line: str) -> str:
        return f"\x1b[1;33m{line}\x1b[0m"


# Much of this code was bitten from the great yaspin library. We wanted to do some animation without our customers
# needing to install an external library, so we modified their spinner and got rid of things we didn't need for this
# use case.
# Check them out here: https://github.com/pavdmyt/yaspin
class Animation(Color):
    """Provide us with a means of making a spinner."""

    def __init__(self, text: str = ""):
        """
        Instantiate the Animation class, then the animation can be started with Animation.start(text).

        :param text: Text displayed to the right of the animation.
        """
        super().__init__()
        self._cycle = itertools.cycle(
            [
                "[   C]",
                "[  CI]",
                "[ CIS]",
                "[CISA]",
                "[ISA ]",
                "[SA  ]",
                "[A   ]",
                "[    ]",
            ]
        )
        self._stop_animation = threading.Event()
        self._stdout_lock = threading.Lock()
        self._animation_thread = threading.Thread()
        self.text: str = f" {text}"

    def _animation(self) -> None:
        """
        Run background thread started by start() and interrupted by done() or error().

        Returns:
            None
        """
        while not self._stop_animation.is_set():
            spin_phase = next(self._cycle)

            if os.name != "nt":
                out = self._blue(spin_phase) + self.text
            else:
                out = spin_phase + self.text

            with self._stdout_lock:
                _clear_console()
                sys.stdout.write(out)
                sys.stdout.flush()

            time.sleep(0.1)

    def start(self, text: str = "") -> None:
        """
        Start the background thread for our animation.

        Args:
            text (str), Optional: Text to print to the terminal after the animation.

        Returns:
            None
        """
        self._text_format(text)
        self._stop_animation = threading.Event()
        self._animation_thread = threading.Thread(target=self._animation)
        self._animation_thread.start()

    def done(self, text: str = "") -> None:
        """
        Stop our background thread and print a green [Done] in place of the animation.

        Args:
            text (str), Optional: Text to print after [Done].

        Returns:
            None
        """
        self._text_format(text)
        if self._animation_thread:
            self._stop_animation.set()
            self._animation_thread.join()

        _clear_console()
        if os.name != "nt":
            print(self._green("[Done]") + self.text)
        else:
            print("[Done]" + self.text)
        sys.stdout.write("\r")

    def error(self, text: str = "") -> None:
        """
        Stop our background thread and print a red [Error] in place of the animation.

        Args:
            text (str), Optional: Text to print after [Error].

        Returns:
            None
        """
        self._text_format(text)
        if self._animation_thread:
            self._stop_animation.set()
            self._animation_thread.join()

        _clear_console()

        if os.name != "nt":
            print(self._red("[Error]") + self.text)
        else:
            print("[Error]" + self.text)

    def update(self, text: str = "") -> None:
        """
        Update the text in the animation.

        Args:
            text (str): Text next to the animation.

        Returns:
            None

        """
        self.text = f" {text}"

    def _text_format(self, text):
        if text:
            self.text = f" {text}"

    @staticmethod
    def _hide_cursor():
        if os.name != "nt":
            sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    @staticmethod
    def _show_cursor():
        if os.name != "nt":
            sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def _clear_console():
    if os.name != "nt":
        sys.stdout.write("\033[2K\033[1G")
    sys.stdout.write("\r")


def _center(line):
    term_size = shutil.get_terminal_size(fallback=(80, 24)).columns
    line_len = len(line)
    pad_size = int((term_size - line_len) / 2)
    return pad_size


ascii_art = """
       _               _                                                     _
      | |             | |                                                   | |
   ___| |__   ___  ___| | ________ _   _  ___  _   _ _ __ ______ _ __  _   _| |___  ___
  / __| '_ \\ / _ \\/ __| |/ /______| | | |/ _ \\| | | | '__|______| '_ \\| | | | / __|/ _ \

 | (__| | | |  __/ (__|   <       | |_| | (_) | |_| | |         | |_) | |_| | \\__ \\  __/
  \\___|_| |_|\\___|\\___|_|\\_\\       \\__, |\\___/ \\__,_|_|         | .__/ \\__,_|_|___/\\___|
                                    __/ |                       | |
                                   |___/                        |_|                     \n
"""
