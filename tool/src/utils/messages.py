from __future__ import annotations
from utils.color import Color

"""
This function prints a success message
@param message: str - The message to print
"""


def msg_success(message: str) -> None:
    print(f'{Color["GREEN"]}[+] {message}{Color["ENDC"]}')


"""
This function prints an error message
@param message: str - The message to print
"""


def msg_error(message: str) -> None:
    print(f'{Color["RED"]}[-] {message}{Color["ENDC"]}')


"""
This function prints a warning message
@param message: str - The message to print
"""


def msg_warning(message: str) -> None:
    print(f'{Color["YELLOW"]}[!] {message}{Color["ENDC"]}')


"""
This function prints an info message
@param message: str - The message to print
"""


def msg_info(message: str) -> None:
    print(f'{Color["BLUE"]}[i] {message}{Color["ENDC"]}')
