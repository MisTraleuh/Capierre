from utils.color import Color

def msg_success(message):
    print(f'{Color["GREEN"]}[+] {message}{Color["ENDC"]}')

def msg_error(message):
    print(f'{Color["RED"]}[-] {message}{Color["ENDC"]}')
    
def msg_warning(message):
    print(f'{Color["YELLOW"]}[!] {message}{Color["ENDC"]}')
    
def msg_info(message):
    print(f'{Color["BLUE"]}[i] {message}{Color["ENDC"]}')
