import sys

Color = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'ENDC': '\033[0m',
}

if sys.stdout.isatty() == False:
    for color in Color:
        Color[color] = ''

