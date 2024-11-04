import sys
from utils.messages import msg_success, msg_error
import os

class CapierreParsing():
    """
    This class is responsible for parsing the arguments
    """
    def __init__(self: object) -> None:
        self.name = 'Capierre'
        self.version = '1.0.0'
        self.file_to_hide = None
        self.type_file = None
        self.sentence = None
        self.binary_file = 'capierre_binary'

    """
    This function prints the help message
    """
    def print_help(self: object) -> None:
        print(f'Usage: {self.name} <file> <sentence>')
        print(f'Options:')
        print(f'  -h, --help     Show this help message and exit')
        print(f'  -v, --version  Show version of the tool')
        print(f'  -fth, --file-to-hide <file>  File to hide')
        print(f'  -s, --sentence <sentence>  Sentence to hide')
        print(f'  -f, --file <file>  File to compile')
        print(f'  -o, --output <file>  Output file')

    """
    This function checks if the file is supported
    @return bool - True if the file is supported, False otherwise
    """
    def check_file(self: object) -> bool:  
        # https://stackoverflow.com/a/61065546/23570806
        magic_numbers = {
            'png': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            'elf': bytes([0x7F, 0x45, 0x4C, 0x46]),
        }
        extension_files = {
            'c': '.c',
            'cpp': '.cpp',
        }
        try:
            with open(self.file_to_hide, 'rb') as fd:
                file_head = fd.read()

            for name, magic in magic_numbers.items():
                if file_head.startswith(magic):
                    self.type_file = name
                    msg_success(f'File detected: {self.type_file}')
                    return True
            for name, end in extension_files.items():
                if self.file_to_hide.endswith(end):
                    self.type_file = name
                    msg_success(f'File detected: {self.type_file}')
                    return True
            else:
                msg_error('File not supported')
                return False
        except Exception as e:
            raise e
    """
    This function gets the sentence from the arguments
    @param argv - The arguments
    @return str - The sentence
    """
    def argv_to_sentence(self: object, argv: object) -> object:
        if (any(arg in argv for arg in ["--sentence", "-s"])):
            return argv[(argv.index("--sentence") if "--sentence" in argv else argv.index("-s")) + 1]
        if (any(arg in argv for arg in ["--file", "-f"])):
            file_index = argv[(argv.index("--file") if "--file" in argv else argv.index("-f")) + 1]
            if (os.path.exists(file_index) == False):
                msg_error(f'File not found: {file_index}')
                exit(1)
            with open(file_index, 'r') as file:
                return file.read()
        return None

    """
    This function checks the arguments
    @return tuple[bool, int] - A tuple with a boolean and an integer
    """
    def check_args(self: object) -> tuple[bool, int]:
        ALL_ARGS = [
            "--help", "-h",
            "--version", "-v",
            "--file-to-hide", "-fth",
            "--sentence", "-s",
            "--file", "-f",
        ]

        if any(arg in sys.argv for arg in ["--help", "-h"]):
            self.print_help()
            return (False, 0)
        if any(arg in sys.argv for arg in ['--version', '-v']):
            print(f'{self.name} v{self.version}')
            return (False, 0)
        if len(sys.argv) < 5:
            msg_error(f'Usage: {self.name} -h')
            return (False, 1)
        if not any(arg in sys.argv for arg in ["--file-to-hide", "-fth"]) or \
           not any(arg in sys.argv for arg in ["--sentence", "-s", "--file", "-f"]):
            msg_error(f'Usage: {self.name} -h')
            return (False, 1)
        self.file_to_hide = sys.argv[(sys.argv.index("--file-to-hide") if "--file-to-hide" in sys.argv else sys.argv.index("-fth")) + 1]
        self.sentence = self.argv_to_sentence(sys.argv)
        if (any(arg in sys.argv for arg in ["--output", "-o"])):
            self.binary_file = sys.argv[(sys.argv.index("--output") if "--output" in sys.argv else sys.argv.index("-o")) + 1]
        if (os.path.exists(self.file_to_hide) == False):
            msg_error(f'File not found: {self.file_to_hide}')
            return (False, 1)
        if (self.sentence == None):
            msg_error('Sentence not found')
            return (False, 1)
        if (self.binary_file == None):
            msg_error('Output file not found')
            return (False, 1)
        if (self.check_file() == False):
            return (False, 1)
        return (True, 0)
