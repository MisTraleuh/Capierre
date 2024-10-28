import sys
from utils.messages import msg_success, msg_error, msg_warning, msg_info
from capierre.compiling_code import compile_code

class CapierreParsing():
    def __init__(self: object) -> None:
        self.name = 'Capierre'
        self.version = '1.0.0'
        self.file = None
        self.type_file = None
        self.sentence = None

    def print_help(self: object) -> None:
        print(f'Usage: {self.name} <file> <sentence>')
        print(f'Options:')
        print(f'  -h, --help     Show this help message and exit')
        print(f'  -v, --version  Show version of the tool')

    # https://stackoverflow.com/a/61065546/23570806
    def check_file(self: object) -> bool:  
        magic_numbers = {
            'png': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            'elf': bytes([0x7F, 0x45, 0x4C, 0x46]),
        }
        extension_files = {
            'c': '.c',
            'cpp': '.cpp',
            'h': '.h',
        }
        try:
            with open(self.file, 'rb') as fd:
                file_head = fd.read()

            for name, magic in magic_numbers.items():
                if file_head.startswith(magic):
                    self.type_file = name
                    msg_success(f'File detected: {self.type_file}')
                    return True
            for name, end in extension_files.items():
                if self.file.endswith(end):
                    self.type_file = name
                    msg_success(f'File detected: {self.type_file}')
                    return True
            else:
                msg_error('File not supported')
        except Exception as e:
            raise e

    def check_args(self: object) -> tuple:
        if len(sys.argv) < 3 and sys.argv[1] not in ['--help', '-h']:
            msg_error(f'Usage: {self.name} <file> <sentence>')
            return (False, 1)
        if (sys.argv[1] in ['--help', '-h']):
            self.print_help()
            return (False, 0)
        if (sys.argv[1] in ['--version', '-v']):
            print(f'{self.name} v{self.version}')
            return (False, 0)
        self.file = sys.argv[1]
        self.sentence = sys.argv[2]
        self.check_file()
        return (True, 0)

def main():
    capierre = CapierreParsing()
    statement, exit_status = capierre.check_args()
    if (statement == False):
        sys.exit(exit_status)
    compile_code(capierre.file, capierre.sentence)

if __name__ == '__main__':
    main()
