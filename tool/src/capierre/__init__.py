import sys
from utils.messages import msg_success, msg_error
from capierre.compiling_code import compile_code

class Capierre:
    def __init__(self: object, file: str, type_file: str, sentence: str) -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence
        

    def hide_information(self: object) -> None:
        match self.type_file:
            case 'c':
                compile_code(self.file, self.sentence, self.type_file)
            case 'cpp':
                compile_code(self.file, self.sentence, self.type_file)
            case _:
                msg_error('File not supported')
                sys.exit(1)
