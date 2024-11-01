import sys
from utils.messages import msg_success, msg_error
from capierre.compiling_code import compile_code

class Capierre:
    """
    This class is responsible for hiding information in files
    @param file: str - The path of the file to hide the information
    @param type_file: str - The type of file to hide the information
    @param sentence: str - The sentence to hide
    """
    def __init__(self: object, file: str, type_file: str, sentence: str) -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence

    """
    This function hides the information in the file
    @return None
    """
    def hide_information(self: object) -> None:
        extension_files = {
            'c': 'gcc',
            'cpp': 'g++',
        }

        if self.type_file in extension_files:
            compile_code(self.file, self.sentence, extension_files[self.type_file])
        else:
            msg_error('File not supported')
            sys.exit(1)
