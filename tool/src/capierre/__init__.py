from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error, msg_info
import subprocess
import os
import tempfile
import platform
import struct
from capierreMagic import CapierreMagic

class Capierre:
    """
    This class is responsible for hiding information in files
    @param file: str - The path of the file to hide the information
    @param type_file: str - The type of file to hide the information
    @param sentence: str - The sentence to hide
    """
    def __init__(self: object, file: str, type_file: str, sentence: str, binary_file = 'capierre_binary') -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence
        self.binary_file = binary_file

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
            self.compile_code(self.file, self.sentence, extension_files[self.type_file])
        else:
            msg_error('File not supported')
            sys.exit(1)

    """
    This function creates a malicious file with the sentence to hide
    @param sentence_to_hide: str | bytes - The sentence to hide
    @return Tuple[str, str] - The path of the malicious file and the path of the sentence to hide
    """
    def create_malicious_file(self: object, sentence_to_hide: str | bytes) -> tuple[str, str]:
        capierre_magic: object = CapierreMagic()
        data: bytes = sentence_to_hide
        section: str = ''
        length: str = ''
        os_type: str = platform.system()

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_fd = tempfile.NamedTemporaryFile(delete=False)
        if type(sentence_to_hide) == str:
            data = data.encode()

        length = struct.pack('<i', len(capierre_magic.CIE_INFORMATION + capierre_magic.MAGIC_NUMBER_START + data + capierre_magic.MAGIC_NUMBER_END))
        sentence_to_hide_fd.write(length + capierre_magic.CIE_INFORMATION + capierre_magic.MAGIC_NUMBER_START + data + capierre_magic.MAGIC_NUMBER_END)
        if (os_type == 'Windows'):
            sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace('\\', '/')
            section = '.eh_fram'
        elif (os_type == 'Linux'):
            section = '.eh_frame'
        elif (os_type == 'Darwin'):
            section = '__TEXT,__eh_frame'
        else:
            msg_error('OS not supported')
            sys.exit(1)

        malicious_code = f"""
        #include <stdio.h>
        #include <stdint.h>

        __asm (
        ".section {section}\\n"
        ".incbin \\"{sentence_to_hide_fd.name}\\"\\n"
        );
        """

        # https://stackoverflow.com/a/65156317/23570806
        malicious_code_fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
        malicious_code_fd.write(malicious_code.encode())
        return (malicious_code_fd.name, sentence_to_hide_fd.name)

    """
    This function compiles the code with the hidden sentence
    @param file_path: str - The path of the file to compile
    @param sentence_to_hide: str - The sentence to hide
    @param type_file: str - The type of file to compile
    @return None
    """
    def compile_code(self: object, file_path: str, sentence_to_hide: str | bytes, compilator_name: str) -> None:
        info_message: str | bytes = sentence_to_hide
        if type(sentence_to_hide) == bytes:
            info_message = info_message.decode()
        msg_info(f'Hidden sentence: {info_message}')
        (malicious_code_file_path, sentece_to_hide_file_path) = self.create_malicious_file(sentence_to_hide)
        compilation_result = subprocess.run(
            [compilator_name, file_path, malicious_code_file_path, '-o', self.binary_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        );
        os.remove(malicious_code_file_path)
        os.remove(sentece_to_hide_file_path)
        if (compilation_result.returncode != 0):
            raise Exception(compilation_result.stderr.strip())
        msg_success('Code compiled successfully')
