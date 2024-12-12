from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error, msg_info
import subprocess
import os
import tempfile
import platform
import struct
import random
from capierreMagic import CapierreMagic

class Capierre:
    """
    This class is responsible for hiding information in files.

    @param file: `str` - The path of the file to hide the information
    @param type_file: `str` - The type of file to hide the information
    @param sentence: `str` - The sentence to hide
    """

    def __init__(self: object, file: str, type_file: str, sentence: str, binary_file = 'capierre_binary') -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence
        self.binary_file = binary_file

    def hide_information(self: object) -> None:
        """
        This function hides the information in the file
        @return None
        """
        extension_files = {
            'c': 'gcc',
            'cpp': 'g++',
        }

        if self.type_file in extension_files:
            self.compile_code(self.file, self.sentence, extension_files[self.type_file])
        else:
            msg_error('File not supported')
            sys.exit(1)

    def create_malicious_file(self: object, sentence_to_hide: str | bytes) -> tuple[str, str]:
        """
        This function creates a malicious file with the sentence to hide.

        @param sentence_to_hide: `str | bytes` - The sentence to hide
        @return `Tuple[str, str]` - The path of the malicious file and the path of the sentence to hide
        """
        capierre_magic: object = CapierreMagic()
        data: bytes = sentence_to_hide
        section: str = capierre_magic.SECTION_HIDE

        information_to_hide: bytes = b""
        len_new_cie: int = 0
        rand_step: int = 0
        new_size: int = 0
        temp_information_to_hide: bytes = b""
        rand_entry: int = random.randint(4, 10)
        entry_number: int = rand_entry

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_fd: list[bytes] = tempfile.NamedTemporaryFile(delete=False)
        if (type(sentence_to_hide) == str):
            data = bytearray(data.encode())

        rand_step = random.randint(1, 16)
        for i in range(0, len(data), rand_step):

            if (i == 0):
                temp_information_to_hide = capierre_magic.MAGIC_NUMBER_START + data[i: i + rand_step]
            else:
                temp_information_to_hide = data[i: i + rand_step]

            if entry_number == rand_entry: 
                len_new_cie = len(information_to_hide)
                temp_information_to_hide    = (capierre_magic.CIE_INFORMATION + temp_information_to_hide)
                entry_number = 0
                rand_entry = random.randint(4, 10)
            else:
                temp_information_to_hide    = (struct.pack('<i', len(information_to_hide) - len_new_cie) +
                                                b"\x11\x11\x11\x11\x22\x22\x22\x22" + struct.pack('bb', 4 - (rand_step & 0b11), random.randint(0, 127)) + b"\x00\x00"
                                                + temp_information_to_hide)

            if (len(data) <= i + rand_step):
                temp_information_to_hide += capierre_magic.MAGIC_NUMBER_END
            new_size = ((len(temp_information_to_hide) | 0b11) ^ 0b11) + 4
            temp_information_to_hide = temp_information_to_hide.ljust(new_size, b'\x00')
            temp_information_to_hide = struct.pack('<i', new_size) + temp_information_to_hide
            information_to_hide += temp_information_to_hide
            entry_number += 1
            rand_step = random.randint(1, 16)

        sentence_to_hide_fd.write(information_to_hide)
        sentence_to_hide_fd.close()

        if (platform.system() == 'Windows'):
            sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace('\\', '/')



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
        malicious_code_fd.close()

        return (malicious_code_fd.name, sentence_to_hide_fd.name)

    def compile_code(self: object, file_path: str, sentence_to_hide: str | bytes, compilator_name: str) -> None:
        """
        This function compiles the code with the hidden sentence.

        @param file_path: `str` - The path of the file to compile.
        @param sentence_to_hide: `str` - The sentence to hide.
        @param type_file: `str` - The type of file to compile.
        @return None
        """
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
        )
        os.remove(malicious_code_file_path)
        os.remove(sentece_to_hide_file_path)
        if (compilation_result.returncode != 0):
            raise Exception(compilation_result.stderr.strip())
        msg_success('Code compiled successfully')
