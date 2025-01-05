from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error, msg_info, msg_warning
import subprocess
import os
import tempfile
import platform
import struct
import random
import angr
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher

class Capierre:
    """
    This class is responsible for hiding information in files.

    @param file: `str` - The path of the file to hide the information
    @param type_file: `str` - The type of file to hide the information
    @param sentence: `str` - The sentence to hide
    """

    def __init__(
        self: Capierre,
        file: str,
        type_file: str,
        sentence: str,
        password: str,
        binary_file="capierre_binary",
    ) -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence
        self.password = password
        self.binary_file = binary_file

    def cipher_information(self: Capierre, *, decrypt: bool) -> None:
        if len(self.password) == 0:
            msg_error("You must supply a password.")
            return
        self.sentence = CapierreCipher.cipher(
            self.sentence, self.password, decrypt=decrypt
        )

    def hide_information(self: Capierre) -> None:
        """
        This function hides the information in the file
        @return None
        """
        extension_files = {
            "c": "gcc",
            "cpp": "g++",
        }

        self.cipher_information(decrypt=False)
        if self.type_file in extension_files:
            self.compile_code(self.file, self.sentence, extension_files[self.type_file])
        else:
            msg_error("File not supported")
            sys.exit(1)

    def create_malicious_file(self: Capierre, sentence_to_hide: str) -> tuple[str, str, bytes]:
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
        new_size: int = 0
        temp_information_to_hide: bytes = b""
        rand_entry: int = random.randint(4, 10)
        entry_number: int = rand_entry
        i: int = 0

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_fd: list[bytes] = tempfile.NamedTemporaryFile(delete=False)
        if (type(sentence_to_hide) == str):
            data = bytearray(data.encode())

        rand_step: int = random.randint(1, 16)
        i: int = 0
        while i < len(data):

            if (i == 0):
                temp_information_to_hide = capierre_magic.MAGIC_NUMBER_START + data[i: i + rand_step]
            else:
                if (len(data) < i + rand_step):
                    rand_step = len(data) - i
                temp_information_to_hide = data[i: i + rand_step]

            if entry_number == rand_entry: 
                len_new_cie = len(information_to_hide)
                temp_information_to_hide    = capierre_magic.CIE_INFORMATION + ((4 - (rand_step & 0b11)) & 0b11).to_bytes(1, 'little') + temp_information_to_hide + struct.pack('bb', random.randint(0, 127), random.randint(0, 127))
                entry_number = 0
                rand_entry = random.randint(4, 10)
            else:
                temp_information_to_hide    = (struct.pack('<i', len(information_to_hide) + 4 - len_new_cie) +
                                                b"\x11\x11\x11\x11" + struct.pack('bb', (4 - (rand_step & 0b11)) & 0b11, random.randint(0, 127)) + b"\x00\x00\x00"
                                                + temp_information_to_hide + struct.pack('bbb', random.randint(0, 127), random.randint(0, 127), random.randint(0, 127)))

            new_size = len(temp_information_to_hide)
            if new_size & 0b11:
                new_size = ((new_size | 0b11) ^ 0b11) + 4
                temp_information_to_hide = temp_information_to_hide.ljust(new_size, b'\x00')

            temp_information_to_hide = struct.pack('<i', new_size) + temp_information_to_hide
            information_to_hide += temp_information_to_hide
            entry_number += 1
            i += rand_step
            rand_step = random.randint(1, 16)

        final_prep: bytes = b'\x18\x00\x00\x00' + capierre_magic.CIE_INFORMATION + capierre_magic.MAGIC_NUMBER_START + b'\x00\x00\x00'
        final_size = len(information_to_hide) - capierre_magic.MAGIC_NUMBER_START_LEN - 20
        final_count = final_size // 20
        final_remain = final_size % 20
        i = 0
        while (i < (final_count - 1)):
            final_prep += b'\x10\x00\x00\x00' + capierre_magic.CIE_INFORMATION + b'\x00\x00\x00'
            i += 1

        if (final_remain != 0):
            final_prep += struct.pack('b', 16 + final_remain) + b'\x00\x00\x00' + capierre_magic.CIE_INFORMATION + b'\x00\x00\x00' + (b'\x00' * final_remain)
        else:
            final_prep += b'\x10\x00\x00\x00' + capierre_magic.CIE_INFORMATION + b'\x00\x00\x00'

        sentence_to_hide_fd.write(final_prep + b'\x00\x00\x00\x00')
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

        return (malicious_code_fd.name, sentence_to_hide_fd.name, information_to_hide)

    def complete_eh_frame_section(self: object, encoded_message: bytes) -> None:

        capierre_magic: object = CapierreMagic()
        eh_frame_section: object = {}
        project: object = angr.Project(self.binary_file, load_options={'auto_load_libs': False})
        symbols = project.loader.main_object.symbols

        for section in project.loader.main_object.sections:
            if section.name == capierre_magic.SECTION_RETRIEVE:
                eh_frame_section = section
                break

        with open(self.binary_file, 'r+b') as binary:
            read_bin = binary.read()
            binary.seek(0)
            eh_frame_block: bytearray = read_bin[eh_frame_section.offset:eh_frame_section.offset + eh_frame_section.memsize]

            i: int = eh_frame_block.find(capierre_magic.MAGIC_NUMBER_START)
            length: int = 1
            fake_addr: int = 0

            if (i == -1):
                msg_warning("Failure to locate compiled block")

            eh_frame_block = eh_frame_block[:i - len(capierre_magic.CIE_INFORMATION) - 4] + encoded_message + b'\x00\x00\x00\x00'
            i -= 4 + len(capierre_magic.CIE_INFORMATION)
            while (i < len(eh_frame_block)):

                length = int.from_bytes(eh_frame_block[i: i + 4], "little")
                if (length == 0):
                    break
                if int.from_bytes(eh_frame_block[i + 4: i + 8], "little") != 0:
                    fake_addr = (project.loader.main_object.min_addr + symbols[random.randint(0, len(symbols) - 1)].relative_addr) - (eh_frame_section.vaddr + i + 8)
                    eh_frame_block = eh_frame_block[:i + 8] + fake_addr.to_bytes(4, byteorder="little", signed=True) + eh_frame_block[i + 12:]
                i += length + 4

            read_bin = read_bin[:eh_frame_section.offset] + eh_frame_block + read_bin[eh_frame_section.offset + eh_frame_section.memsize:]
            binary.truncate(0)
            binary.write(read_bin)
            binary.close()

    def compile_code(self: object, file_path: str, sentence_to_hide: str, compilator_name: str) -> None:
        """
        This function compiles the code with the hidden sentence.

        @param file_path: `str` - The path of the file to compile.
        @param sentence_to_hide: `str` - The sentence to hide.
        @param type_file: `str` - The type of file to compile.
        @return None
        """
        msg_info(f"Hidden sentence: {sentence_to_hide}")
        (malicious_code_file_path, sentece_to_hide_file_path, encoded_message) = (
            self.create_malicious_file(sentence_to_hide)
        )
        compilation_result = subprocess.run(
            [
                compilator_name,
                '-fno-dwarf2-cfi-asm',
                file_path,
                malicious_code_file_path,
                "-o",
                self.binary_file,
            ],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        os.remove(malicious_code_file_path)
        os.remove(sentece_to_hide_file_path)
        if (compilation_result.returncode != 0):
            raise Exception(compilation_result.stderr.strip())
        self.complete_eh_frame_section(encoded_message)
        msg_success("Code compiled successfully")
