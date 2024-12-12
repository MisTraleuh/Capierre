from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error, msg_info
import subprocess
import os
import tempfile
import platform
import struct
import random
import angr
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher


class CieStructure:
        def __init__(self: object, length: bytes, ext_length: bytes, cie_id: bytes, version: bytes, aug_string: bytes, eh_data: bytes, 
                    code_align: bytes, data_align: bytes, ret_addr: bytes, aug_data_length: bytes, aug_data: bytes, init_inst: bytes) -> None:
            self.length = length
            self.ext_length = ext_length
            self.ID = cie_id
            self.version = version
            self.aug_string = aug_string
            self.eh_data = eh_data
            self.code_align = code_align
            self.data_align = data_align
            self.ret_addr = ret_addr
            self.aug_data_length = aug_data_length
            self.aug_data = aug_data
            self.init_inst = init_inst

class FdeStructure:
        def __init__(self: object, length: bytes, ext_length: bytes, cie_pointer: bytes, pcbegin: bytes, 
                        pcrange: bytes, aug_data_length: bytes, aug_data: bytes, cie_call: bytes) -> None:
            self.length = length
            self.ext_length = ext_length
            self.cie_pointer = cie_pointer
            self.pcbegin = pcbegin
            self.pcrange = pcrange
            self.aug_data_length = aug_data_length
            self.aug_data = aug_data
            self.cie_call = cie_call


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

    def create_malicious_file(self: Capierre, sentence_to_hide: str) -> tuple[str, str]:
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
                temp_information_to_hide    = (struct.pack('<i', len(information_to_hide) + 4 - len_new_cie) +
                                                b"\x11\x11\x11\x11" + struct.pack('bb', 4 - (rand_step & 0b11), random.randint(0, 127)) + b"\x00\x00\x00"
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

    def complete_eh_frame_section(self: object) -> None:

        capierre_magic: object = CapierreMagic()
        eh_frame_section: object = {}
        project: object = angr.Project(self.binary_file, load_options={'auto_load_libs': False})
        symbols = project.loader.main_object.symbols

        for section in project.loader.main_object.sections:
            if section.name == ".eh_frame":
                eh_frame_section = section
                break

        with open(self.binary_file, 'r+b') as binary:
            read_bin = binary.read()
            binary.seek(0)
            eh_frame_block: bytearray = read_bin[eh_frame_section.offset:eh_frame_section.offset + eh_frame_section.memsize]

            index = eh_frame_block.find(capierre_magic.CIE_INFORMATION + capierre_magic.MAGIC_NUMBER_START)
            if (index == -1):
                msg_warning("Failure to locate compiled block")

            length: int = 1
            i: int = index - 4
            fake_addr: int = 0
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

    def compile_code(self: object, file_path: str, sentence_to_hide: str | bytes, compilator_name: str) -> None:
        """
        This function compiles the code with the hidden sentence.

        @param file_path: `str` - The path of the file to compile.
        @param sentence_to_hide: `str` - The sentence to hide.
        @param type_file: `str` - The type of file to compile.
        @return None
        """
        msg_info(f"Hidden sentence: {sentence_to_hide}")
        (malicious_code_file_path, sentece_to_hide_file_path) = (
            self.create_malicious_file(sentence_to_hide)
        )
        compilation_result = subprocess.run(
            [
                compilator_name,
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
        self.complete_eh_frame_section()
        if (compilation_result.returncode != 0):
            raise Exception(compilation_result.stderr.strip())
        msg_success("Code compiled successfully")
