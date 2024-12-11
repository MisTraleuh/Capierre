from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error, msg_info
import subprocess
import os
import tempfile
import platform
import struct
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

    def create_malicious_file(self: Capierre, sentence_to_hide: str) -> tuple[str, str]:
        """
        This function creates a malicious file with the sentence to hide.

        @param sentence_to_hide: `str | bytes` - The sentence to hide
        @return `Tuple[str, str]` - The path of the malicious file and the path of the sentence to hide
        """
        capierre_magic: CapierreMagic = CapierreMagic()
        data = bytes(sentence_to_hide, "utf-8")
        section = capierre_magic.SECTION_HIDE

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_tmpfile = tempfile.NamedTemporaryFile(delete=False)
        information_to_hide = (
            capierre_magic.CIE_INFORMATION
            + capierre_magic.MAGIC_NUMBER_START
            + data
            + capierre_magic.MAGIC_NUMBER_END
        )

        sentence_to_hide_length_sereal = struct.pack("<i", len(information_to_hide))
        sentence_to_hide_tmpfile.write(
            sentence_to_hide_length_sereal + information_to_hide
        )
        sentence_to_hide_tmpfile.close()

        if platform.system() == "Windows":
            sentence_to_hide_tmpfile.name = sentence_to_hide_tmpfile.name.replace(
                "\\", "/"
            )

        malicious_code = f"""
        #include <stdio.h>
        #include <stdint.h>

        __asm (
        ".section {section}\\n"
        ".incbin \\"{sentence_to_hide_tmpfile.name}\\"\\n"
        );
        """

        # https://stackoverflow.com/a/65156317/23570806
        malicious_code_fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
        malicious_code_fd.write(malicious_code.encode())
        malicious_code_fd.close()

        return (malicious_code_fd.name, sentence_to_hide_tmpfile.name)

    def compile_code(
        self: Capierre, file_path: str, sentence_to_hide: str, compilator_name: str
    ) -> None:
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
        if compilation_result.returncode != 0:
            raise Exception(compilation_result.stderr.strip())
        msg_success("Code compiled successfully")
