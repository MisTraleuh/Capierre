# pylint: disable=C0114,C0103

from __future__ import annotations
from multiprocessing.pool import ThreadPool
import sys
import subprocess
import os
import tempfile
import platform
import struct
import itertools
import random
import angr
import cle
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher
from capierreInterface import *
from capierreError import *
from utils.messages import msg_success, msg_error, msg_info, msg_warning


class Capierre:
    """
    This class is responsible for hiding information in files.

    @param file: `str` - The path of the file to hide the information
    @param type_file: `str` - The type of file to hide the information
    @param sentence: `str` - The sentence to hide
    @param password: `str` - The password to encrypt the sentence
    @param binary_file: `str` - The path of the binary file to hide the information
    """
    def __init__(
        self: Capierre,
        file: str,
        type_file: str,
        sentence: str,
        password: str,
        binary_file: str = "capierre_binary",
    ) -> None:
        self.file = file
        self.type_file = type_file
        self.sentence = sentence
        self.password = password
        self.binary_file = binary_file

    def cipher_information(self: Capierre, *, decrypt: bool) -> None:
        """
        This function encrypt/decrypt the information using a password.

        @param decrypt: `bool` - Tells the functions to decrypt instead of
        encrypt.
        """
        if len(self.password) == 0:
            msg_error("You must supply a password.")
            return
        self.sentence = CapierreCipher.cipher(
            self.sentence.encode('ascii'), self.password, decrypt=decrypt
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

        if self.type_file in extension_files:
            self.compile_code(
                self.file,
                self.sentence,
                extension_files[self.type_file]
            )
        else:
            self.hide_in_compiled_binaries(self.file, self.sentence)
#            msg_error("File not supported")
#            sys.exit(1)

    def access_bit(self: Capierre, data: str, num: int):
        """
        Useful function to access a particular bit.

        @param data: `str` - data.
        @param num: `int` - number.
        @return `int`
        """
        base = int(num // 8)
        shift = int(num % 8)

        return (ord(data[base]) >> shift) & 0x1

    def compile_asm(
        self: Capierre,
        bit: int,
        instruction: Instruction
    ) -> None | tuple[int, bytes]:
        """
        This function is used with external programs to convert assembly op
        codes.

        @param bit: `int` - The bit for the conversion.
        @param instruction: `Instruction` - The instruction object.
        """
        capierre_magic = CapierreMagic()

        if (
            bit and instruction.mnemonic == 'add' or
            not bit and instruction.mnemonic == 'sub'
        ):
            return None
        if (
            bit and instruction.mnemonic == 'sub' or
            not bit and instruction.mnemonic == 'add'
        ):
            args = instruction.op_str.split(', ')

            try:
                int(args[1])
            except ValueError:
                return None

            immediate = -int(args[1])

            if instruction.mnemonic == 'sub':
                asm = f".intel_syntax noprefix\nadd {args[0]}, {immediate}\n"
            else:
                asm = f".intel_syntax noprefix\nsub {args[0]}, {immediate}\n"
            with tempfile.NamedTemporaryFile() as tmpfile:
                # TODO: Check the GNU C Compiler to be above 14.
                subprocess.run(
                    capierre_magic.COMPILE_GCC + (tmpfile.name, '-'),
                    input=bytes(asm, "ascii"),
                    check=False
                )

                binary = tmpfile.read()

            return (instruction.address, binary)
        msg_error('[!] Invalid operand.')
        return None

    def read_instructions(self: Capierre, node: Node):
        """
        This is a helper function for reading and filtering helpful
        instructions. 

        @param node: `list[NodeView]` - The list of nodes to filter.
        @return `filter()`
        """
        return filter(
            lambda ins: ins.mnemonic in ('add', 'sub'),
            (ins for ins in node.block.capstone.insns) # type: ignore
        )

    def hide_in_compiled_binaries(
        self: Capierre,
        binary_file: str,
        sentence_to_hide: str
    ):
        """
        Hides the current sentence into the already compiled binary.

        @param binary_file: `str` - The path to the binary file.
        @param sentence_to_hide: `str` - The sentence to hide.
        """
        try:
            capierre_magic = CapierreMagic()
            project = angr.Project(
                binary_file,
                load_options={'auto_load_libs': False}
            )

            # WARN: Pylint doesn't recognise the angr library's definitions.
            cfg = NodeView(project.analyses.CFGFast().graph.nodes()) # type: ignore pylint: disable=E1101
            text_section = None

            for section in project.loader.main_object.sections:
                if section.name == capierre_magic.SECTION_HIDE_TEXT:
                    text_section = section
                    break
            if text_section is None:
                raise NonexistentTextSection()
            with open(binary_file, 'r+b') as binary:
                read_bin = binary.read()
                text_block = bytearray(
                    read_bin[
                        text_section.offset:text_section.offset +
                        text_section.memsize
                    ]
                )
                bitstream: list[int] = [
                    self.access_bit(sentence_to_hide, i) for i in range(
                        len(sentence_to_hide) * 8
                    )
                ]
                threads = ThreadPool(os.cpu_count())
                nodes = filter(lambda node: node.block is not None, cfg)
                instruction_list = tuple(itertools.chain(
                    *map(self.read_instructions, nodes)
                ))
                instructions: tuple[tuple[int, bytes]] = tuple(filter(
                    lambda ins: ins is not None,
                    threads.starmap(
                        self.compile_asm, zip(bitstream, instruction_list)
                    )
                )) # type: ignore
                for instruction in instructions:
                    text_block[
                        instruction[0] - text_section.offset :
                        instruction[0] - text_section.offset + len(instruction[1])
                    ] = instruction[1]

                read_bin = (
                    read_bin[:text_section.offset] +
                    text_block +
                    read_bin[text_section.offset + text_section.memsize:]
                )

                binary.seek(0)
                binary.truncate(0)
                binary.write(read_bin)
                binary.close()

        except cle.errors.CLECompatibilityError:
            msg_error("The chosen file is incompatible")
            sys.exit(1)
        except cle.errors.CLEUnknownFormatError:
            msg_error("The file format is incompatible")
            sys.exit(1)
        except cle.errors.CLEInvalidBinaryError:
            msg_error("The chosen binary file is incompatible")
            sys.exit(1)
        except Exception as e:
            raise e

    def create_malicious_file(
        self: Capierre,
        sentence_to_hide: str
    ) -> tuple[str, str, bytes]:
        """
        This function creates a malicious file with the sentence to hide.

        @param sentence_to_hide: `str | bytes` - The sentence to hide.
        @return `Tuple[str, str]` - The path of the malicious file and the path
        of the sentence to hide.
        """
        capierre_magic = CapierreMagic()
        data = sentence_to_hide
        section = capierre_magic.SECTION_HIDE

        information_to_hide = b""
        len_new_cie = 0
        new_size = 0
        temp_information_to_hide = b""
        rand_entry = random.randint(4, 10)
        entry_number = rand_entry
        i = 0

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_fd = tempfile.NamedTemporaryFile(delete=False)
        data = bytearray(data.encode())
        rand_step: int = random.randint(1, 16)
        i: int = 0

        # This loop will create chunks out of AES encrypted content and will
        # add them at the end of fake CIE and FDE structure sprinkled with
        # some random data.
        while i < len(data):
            if i == 0:
                temp_information_to_hide = (
                    capierre_magic.MAGIC_NUMBER_START + data[i: i + rand_step]
                )
            else:
                if len(data) < i + rand_step:
                    rand_step = len(data) - i
                temp_information_to_hide = data[i: i + rand_step]

            # This section creates fake CIEs.
            if entry_number == rand_entry:
                len_new_cie = len(information_to_hide)
                temp_information_to_hide = (
                    capierre_magic.CIE_INFORMATION +
                    ((4 - (rand_step & 0b11)) & 0b11).to_bytes(1, 'little') +
                    temp_information_to_hide +
                    struct.pack(
                        'bb',
                        random.randint(0, 127),
                        random.randint(0, 127)
                    )
                )
                entry_number = 0
                rand_entry = random.randint(4, 10)
            # This section creates fake FDEs with a placeholder address.
            else:
                temp_information_to_hide = (
                    struct.pack(
                        '<i',
                        len(information_to_hide) + 4 - len_new_cie
                    ) +
                    b"\x11\x11\x11\x11" +
                    struct.pack(
                        'bb',
                        (
                            4 - (rand_step & 0b11)) & 0b11,
                            random.randint(0, 127)
                        ) +
                    b"\x00\x00\x00" +
                    temp_information_to_hide +
                    struct.pack(
                        'bbb',
                        random.randint(0, 127),
                        random.randint(0, 127),
                        random.randint(0, 127)
                    )
                )

            # This part was added to provided alignment to 4 bytes as the
            # eh_frame format requires.
            new_size = len(temp_information_to_hide)
            if new_size & 0b11:
                new_size = ((new_size | 0b11) ^ 0b11) + 4
                temp_information_to_hide = temp_information_to_hide.ljust(
                    new_size, b'\x00'
                )

            temp_information_to_hide = (
                struct.pack('<i', new_size) +
                temp_information_to_hide
            )
            information_to_hide += temp_information_to_hide
            entry_number += 1
            i += rand_step
            rand_step = random.randint(1, 16)

        # As MacOSX's linker will throw exceptions on invalid eh_frame FDE
        # addresses, the processed data can't be inserted into the binary
        # directly.
        #
        # Since one can't add more data to the eh_frame section after the
        # compilation ends, forcibly adding space to the end of the eh_frame
        # section to store the processed data was the approach chosen.
        #
        # Prior tests showed that the linker will ignore any data that is added
        # to this section passed the terminator and will throw exceptions on
        # CFI sections that are too long.
        #
        # We chose to add the space needed to hold the data as several fake
        # CIEs.
        if platform.system() == 'Darwin':
            final_prep: bytes = (
                b'\x18\x00\x00\x00' +
                capierre_magic.CIE_INFORMATION +
                capierre_magic.MAGIC_NUMBER_START +
                b'\x00\x00\x00'
            )
            final_size = (
                len(information_to_hide) -
                capierre_magic.MAGIC_NUMBER_START_LEN -
                20
            )
            final_count = final_size // 20
            final_remain = final_size % 20
            i = 0
            while i < (final_count - 1):
                final_prep += (
                    b'\x10\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00'
                )
                i += 1

            if final_remain != 0:
                final_prep += (
                    struct.pack('b', 16 + final_remain) +
                    b'\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00' +
                    (b'\x00' * final_remain)
                )
            else:
                final_prep += (
                    b'\x10\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00'
                )

            sentence_to_hide = information_to_hide
            information_to_hide = final_prep

        # Otherwise, the regular Linux linker will not check anything.
        #
        # Because Linux's linker doesn't care about the size of the eh_frame
        # section, the processed data can be inserted directly into the binary.
        sentence_to_hide_fd.write(information_to_hide)

        sentence_to_hide_fd.close()

        if platform.system() == 'Windows':
            sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace('\\', '/')
        if (platform.system() == 'Darwin'):
            information_to_hide = sentence_to_hide

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

        return (
            malicious_code_fd.name,
            sentence_to_hide_fd.name,
            information_to_hide
        )

    def complete_eh_frame_section( # pylint: disable=C0116
        self: Capierre,
        encoded_message: bytes
    ) -> None:
        capierre_magic = CapierreMagic()
        eh_frame_section = {}
        project = angr.Project(
            self.binary_file,
            load_options={'auto_load_libs': False}
        )
        symbols = project.loader.main_object.symbols
        eh_frame_section = None

        for section in project.loader.main_object.sections:
            if section.name == capierre_magic.SECTION_RETRIEVE:
                eh_frame_section = section
                break
        if eh_frame_section is None:
            raise NonexistentEhFrameSection()
        # To make the fake eh_frame entries more believable, the binary is
        # opened again and its compiled symbols' addresses are added to the
        # FDEs by removing their placeholder values.
        with open(self.binary_file, 'r+b') as binary:
            read_bin = binary.read()
            binary.seek(0)
            eh_frame_block = read_bin[
                eh_frame_section.offset:eh_frame_section.offset +
                eh_frame_section.memsize
            ]

            i = eh_frame_block.find(capierre_magic.MAGIC_NUMBER_START)
            length = 0
            fake_addr = 0

            if i == -1:
                msg_warning("Failure to locate compiled block")
            if platform.system() == 'Darwin':
                eh_frame_block = (
                    eh_frame_block[:i - len(capierre_magic.CIE_INFORMATION) - 4] +
                    encoded_message
                )
            i -= 4 + len(capierre_magic.CIE_INFORMATION)
            while i < len(eh_frame_block):
                length = int.from_bytes(eh_frame_block[i: i + 4], "little")

                if length == 0:
                    break
                if int.from_bytes(eh_frame_block[i + 4: i + 8], "little") != 0:
                    fake_addr = (
                        project.loader.main_object.min_addr +
                        symbols[random.randint(0, len(symbols) - 1)].relative_addr
                    ) - (
                        eh_frame_section.vaddr + i + 8
                    )
                    eh_frame_block = (
                        eh_frame_block[:i + 8] +
                        fake_addr.to_bytes(4, byteorder="little", signed=True) +
                        eh_frame_block[i + 12:]
                    )
                i += length + 4
            read_bin = (
                read_bin[:eh_frame_section.offset] +
                eh_frame_block +
                read_bin[eh_frame_section.offset + eh_frame_section.memsize:]
            )
            binary.truncate(0)
            binary.write(read_bin)
            binary.close()

    def compile_code(
        self: Capierre,
        file_path: str,
        sentence_to_hide: str,
        compilator_name: str
    ) -> None:
        """
        This function compiles the code with the hidden sentence.

        @param file_path: `str` - The path of the file to compile.
        @param sentence_to_hide: `str` - The sentence to hide.
        @param type_file: `str` - The type of file to compile.
        @return None
        """
        msg_info(f"Hidden sentence: {sentence_to_hide}")
        self.cipher_information(decrypt=False)
        (malicious_code_file_path, sentece_to_hide_file_path, encoded_message) = (
            self.create_malicious_file(self.sentence)
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
            check=True
        )
        os.remove(malicious_code_file_path)
        os.remove(sentece_to_hide_file_path)
        if compilation_result.returncode != 0:
            raise CompilationError(compilation_result.stderr.strip())
        self.complete_eh_frame_section(encoded_message)
        msg_success("Code compiled successfully")
