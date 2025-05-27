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
import functools
import random
import angr
import capstone
import cle
import lief
from PIL import Image
from collections import deque
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher
from capierreImage import CapierreImage
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
        sentence: bytes,
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
            return
        self.sentence = CapierreCipher.cipher(
            self.sentence, self.password, decrypt=decrypt
        )

    def hide_information(self: Capierre) -> None:
        """
        This function hides the information in the file
        @return None
        """
        extension_files_compile = {
            "c": "gcc",
            "cpp": "g++",
        }

        extension_files_image = [
            "png",
        ]

        self.cipher_information(decrypt=False)
        if self.type_file in extension_files_compile:
            self.compile_code(self.file, self.sentence, extension_files_compile[self.type_file])
        elif self.type_file in extension_files_image:
            msg_error("FATAL: To conceal within a picture, add the '-i' flag.")
        else:
            self.hide_in_compiled_binaries(self.file, self.sentence)

    def retrieve_int_byte(self: Capierre, data: int, shift: int, size: int):
        """
        Useful function to access a particular bit.

        @param data: `str` - data.
        @param num: `int` - number.
        @return `int`
        """
        return (data >> (size - shift - 1)) & 0x1


    def access_bit(self: Capierre, data: bytes, num: int):
        """
        Useful function to access a particular bit.

        @param data: `bytes` - data.
        @param num: `int` - number.
        @return `int`
        """
        base = int(num // 8)
        shift = 7 - int(num % 8)

        return (data[base] >> shift) & 0x1

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
            (bit and instruction.mnemonic == 'add') or
            (not bit and instruction.mnemonic == 'sub')
        ):
            return None
        if (
            (bit and instruction.mnemonic == 'sub') or
            (not bit and instruction.mnemonic == 'add')
        ):
            args = instruction.op_str.split(', ')
            immediate = -int(args[1], 16)

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
                # Filter out the .note.gnu.property section that is forcibly added by ld in gcc versions > 11.
                if len(binary) > 4096:
                    binary = binary[4096:]

            return (instruction.address, list(binary))
        msg_error('[!] Invalid operand.')
        return None


    def get_correct_architecture(self, file_path: str):
        binary = lief.parse(file_path)
        cs_arch = None
        cs_mode = None
        supported = True

        if isinstance(binary, lief.MachO.Binary):
            cpu_type = binary.header.cpu_type
            if cpu_type == lief.MachO.Header.CPU_TYPE.X86:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
            elif cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
            else:
                raise ValueError(f"Unsupported Mach-O CPU type: {cpu_type}")
            supported = False

        elif isinstance(binary, lief.ELF.Binary):
            machine = binary.header.machine_type
            if machine == lief.ELF.ARCH.I386:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
            elif machine == lief.ELF.ARCH.X86_64:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
            else:
                raise ValueError(f"Unsupported ELF machine type: {machine}")

        elif isinstance(binary, lief.PE.Binary):
            machine = binary.header.machine
            if machine == lief.PE.Header.MACHINE_TYPES.I386:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
            elif machine == lief.PE.Header.MACHINE_TYPES.AMD64:
                cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
            else:
                raise ValueError(f"Unsupported PE machine type: {machine}")

        else:
            raise TypeError("Unsupported binary format")

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True

        return md, binary, supported

    def load_angr_project(self: Capierre, filepath: str):
        try:
            capierre_magic = CapierreMagic()
            capstoneProjModule, project, supported = self.get_correct_architecture(filepath)

            # WARN: Pylint doesn't recognise the angr library's definitions.
            # pylint: disable=E1101

            #if supported == False:
            #    return self.load_mac_binaries(filepath)

            text_section = None
            # This is done instead of calling get_section() because some binaries we tested had improperly named sections.
            for section in project.sections:
                if section.name.startswith(capierre_magic.SECTION_HIDE_TEXT):
                    text_section = section
                    break
                elif section.name.startswith('__text'):
                    text_section = section
                    break

            if text_section is None:
                raise NonexistentTextSection()

            end_text_section: int = text_section.virtual_address + text_section.size
            instruction_list: list = []
            tmp_unduplicated: list = []
            instruction_list_unique: list = []
            len_sentence: int = len(self.sentence) * 8 + 32
            valid_func_list: deque = deque()

            if supported == True:
                valid_func_list = deque(filter(lambda sym: text_section.virtual_address <= sym.value < end_text_section and 0 < sym.size, project.functions))

                while 0 < len(valid_func_list) and len(instruction_list) < len_sentence:
                    for func in list(valid_func_list):
                        if len_sentence <= len(instruction_list):
                            break
                        code = project.get_content_from_virtual_address(func.value, func.size)
                        instruction_list += list(map(InstructionSetWrapper, filter(lambda ins: ins.mnemonic in ("add", "sub") and len(ins.operands) == 2 and ins.operands[1].type == capstone.CS_OP_IMM, capstoneProjModule.disasm(code, func.value))))
                        valid_func_list.popleft()

                    instruction_list = list(dict.fromkeys(instruction_list))

            else:
                # Mach-O binaries are strange in that, while they will provide symbols... somewhat, non of them have an explicit size.
                # The obvious logical thing to do is reorder the symbols by value and calculate the difference between their respective addresses.
                # Due to alignment however, the next address might begin after padding data which might be 0s or NOP instructions.
                # In very rare cases, there is a non zero chance that padding data might be garbage.
                # We'll assume for this release that it might be negligible enough.
                valid_func_list = deque(sorted(filter(lambda sym: sym.type == lief.MachO.Symbol.TYPE.SECTION and text_section.virtual_address <= sym.value < end_text_section, project.symbols), key=lambda sym: sym.value))
                print(len(valid_func_list))
                while 1 < len(valid_func_list) and len(instruction_list) < len_sentence:
                    #The final value will be ignored, that's okay for now.
                    for sym1, sym2 in zip(list(valid_func_list), list(valid_func_list)[1:]):
                        if len_sentence <= len(instruction_list):
                            break
                        code = project.get_content_from_virtual_address(sym1.value, sym2.value - sym1.value)
                        instruction_list += list(map(InstructionSetWrapper, filter(lambda ins: ins.mnemonic in ("add", "sub") and len(ins.operands) == 2 and ins.operands[1].type == capstone.CS_OP_IMM, capstoneProjModule.disasm(code, sym1.value))))
                        valid_func_list.popleft()

                    instruction_list = list(dict.fromkeys(instruction_list))

            instruction_list_unique = [wrapped.ins for wrapped in instruction_list[0:len_sentence]]
            return instruction_list_unique, text_section.offset, text_section.size, text_section.virtual_address

        except cle.errors.CLECompatibilityError:
            msg_error("The chosen file is incompatible")
            return [], 0, 0, 0
        except cle.errors.CLEUnknownFormatError:
            msg_error("The file format is incompatible")
            return [], 0, 0, 0
        except cle.errors.CLEInvalidBinaryError:
            msg_error("The chosen binary file is incompatible")
            return [], 0, 0, 0
        except NonexistentTextSection:
            msg_error("The chosen binary file doesn't have a properly named text section.")
            return [], 0, 0, 0
        except Exception as e:
            raise e
            msg_error("An uncatalogued exception occured.")
            return [], 0, 0, 0

    def hide_in_compiled_binaries(
        self: Capierre,
        filepath: str,
        sentence_to_hide: bytes
    ):
        """
        Hides the current sentence into the already compiled binary.

        @param filepath: `str` - The path to the binary file.
        @param sentence_to_hide: `bytes` - The sentence to hide.
        """
        instruction_list, text_section_offset, text_section_size, text_section_addr = self.load_angr_project(filepath)

        if instruction_list == []:
            msg_error("FATAL: Instruction list is empty.")
            return

        with open(filepath, 'r+b') as file:
            read_bin = file.read()
            text_block = bytearray(
                read_bin[
                    text_section_offset:text_section_offset +
                    text_section_size
                ]
            )

            bitstream: list[int] = [
                self.access_bit(sentence_to_hide, i) for i in range(
                    len(sentence_to_hide) * 8
                )
            ]
            bitstream = [self.retrieve_int_byte(len(sentence_to_hide), i, 32) for i in range(0, 32)] + bitstream

            if (len(instruction_list) < len(bitstream)):
                msg_error(f"FATAL: Binary has {len(instruction_list)} bits available but at least {len(bitstream)} are required.")
                return

            threads = ThreadPool(os.cpu_count())
            instructions: tuple[tuple[int, bytes]] = tuple(filter(
                lambda ins: ins is not None,
                threads.starmap(
                    self.compile_asm, zip(bitstream, instruction_list)
                )
            ))  # type: ignore

            for instruction in instructions:
                text_block[
                    instruction[0] - text_section_addr:
                    instruction[0] - text_section_addr +
                        len(instruction[1])
                ] = instruction[1]
            read_bin = (
                read_bin[:text_section_offset] +
               text_block +
                read_bin[text_section_offset + text_section_size:]
            )

            file.seek(0)
            file.truncate(0)
            file.write(read_bin)
            file.close()

    def create_malicious_file(
        self: Capierre,
        sentence_to_hide: bytes
    ) -> tuple[str, str, bytes]:
        """
        This function creates a malicious file with the sentence to hide.

        @param sentence_to_hide: `bytes` - The sentence to hide.
        @return `Tuple[str, str]` - The path of the malicious file and the path
        of the sentence to hide.
        """
        capierre_magic = CapierreMagic()
        data = bytearray(sentence_to_hide)
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
            sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace(
                '\\', '/')
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
        malicious_code_fd = tempfile.NamedTemporaryFile(
            delete=False, suffix=".c")
        malicious_code_fd.write(malicious_code.encode())
        malicious_code_fd.close()

        return (
            malicious_code_fd.name,
            sentence_to_hide_fd.name,
            information_to_hide
        )

    def complete_eh_frame_section(  # pylint: disable=C0116
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
                        symbols[random.randint(
                            0, len(symbols) - 1)].relative_addr
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
        sentence_to_hide: bytes,
        compilator_name: str
    ) -> None:
        """
        This function compiles the code with the hidden sentence.

        @param file_path: `str` - The path of the file to compile.
        @param sentence_to_hide: `str` - The sentence to hide.
        @param type_file: `str` - The type of file to compile.
        @return None
        """
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
            check=True
        )
        os.remove(malicious_code_file_path)
        os.remove(sentece_to_hide_file_path)
        if compilation_result.returncode != 0:
            raise CompilationError(compilation_result.stderr.strip())
        self.complete_eh_frame_section(encoded_message)
        msg_success("Code compiled successfully")
