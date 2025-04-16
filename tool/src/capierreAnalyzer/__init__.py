from __future__ import annotations
import sys
import angr
import cle
import itertools
import functools
from utils.messages import msg_success, msg_error, msg_warning
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher
from capierreInterface import *


class CapierreAnalyzer:
    """
    This class is responsible for analyzing the file.
    """

    def __init__(
        self: CapierreAnalyzer, filepath: str, output_file_retreive: str, password: str
    ) -> None:
        self.filepath = filepath
        self.output_file_retreive = output_file_retreive
        self.password = password

    def cipher_information(self: CapierreAnalyzer, *, retrieved_content: bytes, decrypt: bool) -> str:
        if len(self.password) == 0:
            msg_error("You must supply a password.")
            return
        return CapierreCipher.cipher(
            retrieved_content, self.password, decrypt=decrypt
        )

    def load_angr_project(self: Capierre, filepath: str):
        try:
            capierre_magic = CapierreMagic()
            project = angr.Project(
                filepath,
                load_options={'auto_load_libs': False}
            )

            # WARN: Pylint doesn't recognise the angr library's definitions.
            # pylint: disable=E1101
            cfg = NodeView(project.analyses.CFGFast().graph.nodes()) # type: ignore
            text_section = None

            for section in project.loader.main_object.sections:
                if section.name == capierre_magic.SECTION_HIDE_TEXT:
                    text_section = section
                    break
            if text_section is None:
                raise NonexistentTextSection()
            return cfg, text_section
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

    def access_bit(self: Capierre, data: str, num: int):
        """
        Useful function to access a particular bit.

        @param data: `str` - data.
        @param num: `int` - number.
        @return `int`
        """
        base = int(num // 8)
        shift = 7 - int(num % 8)

        return (ord(data[base]) >> shift) & 0x1

    def read_instructions(self: CapierreAnalyzer, node: Node):
        """
        This is a helper function for reading and filtering helpful
        instructions. 

        @param node: `list[NodeView]` - The list of nodes to filter.
        @return `filter()`
        """
        return filter(
            lambda ins: ins.mnemonic in ('add', 'sub'),
            (ins for ins in node.block.capstone.insns)  # type: ignore
        )

    def remove_incorrect_instructions(self: CapierreAnalyzer, instruction: Instruction):
        args = instruction.op_str.split(', ')
        try:
            int(args[1])
        except ValueError:
            return None
        return instruction

    def read_in_compiled_binaries(self: CapierreAnalyzer) -> str:
        """
        Reads the sentence into the already compiled binary.

        @param filepath: `str` - The path to the binary file.
        @return `str` - The sentence.
        """
        size: int = 0
        cfg, text_section = self.load_angr_project(self.filepath)

        nodes = filter(lambda node: node.block is not None, cfg)
        instruction_list = tuple(itertools.chain(
            *map(self.read_instructions, nodes)
        ))
        instruction_list = tuple(filter(lambda ins: self.remove_incorrect_instructions(ins) is not None and ins.address - text_section.vaddr <= text_section.memsize and ins.address - text_section.vaddr >= 0, instruction_list))
        instruction_list = tuple(dict([(str(ins.address), ins) for ins in instruction_list]).values())
        bits = functools.reduce(lambda s, ins: s + '1' if ins.mnemonic ==
            'add' else s + '0', instruction_list, '')
        size = int.from_bytes(''.join(
            [chr(int(bits[i:i+8], 2)) for i in range(0, 32, 8)]
        ).encode(), 'big')
        message_retrieved = ''.join(
            [chr(int(bits[i:i+8], 2)) for i in range(32, len(bits), 8)]
        )
        if self.output_file_retreive != '':
            with open(self.output_file_retreive, "wb") as file:
                file.write(message_retrieved[0:size].encode('utf-8'))
                file.close()
            msg_success(
                f"Message retrieved and saved in {self.output_file_retreive}"
            )
        else:
            msg_success(f"Message: {message_retrieved[0:size]}")
        return message_retrieved

    def retrieve_message_from_binary(self: CapierreAnalyzer) -> None:
        """
        This function will read a binary and retrieve the hidden message.
        @return None
        """
        capierre_magic = CapierreMagic()
        index: int = -1
        eh_frame_block: bytes = b''
        project: object = None
        eh_frame_section: object = None
        section_target: str = capierre_magic.SECTION_RETRIEVE
        encoded_string: bytes = b''
        message_retrieved: str = ''

        try:

            project = angr.Project(
                self.filepath, load_options={"auto_load_libs": False}
            )

            for section in project.loader.main_object.sections:
                if section.name == section_target:
                    eh_frame_section = section
                    break

            with open(self.filepath, "rb") as binary:
                eh_frame_block: bytes = binary.read()[
                    eh_frame_section.offset : eh_frame_section.offset
                    + eh_frame_section.memsize
                ]
                binary.close()
            index = eh_frame_block.find(capierre_magic.MAGIC_NUMBER_START)
            if index == -1:
                msg_warning("Message not found within the binary.")
                sys.exit(1)

            alignment_padding: int = eh_frame_block[index - 1]
            index = index - (5 + len(capierre_magic.CIE_INFORMATION))
            length: int = int.from_bytes(eh_frame_block[index: index + 4], "little")
            encoded_string = encoded_string + eh_frame_block[index + 5 + len(capierre_magic.CIE_INFORMATION) + capierre_magic.MAGIC_NUMBER_START_LEN: index + length - alignment_padding + 2]
            index += length + 4

            while index < len(eh_frame_block):
                length = int.from_bytes(eh_frame_block[index: index + 4], "little")
                if (length == 0):
                    break
                if int.from_bytes(eh_frame_block[index + 4: index + 8], "little") != 0:
                    alignment_padding = eh_frame_block[index + 12]
                    encoded_string = encoded_string + eh_frame_block[index + 17: index + length - alignment_padding + 1]
                else:
                    alignment_padding = eh_frame_block[index + 4 + len(capierre_magic.CIE_INFORMATION)]
                    encoded_string = encoded_string + eh_frame_block[index + 5 + len(capierre_magic.CIE_INFORMATION): index + length - alignment_padding + 2]
                index += length + 4

            message_retrieved = self.cipher_information(retrieved_content=encoded_string, decrypt=True)

            if self.output_file_retreive != '':
                with open(self.output_file_retreive, "wb") as file:
                    file.write(message_retrieved.encode('utf-8'))
                    file.close()
                msg_success(
                    f"Message retrieved and saved in {self.output_file_retreive}"
                )
            else:
                msg_success(f"Message: {message_retrieved}")

        except cle.errors.CLECompatibilityError as e:
            msg_error("The chosen file is incompatible")
            sys.exit(1)
        except cle.errors.CLEUnknownFormatError as e:
            msg_error("The file format is incompatible")
            sys.exit(1)
        except cle.errors.CLEInvalidBinaryError as e:
            msg_error("The chosen binary file is incompatible")
            sys.exit(1)
        except Exception as e:
            raise e
