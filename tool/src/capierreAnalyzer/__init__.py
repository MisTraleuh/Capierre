from __future__ import annotations
import sys
import angr
import cle
from utils.messages import msg_success, msg_error, msg_warning
from capierreMagic import CapierreMagic
from capierreCipher import CapierreCipher


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

    def cipher_information(self: Capierre, *, retrieved_content: str, decrypt: bool) -> str:
        if len(self.password) == 0:
            msg_error("You must supply a password.")
            return
        return CapierreCipher.cipher(
            retrieved_content, self.password, decrypt=decrypt
        )

    def retrieve_message_from_binary(self: CapierreAnalyzer) -> None:
        """
        This function will read a binary and retrieve the hidden message.
        @return None
        """
        capierre_magic = CapierreMagic()
        index: int = -1
        eh_frame_block: bytes = b''
        project: object = None
        eh_frame_section:object = None
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
            length:int = int.from_bytes(eh_frame_block[index: index + 4], "little")
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

            message_retrieved = self.cipher_information(retrieved_content=encoded_string.decode('ascii'), decrypt=True)
            if self.output_file_retreive != '':
                with open(self.output_file_retreive, "wb") as file:
                    file.write(message_retrieved)
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
