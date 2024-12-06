from __future__ import annotations
import sys
import logging

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")
import angr
import cle
import objectplatform
from utils.messages import msg_success, msg_error, msg_warning
from capierreMagic import CapierreMagic


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

    def retrieve_message_from_binary(self: CapierreAnalyzer) -> None:
        """
        This function will read a binary and retrieve the hidden message.
        @return None
        """
        capierre_magic = CapierreMagic()
        index = -1
        rodata_block = bytes()
        project = None
        rodata_section = None
        section_target = capierre_magic.SECTION_RETRIEVE

        try:

            project = angr.Project(self.filepath, load_options={"auto_load_libs": False})

            for section in project.loader.main_object.sections:
                if section.name == section_target:
                    rodata_section = section
                    break

            with open(self.filepath, "rb") as binary:
                rodata_block = binary.read()[
                    rodata_section.offset : rodata_section.offset
                    + rodata_section.memsize
                ]
            binary.close()
            index = rodata_block.find(capierre_magic.MAGIC_NUMBER_START)
            if index == -1:
                msg_warning("Message not found within the binary.")
                sys.exit(1)

            index += capierre_magic.MAGIC_NUMBER_START_LEN
            message_retrieved = rodata_block[
                index : rodata_block[index:].find(capierre_magic.MAGIC_NUMBER_END)
                + index
            ]
            if self.output_file_retreive != None:
                with open(self.output_file_retreive, "wb") as file:
                    file.write(message_retrieved)
                file.close()
                msg_success(
                    f"Message retrieved and saved in {self.output_file_retreive}"
                )
            else:
                msg_success(f"Message: {message_retrieved.decode('utf-8')}")

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
