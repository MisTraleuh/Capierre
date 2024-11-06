import sys
import angr
import cle
from utils.messages import msg_success, msg_error, msg_warning, msg_info

class CapierreAnalyzer():
    """
    This class is responsible for analyzing the file.
    """
    def __init__(self: object, file: str) -> None:
        self.file = file

    """
    This function will read a binary and retrieve the hidden message.
    @return None
    """
    def retrieve_message_from_binary(self: object) -> None:
        index: int = -1
        rodata_block:bytes = []
        project: object = None
        rodata_section: object = None

        try:

            project = angr.Project(self.file)

            for section in project.loader.main_object.sections:
                if section.name == ".rodata":
                    rodata_section = section
                    break

            with open(self.file, 'rb') as binary:
                rodata_block = binary.read()[rodata_section.offset:rodata_section.offset + rodata_section.memsize]
            binary.close()

            index = rodata_block.find(b"CAPIERRE")
            if index == -1:
                msg_warning("Message not found within the binary.")
                sys.exit(84)

            index += 8
            msg_success("Message: " + rodata_block[index:rodata_block[index:].find(b'\0') + index].decode("utf-8"))

        except cle.errors.CLECompatibilityError as e:
                msg_error('The chosen file is incompatible')
                sys.exit(84)
        except cle.errors.CLEInvalidFileFormatError as e:
                msg_error('The file format is incompatible')
                sys.exit(84)
        except cle.errors.CLEUnknownFormatError as e:
                msg_error('The file format is incompatible')
                sys.exit(84)
        except cle.errors.CLEInvalidBinaryError as e:
                msg_error('The chosen binary file is incompatible')
                sys.exit(84)
        except Exception as e:
            raise e
