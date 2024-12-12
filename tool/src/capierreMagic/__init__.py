from __future__ import annotations
import platform

class CapierreMagic():
    def __init__(self):
        self.CIE_INFORMATION = b"\x00\x00\x00\x00\x01\x7a\x52\x00\x01\x78\x10\x01\x1b"
        self.MAGIC_NUMBER_START = b"CAPIERRE"
        self.MAGIC_NUMBER_END = self.MAGIC_NUMBER_START[::-1] + (b"\0" * 4)
        self.MAGIC_NUMBER_START_LEN = len(self.MAGIC_NUMBER_START)
        self.MAGIC_NUMBER_END_LEN = len(self.MAGIC_NUMBER_END)
        self.SECTION_HIDE = self.choose_section_hide()
        self.SECTION_RETRIEVE = self.choose_section_retrieve()

    """
    This function chooses the section to hide the information
    @return str - The section to hide the information | CAN BE None
    """
    def choose_section_hide(self) -> str | None:
        os_type: str = platform.system()
        section: str = ''

        if (os_type == 'Windows'):
            section = '.eh_fram'
        elif (os_type == 'Linux'):
            section = '.eh_frame'
        elif (os_type == 'Darwin'):
            section = '__TEXT,__eh_frame'
        else:
            return None

        return section

    def choose_section_retrieve(self) -> str | None:
        os_type: str = platform.system()
        section: str = ''

        if (os_type == 'Windows'):
            section = '.eh_fram'
        elif (os_type == 'Linux'):
            section = '.eh_frame'
        elif (os_type == 'Darwin'):
            section = '__eh_frame'
        else:
            return None

        return section
