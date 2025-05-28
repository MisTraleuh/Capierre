from __future__ import annotations
import platform


class CapierreMagic:
    def __init__(self: CapierreMagic):
        self.CIE_INFORMATION = b"\x00\x00\x00\x00\x01\x7a\x52\x00\x01\x78\x10\x01\x1b"
        self.MAGIC_NUMBER_START = b"CAPIERRE"
        self.MAGIC_NUMBER_END = self.MAGIC_NUMBER_START[::-1] + (b"\0" * 4)
        self.MAGIC_NUMBER_START_LEN = len(self.MAGIC_NUMBER_START)
        self.MAGIC_NUMBER_END_LEN = len(self.MAGIC_NUMBER_END)
        self.SECTION_HIDE = self.choose_section_hide()
        self.SECTION_RETRIEVE = self.choose_section_retrieve()
        self.SECTION_HIDE_TEXT = self.choose_section_hide_text()
        self.SECTION_PLATFORM = self.fetch_platform()
        self.COMPILE_GCC = (
            "gcc",
            "-nostartfiles",
            "-nostdlib",
            "-x",
            "assembler",
            "-Wl,--oformat=binary,--entry=0",
            "-o",
        )

    def fetch_platform(self) -> str:
        return platform.system()

    def choose_section_hide_text(self: CapierreMagic) -> str | None:
        """
        This function chooses the section to hide the information
        @return `str | None` - The section to hide the information.
        """
        os_type: str = platform.system()
        section: str = ""

        if os_type == "Windows":
            section = ".text"
        elif os_type == "Linux":
            section = ".text"
        elif os_type == "Darwin":
            section = "__TEXT,__text"
        else:
            return None

        return section

    def choose_section_hide(self: CapierreMagic) -> str | None:
        os_type: str = platform.system()
        section: str = ""

        if os_type == "Windows":
            section = ".eh_fram"
        elif os_type == "Linux":
            section = ".eh_frame"
        elif os_type == "Darwin":
            section = "__TEXT,__eh_frame"
        else:
            return None

        return section

    def choose_section_retrieve(self: CapierreMagic) -> str | None:
        os_type: str = platform.system()
        section: str = ""

        if os_type == "Windows":
            section = ".eh_fram"
        elif os_type == "Linux":
            section = ".eh_frame"
        elif os_type == "Darwin":
            section = "__eh_frame"
        else:
            return None

        return section
