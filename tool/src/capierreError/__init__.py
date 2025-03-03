# pylint: disable=C0114,C0103

class CompilationError(Exception):
    """
    Compilation error exception type.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class NonexistentEhFrameSection(Exception):
    """
    Non-existent eh frame section exception type.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class NonexistentTextSection(Exception):
    """
    Non-existent text section exception type.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
