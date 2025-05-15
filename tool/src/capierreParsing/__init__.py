from __future__ import annotations
import sys
from utils.messages import msg_success, msg_error
import os
import platform


class CapierreParsing:
    """
    This class is responsible for parsing the arguments
    """

    def __init__(self: CapierreParsing) -> None:
        self.name = "Capierre"
        self.version = "1.0.0"
        self.file = str()
        self.type_file = str()
        self.sentence = str()
        self.seed = 42
        self.password = str()
        self.binary_file = "capierre_binary"
        self.output_file_retreive = str()
        self.conceal = False
        self.retrieve = False
        self.image = False
        self.mode = False

    def print_help(self: CapierreParsing) -> None:
        """
        This function prints the help message
        """
        print(f"Usage: {self.name} <file> <sentence>")
        print(f"Options:")
        print(f"  -h, --help     Show this help message and exit")
        print(f"  -v, --version  Show version of the tool")
        print(f"  -c, --conceal  Hide a message")
        print(f"  -r, --retrieve Retrieve a message")
        print(f"  -i, --image Switch to Image Mode. Default: Normal Mode")
        print(f"  -fth, --file-to-hide <file>  File to hide")
        print(f"  -s, --sentence <sentence>  Sentence to hide")
        print(f"  -p, --password <password>  Password for encryption")
        print(f"  -f, --file <file>  Input file to compile or to retrieve")
        print(f"  -o, --output <file>  Output file")
        print(f"  -sd, --seed <number>  Optional: Seed used by the image algorithm")
        print(f"  -m, --mode Changes the retrieval process into Compiled mode. Default is Compilation mode")

    def check_file(self: CapierreParsing) -> bool:
        """
        This function checks if the file is supported
        @return bool - True if the file is supported, False otherwise
        """

        # https://stackoverflow.com/a/61065546/23570806
        magic_numbers = {
            "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            "jpg": bytes([0xFF, 0xD8, 0xFF]),
            "webp": bytes([0x52, 0x49, 0x46, 0x46]),
            "gif": bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]),
            "gif": bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
            "elf": bytes([0x7F, 0x45, 0x4C, 0x46]),
            "mach-o": bytes([0xCF, 0xFA, 0xED, 0xFE]),
            "macho-o-universal": bytes([0xCA, 0xFE, 0xBA, 0xBE]),
        }
        extension_files = {
            "c": ".c",
            "cpp": ".cpp",
        }
        try:
            if self.file is None:
                raise FileNotFoundError()
            with open(self.file, "rb") as fd:
                file_head = fd.read()

            for name, magic in magic_numbers.items():
                if file_head.startswith(magic):
                    self.type_file = name
                    msg_success(f"File detected: {self.type_file}")
                    return True
            for name, end in extension_files.items():
                if self.file.endswith(end):
                    self.type_file = name
                    msg_success(f"File detected: {self.type_file}")
                    return True
            else:
                msg_error("File not supported")
                return False
        except Exception as e:
            raise e

    def get_args(self: CapierreParsing, tuple_possible: tuple[str, str]) -> str:
        index = -1
        if tuple_possible[0] in sys.argv:
            index = sys.argv.index(tuple_possible[0])
            if index + 1 >= len(sys.argv):
                msg_error(
                    f"{tuple_possible[0]}: Argument not found. Usage: {self.name} -h"
                )
                exit(1)
        if tuple_possible[1] in sys.argv:
            index = sys.argv.index(tuple_possible[1])
            if index + 1 >= len(sys.argv):
                msg_error(
                    f"{tuple_possible[1]}: Argument not found. Usage: {self.name} -h"
                )
                exit(1)
        return sys.argv[index + 1]

    def argv_to_password(self: CapierreParsing, argv: list[str]) -> str:
        """
        This function gets the password from the arguments
        @param args - The arguments
        @return str - The password
        """
        if any(arg in argv for arg in ["--password", "-p"]):
            return argv[
                (argv.index("--password") if "--password" in argv else argv.index("-p"))
                + 1
            ]
        return str()

    def argv_to_seed(self: CapierreParsing, argv: list[str]) -> str:
        """
        This function gets the seed from the arguments
        @param args - The arguments
        @return int - The seed
        """
        try:
            if any(arg in argv for arg in ["--seed", "-sd"]):
                return int(argv[
                    (argv.index("--seed") if "--seed" in argv else argv.index("-sd"))
                    + 1
                ])
            return 42
        except:
            msg_error("The chosen seed isn't a valid integer.")
            return -1

    def argv_to_sentence(self: CapierreParsing, argv: list[str]) -> str:
        """
        This function gets the sentence from the arguments
        @param argv - The arguments
        @return str - The sentence
        """

        if any(arg in argv for arg in ["--sentence", "-s"]):
            return argv[
                (argv.index("--sentence") if "--sentence" in argv else argv.index("-s"))
                + 1
            ]
        if any(arg in argv for arg in ["--file-to-hide", "-fth"]):
            file_index = self.get_args(("--file-to-hide", "-fth"))
            if os.path.exists(file_index) == False:
                msg_error(f"File not found: {file_index}")
                exit(1)
            with open(file_index, "r") as file:
                return file.read()
        return str()

    def check_conceal_args(self: CapierreParsing) -> tuple[bool, int]:
        if len(sys.argv) < 5:
            msg_error(f"Not good number of args\nUsage: {self.name} -h")
            return (False, 1)
        if not any(
            arg in sys.argv for arg in ["--sentence", "-s", "--file-to-hide", "-fth"]
        ):
            msg_error(
                f'"--sentence", "-s", "--file-to-hide or "-fth" not found\nUsage: {self.name} -h'
            )
            return (False, 1)

        self.file = self.get_args(("--file", "-f"))
        self.seed = self.argv_to_seed(sys.argv)
        self.sentence = self.argv_to_sentence(sys.argv)
        self.password = self.argv_to_password(sys.argv)

        if (self.seed < 0):
            return (False, 1)
        if any(arg in sys.argv for arg in ["--output", "-o"]):
            self.binary_file = self.get_args(("--output", "-o"))
        if (platform.system() == 'Windows' and self.binary_file.split('.')[-1] != 'exe'):
            self.binary_file = f"{self.binary_file}.exe"
        if os.path.exists(self.file) == False:
            msg_error(f"File not found: {self.file}")
            return (False, 1)
        if self.check_file() == False:
            return (False, 1)
        return (True, 0)

    def check_retrieve_args(self: CapierreParsing) -> tuple[bool, int]:
        self.file = self.get_args(("--file", "-f"))
        self.password = self.argv_to_password(sys.argv)
        if any(arg in sys.argv for arg in ["--output", "-o"]):
            self.output_file_retreive = self.get_args(("--output", "-o"))
        return (True, 0)

    def check_args(self: CapierreParsing) -> tuple[bool, int]:
        """
        This function checks the arguments
        @return tuple[bool, int] - A tuple with a boolean and an integer
        """

        ALL_ARGS = {
            "help": ("--help", "-h"),
            "version": ("--version", "-v"),
            "file_to_hide": ("--file-to-hide", "-fth"),
            "sentence": ("--sentence", "-s"),
            "password": ("--password", "-p"),
            "file": ("--file", "-f"),
            "retrieve": ("--retrieve", "-r"),
            "conceal": ("--conceal", "-c"),
            "image": ("--image", "-i"),
            "mode": ("--mode", "-m")
        }

        if any(arg in sys.argv for arg in ALL_ARGS["help"]):
            self.print_help()
            return (False, 0)
        if any(arg in sys.argv for arg in ALL_ARGS["version"]):
            print(f"{self.name} v{self.version}")
            return (False, 0)
        if any(arg in sys.argv for arg in ALL_ARGS["retrieve"]):
            self.retrieve = True
        if any(arg in sys.argv for arg in ALL_ARGS["conceal"]):
            self.conceal = True
        if self.conceal == False and self.retrieve == False:
            msg_error(f"--retrieve or --conceal not found\nUsage: {self.name} -h")
            return (False, 1)
        if self.conceal == True and self.retrieve == True:
            msg_error(f"--retrieve and --conceal found\nUsage: {self.name} -h")
            return (False, 1)
        if not any(arg in sys.argv for arg in ["--file", "-f"]):
            msg_error(f'"--file", "-f" not found\nUsage: {self.name} -h')
            return (False, 1)
        if any(arg in sys.argv for arg in ALL_ARGS["image"]):
            self.image = True
        if any(arg in sys.argv for arg in ALL_ARGS["mode"]):
            self.mode = True
        if self.conceal == True:
            return self.check_conceal_args()
        else:
            return self.check_retrieve_args()
