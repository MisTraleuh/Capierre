import os
import subprocess

BINARY_PATH = f"{os.getcwd()}/dist/capierre_binary"
TEST_PATH = f"{os.getcwd()}/tests/src"
BINARY_FILE_NAME = f"{os.getcwd()}/capierre_binary"
MAGIC_NUMBER_START = "CAPIERRE"
MAGIC_NUMBER_END = "EERIPAC"
MAGIC_NUMBER_START_LEN = len(MAGIC_NUMBER_START)
MAGIC_NUMBER_END_LEN = len(MAGIC_NUMBER_END)

def subprocess_run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=(os.name == 'nt')
    )

def subprocess_popen(args: list[str], stdin=None) -> subprocess.Popen:
    return subprocess.Popen(
        args,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=(os.name == 'nt')
    )