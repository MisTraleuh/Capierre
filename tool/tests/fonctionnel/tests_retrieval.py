import subprocess
import os
from . import *

def test_retrieve_argument():
    sentence_to_hide = "Hello World!"
    result_compile: object = subprocess.run(
        [BINARY_PATH, "--conceal",
         "--file","./tests/main.cpp",
         "--sentence", sentence_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result_compile.returncode == 0

    result_retrieve: object = subprocess.run(
        [BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result_retrieve.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result_retrieve.stdout == expected_output
    os.remove(BINARY_FILE_NAME)
