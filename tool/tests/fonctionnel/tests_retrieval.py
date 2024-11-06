import subprocess
import os

BINARY_PATH = "../dist/capierre_binary"
BINARY_FILE_NAME = 'capierre_binary'

def test_retrieve_argument():
    result_compile: object = subprocess.run(
        [BINARY_PATH, '-c', './tests/rodata_add_member.c', 'Hello World!'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result_compile.returncode == 0
    result_retrieve: object = subprocess.run(
        [BINARY_PATH, '-r', './capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result_retrieve.returncode == 0
    expected_output = "Message: Hello World!\n"
    assert result.stdout == expected_output
