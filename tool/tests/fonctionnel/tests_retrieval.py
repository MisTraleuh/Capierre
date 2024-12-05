import subprocess
import os
from . import *

def test_retrieve_argument():
    sentence_to_hide = "Hello World!"
    result_compile: object = subprocess.run(
        [BINARY_PATH, "--conceal",
         "--file","./tests/src/main.cpp",
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

def test_retrieve_a_special_sentence_cpp_file():
    sentence_to_hide = "This is a very special sentence +-*!@#$%^&*()_+^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    result = subprocess.run(
        [BINARY_PATH, "--conceal",
         "--file","./tests/src/main.cpp",
         "--sentence", sentence_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0

    result = subprocess.run(
        [BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)

def test_retrieve_a_file_cpp_file():
    filepath_to_hide = "./tests/src/HIDDEN_FILE"
    sentence_to_hide = open(filepath_to_hide, 'r').read()

    result = subprocess.run(
        [BINARY_PATH, "--conceal",
         "--file","./tests/src/main.cpp",
         "--file-to-hide", filepath_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0

    result = subprocess.run(
        [BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)
