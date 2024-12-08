import subprocess
import os
from . import *

def test_retrieve_argument():
    sentence_to_hide = "Hello World!"
    result_compile: object = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--sentence", sentence_to_hide],
    )
    assert result_compile.returncode == 0

    result_retrieve: object = subprocess_run(
        [BINARY_PATH, '-r', '--file', BINARY_FILE_NAME],
    )
    assert result_retrieve.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result_retrieve.stdout == expected_output
    os.remove(BINARY_FILE_NAME)

def test_retrieve_a_special_sentence_cpp_file():
    sentence_to_hide = "This is a very special sentence +-*!@#$%^&*()_+^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    result = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--sentence", sentence_to_hide],
    )
    assert result.returncode == 0

    result = subprocess_run(
        [BINARY_PATH, '-r', '--file', BINARY_FILE_NAME],
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)

def test_retrieve_a_file_cpp_file():
    filepath_to_hide = f"{TEST_PATH}/HIDDEN_FILE"
    sentence_to_hide = open(filepath_to_hide, 'r').read()

    result = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--file-to-hide", filepath_to_hide],
    )
    assert result.returncode == 0

    result = subprocess_run(
        [BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME],
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)
