import subprocess
import os
from . import *

def test_retrieve_argument():
    sentence_to_hide = "Hello World!"
    password = "password"

    result_compile: object = subprocess_run(
        [
         BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--sentence", sentence_to_hide,
         "--password", password,
        ],
    )
    assert result_compile.returncode == 0

    result_retrieve: object = subprocess_run(
        [
         BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME,
         '--password', password
        ],
    )
    assert result_retrieve.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result_retrieve.stdout == expected_output
    os.remove(BINARY_FILE_NAME)

def test_retrieve_a_special_sentence_cpp_file():
    sentence_to_hide = "This is a very special sentence +-*^!@#$%^&*()_+^^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    password = "This is a very big password +-*^!@#$%^&*()_+^^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    
    result = subprocess_run(
        [
         BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--sentence", sentence_to_hide,
         "--password", password,
        ],
    )
    assert result.returncode == 0

    result = subprocess_run(
        [
         BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME,
         '--password', password
        ],
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)

def test_retrieve_a_file_cpp_file():
    filepath_to_hide = f"{TEST_PATH}/HIDDEN_FILE"
    sentence_to_hide = open(filepath_to_hide, 'r').read()
    password = "I love Capierre! Do you want to marry me ?!!!! If you said no I'll cry and I'll never talk to you again :( Sometimes I'm a little bit crazy but I'm a good person trust me <3"

    result = subprocess_run(
        [
         BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--file-to-hide", filepath_to_hide,
         "--password", password,
        ],
    )
    assert result.returncode == 0

    result = subprocess_run(
        [
         BINARY_PATH, '-r',
         '--file', BINARY_FILE_NAME,
         '--password', password
        ],
    )
    assert result.returncode == 0
    expected_output = f"[+] Message: {sentence_to_hide}\n"
    assert result.stdout == expected_output
    os.remove(BINARY_FILE_NAME)
