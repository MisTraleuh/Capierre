import subprocess
import os
from . import *

"""
ERROR TESTS
"""
def test_no_arguments():
    result = subprocess_run(
        [BINARY_PATH],
    )
    assert result.returncode == 1
    expected_output = "[-] --retrieve or --conceal not found\nUsage: Capierre -h\n"
    assert result.stdout == expected_output

def test_help_argument():
    result = subprocess_run(
        [BINARY_PATH, '--help'],
    )
    assert result.returncode == 0
    expected_output = "Usage: Capierre <file> <sentence>\nOptions:\n  -h, --help     Show this help message and exit\n  -v, --version  Show version of the tool\n  -c, --conceal  Hide a message\n  -r, --retrieve Retrieve a message\n  -fth, --file-to-hide <file>  File to hide\n  -s, --sentence <sentence>  Sentence to hide\n  -f, --file <file>  File to compile or to retrieve\n  -o, --output <file>  Output file\n"
    assert result.stdout == expected_output

def test_conceal_and_retrieve_params():
    result = subprocess_run(
        [BINARY_PATH, '--conceal', '--retrieve'],
    )
    assert result.returncode == 1
    expected_output = "[-] --retrieve and --conceal found\nUsage: Capierre -h\n"
    assert result.stdout == expected_output

"""
FUNCTIONAL TESTS
"""
def test_hidding_a_hello_world_c_file():
    sentence_to_hide = "Hello World!"
    result = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.c",
         "--sentence", sentence_to_hide],
    )
    assert result.returncode == 0
    expected_output_capierre_tool = f"[+] File detected: c\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output_capierre_tool
    result = subprocess_run(
        [BINARY_FILE_NAME],
    )
    assert result.returncode == 0
    expected_output_launch_c_file = f"Hello, World! C file\n"
    assert result.stdout == expected_output_launch_c_file

    output, error = search_hidden_text(BINARY_FILE_NAME, sentence_to_hide)

    expected_output_find_the_sentence_hide = f"{MAGIC_NUMBER_START}{sentence_to_hide}{MAGIC_NUMBER_END}\n"
    assert output == expected_output_find_the_sentence_hide
    os.remove(BINARY_FILE_NAME)

def test_hidding_a_special_sentence_cpp_file():
    sentence_to_hide = "This is a very special sentence +-*!@#$%^&*()_+^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    result = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--sentence", sentence_to_hide],
    )
    assert result.returncode == 0
    expected_output_capierre_tool = f"[+] File detected: cpp\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output_capierre_tool
    result = subprocess_run(
        [BINARY_FILE_NAME],
    )
    assert result.returncode == 0
    expected_output_launch_c_file = f"Hello, World! C++ file\n"
    assert result.stdout == expected_output_launch_c_file

    output, error = search_hidden_text(BINARY_FILE_NAME, sentence_to_hide)

    expected_output_find_the_sentence_hide = f"{MAGIC_NUMBER_START}{sentence_to_hide}{MAGIC_NUMBER_END}\n"
    assert output == expected_output_find_the_sentence_hide
    os.remove(BINARY_FILE_NAME)

def test_hidding_a_file_in_c_file():
    filepath_to_hide =  f"{TEST_PATH}/HIDDEN_FILE"
    sentence_to_hide = open(filepath_to_hide, 'r').read()

    result = subprocess_run(
        [BINARY_PATH, "--conceal",
         "--file", f"{TEST_PATH}/main.cpp",
         "--file-to-hide", filepath_to_hide],
    )
    assert result.returncode == 0
    expected_output_capierre_tool = f"[+] File detected: cpp\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output_capierre_tool
    result = subprocess_run(
        [BINARY_FILE_NAME],
    )
    assert result.returncode == 0
    expected_output_launch_c_file = f"Hello, World! C++ file\n"
    assert result.stdout == expected_output_launch_c_file

    output, error = search_hidden_text(BINARY_FILE_NAME, sentence_to_hide)

    expected_output_find_the_sentence_hide = f"{MAGIC_NUMBER_START}{sentence_to_hide}{MAGIC_NUMBER_END}\n"
    assert output == expected_output_find_the_sentence_hide
    os.remove(BINARY_FILE_NAME)
