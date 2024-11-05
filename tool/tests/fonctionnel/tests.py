import subprocess
import os

BINARY_PATH = "./dist/capierre_binary"
BINARY_FILE_NAME = 'capierre_binary'

"""
ERROR TESTS
"""
def test_no_arguments():
    result = subprocess.run(
        [BINARY_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 1
    expected_output = "[-] Usage: Capierre -h\n"
    assert result.stdout == expected_output

def test_help_argument():
    result = subprocess.run(
        [BINARY_PATH, '--help'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output ='Usage: Capierre <file> <sentence>\nOptions:\n  -h, --help     Show this help message and exit\n  -v, --version  Show version of the tool\n  -fth, --file-to-hide <file>  File to hide\n  -s, --sentence <sentence>  Sentence to hide\n  -f, --file <file>  File to compile\n  -o, --output <file>  Output file\n'
    assert result.stdout == expected_output

def test_hidding_a_hello_world_file_with_a_not_supported_extension():
    sentence_to_hide = "Hello World!"
    result = subprocess.run(
        [BINARY_PATH,
            '--file-to-hide', 'tests/main.blabla',
            '--sentence', sentence_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 1
    expected_output = "[-] File not supported\n"
    assert result.stdout == expected_output

def test_hidding_a_hello_world_c_file():
    sentence_to_hide = "Hello World!"
    result = subprocess.run(
        [BINARY_PATH,
            '--file-to-hide', 'tests/main.c',
            '--sentence', sentence_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output_capierre_tool = f"[+] File detected: c\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output_capierre_tool
    result = subprocess.run(
        ['./capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output_launch_c_file = f"Hello, World! C file\n"
    assert result.stdout == expected_output_launch_c_file

    strings_process = subprocess.Popen(
        ['strings', 'capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    grep_process = subprocess.Popen(
        ['grep', sentence_to_hide],
        stdin=strings_process.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    strings_process.stdout.close()
    output, error = grep_process.communicate()

    expected_output_find_the_sentence_hide = sentence_to_hide + "\n"
    assert output == expected_output_find_the_sentence_hide
    os.remove(BINARY_FILE_NAME)

def test_hidding_a_special_sentence_cpp_file():
    sentence_to_hide = "This is a very special sentence +-*!@#$%^&*()_+^^^^<<>> 1234567890 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ ' \"````"
    result = subprocess.run(
        [BINARY_PATH,
            '--file-to-hide', 'tests/main.cpp',
            '--sentence', sentence_to_hide],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output_capierre_tool = f"[+] File detected: cpp\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output_capierre_tool
    result = subprocess.run(
        ['./capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output_launch_c_file = f"Hello, World! C++ file\n"
    assert result.stdout == expected_output_launch_c_file

    strings_process = subprocess.Popen(
        ['strings', 'capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    grep_process = subprocess.Popen(
        # https://stackoverflow.com/questions/12387685/grep-for-special-characters-in-unix
        ['grep', '-F', sentence_to_hide],
        stdin=strings_process.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    strings_process.stdout.close()
    output, error = grep_process.communicate()

    expected_output_find_the_sentence_hide = sentence_to_hide + "\n"
    assert output == expected_output_find_the_sentence_hide
    os.remove(BINARY_FILE_NAME)
