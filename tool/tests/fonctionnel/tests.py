import subprocess
import os

BINARY_PATH = "./dist/capierre_binary"
BINARY_FILE_NAME = 'capierre_binary'

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

def test_hidding_a_hello_world_c_file():
    sentence_to_hide = "Hello World!"
    result = subprocess.run(
        [BINARY_PATH,
            '--file-to-hide', 'tests/main.c',
            '--sentence', 'Hello World!'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print(result.stdout)
    assert result.returncode == 0
    expected_output = f"[+] File detected: c\n[i] Hidden sentence: {sentence_to_hide}\n[+] Code compiled successfully\n"
    assert result.stdout == expected_output
    result = subprocess.run(
        ['./capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output = f"Hello World!"

    strings_process = subprocess.Popen(
        ['strings', 'capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    grep_process = subprocess.Popen(
        ['grep', expected_output],
        stdin=strings_process.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    strings_process.stdout.close()
    output, error = grep_process.communicate()

    expected_output = "Hello World!\n"
    assert output == expected_output
    os.remove(BINARY_FILE_NAME)
    