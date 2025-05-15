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
    expected_output = "Usage: Capierre <file> <sentence>\nOptions:\n  -h, --help     Show this help message and exit\n  -v, --version  Show version of the tool\n  -c, --conceal  Hide a message\n  -r, --retrieve Retrieve a message\n  -fth, --file-to-hide <file>  File to hide\n  -s, --sentence <sentence>  Sentence to hide\n  -p, --password <password>  Password for encryption\n  -f, --file <file>  File to compile or to retrieve\n  -o, --output <file>  Output file\n  -m, --mode Changes the retrieval process into Compiled mode. Default is Compilation mode\n"
    assert result.stdout == expected_output

def test_conceal_and_retrieve_params():
    result = subprocess_run(
        [BINARY_PATH, '--conceal', '--retrieve'],
    )
    assert result.returncode == 1
    expected_output = "[-] --retrieve and --conceal found\nUsage: Capierre -h\n"
    assert result.stdout == expected_output
