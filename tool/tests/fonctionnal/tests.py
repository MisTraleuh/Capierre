import subprocess

def test_no_arguments():
    result = subprocess.run(
        ['./dist/capierre_binary'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 1
    expected_output = "[-] Usage: Capierre <file> <sentence>\n"
    assert result.stdout == expected_output

def test_help_argument():
    result = subprocess.run(
        ['./dist/capierre_binary', '--help'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0
    expected_output = "Usage: Capierre <file> <sentence>\nOptions:\n  -h, --help     Show this help message and exit\n  -v, --version  Show version of the tool\n"
    assert result.stdout == expected_output