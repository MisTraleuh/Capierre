from __future__ import annotations
import os
import subprocess

BINARY_PATH = f"{os.getcwd()}/dist/capierre_binary"
TEST_PATH = f"{os.getcwd()}/tests/src"
BINARY_FILE_NAME = f"{os.getcwd()}/capierre_binary" + (".exe" if os.name == 'nt' else "")
MAGIC_NUMBER_START = "CAPIERRE"
MAGIC_NUMBER_END = "EERIPAC"
MAGIC_NUMBER_START_LEN = len(MAGIC_NUMBER_START)
MAGIC_NUMBER_END_LEN = len(MAGIC_NUMBER_END)

def subprocess_run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=(os.name == 'nt')
    )

def subprocess_popen(args: list[str], stdin=None) -> subprocess.Popen:
    return subprocess.Popen(
        args,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=(os.name == 'nt')
    )

def search_hidden_text(binary_file, sentence_to_hide):
    if os.name == 'nt':
        strings_command = f"Get-Content -Path '{binary_file}' -Encoding Byte | ForEach-Object {{ [char]$_ }} | Out-String"
        grep_command = f"Select-String -Pattern '{sentence_to_hide}'"

        strings_process = subprocess_popen(
            ["powershell", "-Command", strings_command]
        )

        grep_process = subprocess_popen(
            ["powershell", "-Command", grep_command],
            stdin=strings_process.stdout,
        )

        strings_process.stdout.close()
        output, error = grep_process.communicate()

    else:
        strings_process = subprocess_popen(
            ['strings', binary_file],
        )

        grep_process = subprocess_popen(
            # https://stackoverflow.com/questions/12387685/grep-for-special-characters-in-unix
            ['grep', '-F', sentence_to_hide],
            stdin=strings_process.stdout,
        )

        strings_process.stdout.close()
        output, error = grep_process.communicate()

    return output, error