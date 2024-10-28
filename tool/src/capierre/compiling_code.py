import subprocess
import os
import tempfile
from utils.messages import msg_success, msg_error, msg_warning, msg_info

def create_malicious_file(sentence_to_hide: str) -> None:
    # https://stackoverflow.com/a/8577226/23570806
    sentece_to_hide_fd = tempfile.NamedTemporaryFile(delete=False)
    sentece_to_hide_fd.write(sentence_to_hide.encode())

    malicious_code = f"""
    #include <stdio.h>
    #include <stdint.h>

    __asm (
    ".section .rodata\\n"
    "nop\\n"
    ".incbin \\"{sentece_to_hide_fd.name}\\"\\n"
    );
    """

    # https://stackoverflow.com/a/65156317/23570806
    malicious_code_fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
    malicious_code_fd.write(malicious_code.encode())
    return (malicious_code_fd.name, sentece_to_hide_fd.name)

def compile_code(file_path: str, sentence_to_hide: str, type_file: str) -> None:
    msg_info(f"Hidden sentence: {sentence_to_hide}")
    (malicious_code_file_path, sentece_to_hide_file_path) = create_malicious_file(sentence_to_hide)
    compiltator = 'g++' if type_file == 'cpp' else 'gcc'
    compilation_result = subprocess.run(
        [compiltator, file_path, malicious_code_file_path, '-o', 'capierre_binary'],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    );
    os.remove(malicious_code_file_path)
    os.remove(sentece_to_hide_file_path)
    if (compilation_result.returncode != 0):
        raise Exception(compilation_result.stderr.strip())
    msg_success('Code compiled successfully')
