import subprocess
import os
import tempfile
from utils.messages import msg_success, msg_error, msg_warning, msg_info

"""
This function creates a malicious file with the sentence to hide
@param sentence_to_hide: str - The sentence to hide
@return Tuple[str, str] - The path of the malicious file and the path of the sentence to hide
"""
def create_malicious_file(sentence_to_hide: str) -> None:
    # https://stackoverflow.com/a/8577226/23570806
    sentence_to_hide_fd = tempfile.NamedTemporaryFile(delete=False)
    sentence_to_hide_fd.write(sentence_to_hide.encode())

    malicious_code = f"""
    #include <stdio.h>
    #include <stdint.h>

    __asm (
    ".section .rodata\\n"
    "nop\\n"
    ".incbin \\"{sentence_to_hide_fd.name}\\"\\n"
    );
    """

    # https://stackoverflow.com/a/65156317/23570806
    malicious_code_fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
    malicious_code_fd.write(malicious_code.encode())
    return (malicious_code_fd.name, sentence_to_hide_fd.name)

"""
This function compiles the code with the hidden sentence
@param file_path: str - The path of the file to compile
@param sentence_to_hide: str - The sentence to hide
@param type_file: str - The type of file to compile
@return None
"""
def compile_code(file_path: str, sentence_to_hide: str, compilator_name: str) -> None:
    msg_info(f"Hidden sentence: {sentence_to_hide}")
    (malicious_code_file_path, sentece_to_hide_file_path) = create_malicious_file(sentence_to_hide)
    compilation_result = subprocess.run(
        [compilator_name, file_path, malicious_code_file_path, '-o', 'capierre_binary'],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    );
    os.remove(malicious_code_file_path)
    os.remove(sentece_to_hide_file_path)
    if (compilation_result.returncode != 0):
        raise Exception(compilation_result.stderr.strip())
    msg_success('Code compiled successfully')
