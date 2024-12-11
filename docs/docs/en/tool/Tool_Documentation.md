# 📖 Tool documentation

Before diving into the detailed explanation of how the tool works, it is important to understand the basic concepts of steganography and binary manipulation. These two domains are essential to comprehend how **Capierre** functions and how it can be used to embed information into binary files while keeping them functional, regardless of the amount of information embedded or the platform used.

## 📚 Basic Concepts

### 🤔 Steganography

As you probably know, steganography is the art of hiding information within digital media in such a way that it is undetectable. In the case of **Capierre**, steganography is used to embed information into binary files without compromising their functionality.

Since we want a message to not only be hidden and transmitted undetected but also retain its integrity and functionality once extracted, steganography is a natural choice for this project.

### 🧑‍💻 Binary Manipulation

In this section, we will explore how a binary file is structured and how we can manipulate its data to embed additional information. Binary manipulation is an essential skill to understand how **Capierre** works and how it can be used to embed information into binary files.

:::warning 📚 Prerequisites
We will cover the basics of binary manipulation, but it is recommended to have a basic understanding of binary file structures, programming, and operating system nuances. If you do not have this background, we recommend consulting additional resources to better grasp these concepts.
:::

A binary file consists of several elements, including headers, sections, data, and instructions. Each of these elements has a specific role in the binary's operation and can be modified to embed additional information.

Here is a general structure of a binary file:

![Binary Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)

In the case of Capierre, we will focus on the headers and sections of the binary to embed additional information without compromising the binary's functionality.

## 🛠️ How Capierre Works

Since the tool can handle the following input types:
- A `.c` file, which is a C source file that has not yet been compiled.
- A `.cpp` file, which is a C++ source file that has not yet been compiled.
- A `.exe` file, which is a compiled binary executable file for Windows.
- A `.out` file, which is a compiled binary executable file for Ubuntu.
- A `.app` file, which is a compiled binary executable file for macOS.

We will explore how the tool adapts to each of these scenarios.

### 📂 Source Files

For `.c` and `.cpp` files, the tool compiles the source file into a binary executable: `.exe` for Windows, `.out` for Ubuntu, and `.app` for macOS. It then embeds the information into the binary executable while keeping it functional.

To achieve this, the tool checks if the file has a `.c` or `.cpp` extension:

```python
extension_files = {
    'c': '.c',
    'cpp': '.cpp',
}
try:
    with open(self.file, 'rb') as fd:
        file_head = fd.read()
    for name, magic in magic_numbers.items():
        if file_head.startswith(magic):
            self.type_file = name
            msg_success(f'File detected: {self.type_file}')
            return True
    for name, end in extension_files.items():
        if self.file.endswith(end):
            self.type_file = name
            msg_success(f'File detected: {self.type_file}')
            return True
except Exception as e:
    msg_error(f'Error: {e}')
    return False
```

Pour compiler le fichier source, nous avons cette partie là:

```python
def hide_information(self: object) -> None:
    """
    This function hides the information in the file
    @return None
    """
    extension_files = {
        'c': 'gcc',
        'cpp': 'g++',
    }
    if self.type_file in extension_files:
        self.compile_code(self.file, self.sentence, extension_files[self.type_file])
    else:
        msg_error('File not supported')
        sys.exit(1)
```

Then, to integrate the information into the executable binary, we have this part to hide the information:

```python
def create_malicious_file(self: object, sentence_to_hide: str | bytes) -> tuple[str, str]:
    """
    This function creates a malicious file with the sentence to hide.
    @param sentence_to_hide: `str | bytes` - The sentence to hide
    @return `Tuple[str, str]` - The path of the malicious file and the path of the sentence to hide
    """
    capierre_magic: object = CapierreMagic()
    data: bytes = sentence_to_hide
    section: str = capierre_magic.SECTION_HIDE
    sentence_to_hide_length_sereal: str = ''
    # https://stackoverflow.com/a/8577226/23570806
    sentence_to_hide_fd: list[bytes] = tempfile.NamedTemporaryFile(delete=False)
    if (type(sentence_to_hide) == str):
        data = data.encode()
    information_to_hide: str = (capierre_magic.CIE_INFORMATION + 
                                capierre_magic.MAGIC_NUMBER_START +
                                data +
                                capierre_magic.MAGIC_NUMBER_END)
    sentence_to_hide_length_sereal = struct.pack('<i', len(information_to_hide))
    sentence_to_hide_fd.write(sentence_to_hide_length_sereal + information_to_hide)
    sentence_to_hide_fd.close()
    if (platform.system() == 'Windows'):
        sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace('\\', '/')
    malicious_code = f"""
    #include <stdio.h>
    #include <stdint.h>
    __asm (
    ".section {section}\\n"
    ".incbin \\"{sentence_to_hide_fd.name}\\"\\n"
    );
    """
    # https://stackoverflow.com/a/65156317/23570806
    malicious_code_fd = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
    malicious_code_fd.write(malicious_code.encode())
    malicious_code_fd.close()
    return (malicious_code_fd.name, sentence_to_hide_fd.name)

def compile_code(self: object, file_path: str, sentence_to_hide: str | bytes, compilator_name: str) -> None:
    """
    This function compiles the code with the hidden sentence.
    @param file_path: `str` - The path of the file to compile.
    @param sentence_to_hide: `str` - The sentence to hide.
    @param type_file: `str` - The type of file to compile.
    @return None
    """
    info_message: str | bytes = sentence_to_hide
    if type(sentence_to_hide) == bytes:
        info_message = info_message.decode()
    msg_info(f'Hidden sentence: {info_message}')
    (malicious_code_file_path, sentece_to_hide_file_path) = self.create_malicious_file(sentence_to_hide)
    compilation_result = subprocess.run(
        [compilator_name, file_path, malicious_code_file_path, '-o', self.binary_file],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    os.remove(malicious_code_file_path)
    os.remove(sentece_to_hide_file_path)
    if (compilation_result.returncode != 0):
        raise Exception(compilation_result.stderr.strip())
    msg_success('Code compiled successfully')
```

If we decompute the `create_malicious_file` and `compile_code` functions, we can see that the `create_malicious_file` function creates a temporary file containing the information to be hidden, and the `compile_code` function compiles the source file with the hidden information.

#### What does the `create_malicious_file` function do?

Our function `create_malicious_file`:
- Takes a phrase to hide as a parameter.
- Creates a **temporary file** that contains the phrase to hide and the **section** where the phrase will be hidden.
- Creates another **temporary file** containing the assembly code that includes the first **temporary file**, embedding the phrase in the specified section.
- Returns the path to the temporary file containing the assembly code and the path to the temporary file containing the hidden phrase.

:::tip 📚 What is asm?

In C, and particularly with the GCC compiler, we have a directive called `__asm`. It exists in various forms, such as:
- `__asm__`
- `__asm`
- `asm`
- `asm__`

This directive allows us to write assembly code directly in a C or C++ source file. Among assembly instructions, there is a directive called `.incbin`, which, as the name suggests, includes a binary file in the source file (`incbin -> include binary`). Since we don't want the binary file to be directly visible, we hide it in a specific section of the binary using another directive called `.section`, which allows us to create a section in the binary.

You can find more information about this directive [here](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html).
:::

Now let's discuss the `compile_code` function.

#### What does the `compile_code` function do ?

Our `compile_code` function:
- Takes the source file path, the phrase to hide, and the compiler to use as parameters.
- Calls the `create_malicious_file` function to generate the temporary files.
- Compiles the source file along with the temporary files.
- Deletes the temporary files.
- Raises an exception if the compilation fails.

For example, this would result in a command like:

```bash
$ gcc file.c /tmp/TMP_DIR123456789/tmp_file.c -o capierre_binary
```

:::tip 🤓 How does our temporary file tmp_file.c include our malicious file in the compiled binary? During the compilation of our source file, the compiler includes the content of our temporary file into the compiled binary. This is why we created a specific section to hide our temporary file and used the .incbin directive to include it in the binary.

**The __asm instruction is directly interpreted during compilation.**
:::

### 🗂️ Sections in a Binary

If you've read this far, you understand that we created a specific section to hide our temporary file. But how do we choose a section in a binary that **will never have any impact** on the binary's functionality ?

For this purpose, we created a class called ``CapierreMagic`` that contains all the crucial information needed to hide data in a binary.

```python
class CapierreMagic():
    def __init__(self):
        self.CIE_INFORMATION = b"\0\0\0\0\1\0\0\0\x10"
        self.MAGIC_NUMBER_START = b"CAPIERRE"
        self.MAGIC_NUMBER_END = self.MAGIC_NUMBER_START[::-1] + (b"\0" * 4)
        self.MAGIC_NUMBER_START_LEN = len(self.MAGIC_NUMBER_START)
        self.MAGIC_NUMBER_END_LEN = len(self.MAGIC_NUMBER_END)
        self.SECTION_HIDE = self.choose_section_hide()
        self.SECTION_RETRIEVE = self.choose_section_retrieve()

    """
    This function chooses the section to hide the information
    @return str - The section to hide the information | CAN BE None
    """
    def choose_section_hide(self) -> str | None:
        os_type: str = platform.system()
        section: str = ''

        if (os_type == 'Windows'):
            section = '.eh_fram'
        elif (os_type == 'Linux'):
            section = '.eh_frame'
        elif (os_type == 'Darwin'):
            section = '__TEXT,__eh_frame'
        else:
            return None

        return section

    def choose_section_retrieve(self) -> str | None:
        os_type: str = platform.system()
        section: str = ''

        if (os_type == 'Windows'):
            section = '.eh_fram'
        elif (os_type == 'Linux'):
            section = '.eh_frame'
        elif (os_type == 'Darwin'):
            section = '__eh_frame'
        else:
            return None

        return section
```

To be fully transparent, at the very beginning of creating the tool, we chose a section named `.rodata` to hide information. However, after extensive testing, we noticed that this section is used by the compiler to store program constants.

:::warning 🚨 Why not use the `.rodata` section?
If we use the `.rodata` section to hide information, the compiler will overwrite the program's constants with the hidden information. This would render the binary non-functional.
:::

After conducting further research on sections, as detailed on [this site](https://sysblog.informatique.univ-paris-diderot.fr/2024/04/01/le-format-elf-executable-and-linkable-format/), we decided to use the `.eh_frame` section.

:::tip 🤓 Why the `.eh_frame` section?
The `.eh_frame` section is used to store exception handling information. Since we do not want our binary to be affected by the hidden information, we selected this section as the ideal location for embedding the data.
:::

### 📦 Fichier binaire exécutable

[...]
