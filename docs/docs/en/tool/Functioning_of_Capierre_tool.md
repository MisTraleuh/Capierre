## 🧠 Handling different file types

The **tool Capierre** can handle several file formats, and adapts its behavior accordingly:

- **`.c`** : C source file (not compiled)  

- **`.cpp`** : C++ source file (not compiled)  

- **`.exe`** : Binary compiled for **Windows**.  

- **`.out`** : Binary compiled for **Linux (Ubuntu)** **.  

- **`.app`** : Compiled binary for **macOS**.

---

## 📂 Source files: `.c` and `.cpp

When the user provides a source file, Capierre :

1. Detects the file type.

2. Compiles the source file with `gcc` or `g++` depending on the extension.

3. Integrates a hidden phrase into the binary via a custom section.

### 🔍 Extension detection

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

### ⚙️ Conditional compilation

Depending on the extension detected, the appropriate compiler is selected (`gcc` or `g++`):

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

---

## 🛠 Injecting information into the binary

The aim of these steps is to discreetly insert **a phrase to hide** into the binary file.

### 🔧 Function `create_malicious_file`

This function generates two temporary files:

1. A binary file containing the phrase to be hidden.

2. A `.c` source file containing an assembler directive to include this binary via `.incbin` in a custom section.

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
```

#### ⚠️ Why use __asm and .incbin?

>In C (GCC), the `__asm` directive lets you write inline assembly code.\
>The `.incbin` directive lets you include a binary file directly in a source file.\
>The `.section` directive lets you choose a specific section to insert content.

More information is available [here](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html).

---

### 🧪 Function `compile_code`

This function performs the following steps:

1. Creates temporary files with `create_malicious_file`.

2. Compile source file + injected code.

3. Deletes temporary files.

4. Handles compilation errors.

```python
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

**When compiling automatically, an example of a command generated could be:**

```bash

$ gcc file.c /tmp/TMP_DIR123456789/tmp_file.c -o capierre_binary

```

---

## 📑 Choice of section in binary

Instead of using `.rodata`, Capierre uses section `.eh_frame` or equivalent depending on OS.

### ❌ Why not use .rodata?

Using .rodata can cause conflicts: user constants containing the same magic numbers (as seen previously [here](#📑-sections-in-a-binary) 👀) as Capierre can be misinterpreted as hidden messages.



For example, the following problematic code introduces the value `CapierreMagic.MAGIC_NUMBER_START` within this section:

```c

const char *brokeCapierre = "\x43\x41\x50\x49\x45\x52\x52\x45";

```

After researching the sections on this site [the](https://sysblog.informatique.univ-paris-diderot.fr/2024/04/01/le-format-elf-executable-and-linkable-format/).

### ✅ Why use .eh_frame?

Capierre uses the .eh_frame section (or equivalent) for several reasons:

1. Present by default on all platforms (Windows, Linux, macOS)

2. unlikely to interfere with other program data

3. Allows discrete and robust injection

```python
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


### 🧬 CapierreMagic class

This class centralizes:

- The magic numbers used to locate hidden data

- Sections used to hide or find messages

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
```

---

## 📌 Conclusion

Thanks to an intelligent system of analysis, compilation and injection, Capierre makes it possible to hide data in compiled binary files, without altering their operation.\
The precise choice of the .eh_frame section ensures the reliability of the operation on all platforms.