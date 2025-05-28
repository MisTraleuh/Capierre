# 🧠 Capierre tool algorithms

## 🔧 Handling different file types

The **tool** can handle several file formats, and adapts its behavior accordingly:


- **`.c`** : C source file (not compiled)
  
- **`.cpp`** : C++ source file (not compiled)

- **`.exe`** : Binary compiled for **Windows**. 

- **`.out`** : Binary compiled for **Linux (Ubuntu)**.

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

### 🧪 Function `create_malicious_file`

Purpose:\
Generates a malicious C source file that embeds a crafted section (.eh_frame) containing the encrypted message using fake CIE (Common Information Entry) and FDE (Frame Description Entry) structures.

Steps:
1. Encrypt & Chunk Message:
    - Breaks the message into random-sized chunks (1–16 bytes).
    - Chunks are wrapped in fake CIE/FDE structures that resemble DWARF debugging data.

2. Fake Structure Construction:

    - Every few chunks, a fake CIE is inserted.
    - Other chunks are wrapped in fake FDEs, with placeholders for addresses.

3. Alignment:

    - Aligns all entries to 4-byte boundaries as required by .eh_frame.

4. macOS Handling:

    - macOS enforces stricter .eh_frame validation.
    - Adds “padding” fake CIEs so the inserted data doesn't cause crashes.

5. Source Code Emission:

    - Embeds the binary data using GCC inline assembly (.incbin) inside a new .eh_frame-like section.

Returns:

- Path to the generated .c file.
- Path to the binary chunk.
- Raw embedded data.

```python
    def create_malicious_file(
        self: Capierre,
        sentence_to_hide: bytes
    ) -> tuple[str, str, bytes]:
        """
        This function creates a malicious file with the sentence to hide.

        @param sentence_to_hide: `bytes` - The sentence to hide.
        @return `Tuple[str, str]` - The path of the malicious file and the path
        of the sentence to hide.
        """
        capierre_magic = CapierreMagic()
        data = bytearray(sentence_to_hide)
        section = capierre_magic.SECTION_HIDE

        information_to_hide = b""
        len_new_cie = 0
        new_size = 0
        temp_information_to_hide = b""
        rand_entry = random.randint(4, 10)
        entry_number = rand_entry
        i = 0

        # https://stackoverflow.com/a/8577226/23570806
        sentence_to_hide_fd = tempfile.NamedTemporaryFile(delete=False)
        rand_step: int = random.randint(1, 16)
        i: int = 0

        # This loop will create chunks out of AES encrypted content and will
        # add them at the end of fake CIE and FDE structure sprinkled with
        # some random data.
        while i < len(data):
            if i == 0:
                temp_information_to_hide = (
                    capierre_magic.MAGIC_NUMBER_START + data[i: i + rand_step]
                )
            else:
                if len(data) < i + rand_step:
                    rand_step = len(data) - i
                temp_information_to_hide = data[i: i + rand_step]

            # This section creates fake CIEs.
            if entry_number == rand_entry:
                len_new_cie = len(information_to_hide)
                temp_information_to_hide = (
                    capierre_magic.CIE_INFORMATION +
                    ((4 - (rand_step & 0b11)) & 0b11).to_bytes(1, 'little') +
                    temp_information_to_hide +
                    struct.pack(
                        'bb',
                        random.randint(0, 127),
                        random.randint(0, 127)
                    )
                )
                entry_number = 0
                rand_entry = random.randint(4, 10)
            # This section creates fake FDEs with a placeholder address.
            else:
                temp_information_to_hide = (
                    struct.pack(
                        '<i',
                        len(information_to_hide) + 4 - len_new_cie
                    ) +
                    b"\x11\x11\x11\x11" +
                    struct.pack(
                        'bb',
                        (
                            4 - (rand_step & 0b11)) & 0b11,
                        random.randint(0, 127)
                    ) +
                    b"\x00\x00\x00" +
                    temp_information_to_hide +
                    struct.pack(
                        'bbb',
                        random.randint(0, 127),
                        random.randint(0, 127),
                        random.randint(0, 127)
                    )
                )

            # This part was added to provided alignment to 4 bytes as the
            # eh_frame format requires.
            new_size = len(temp_information_to_hide)
            if new_size & 0b11:
                new_size = ((new_size | 0b11) ^ 0b11) + 4
                temp_information_to_hide = temp_information_to_hide.ljust(
                    new_size, b'\x00'
                )

            temp_information_to_hide = (
                struct.pack('<i', new_size) +
                temp_information_to_hide
            )
            information_to_hide += temp_information_to_hide
            entry_number += 1
            i += rand_step
            rand_step = random.randint(1, 16)

        # As MacOSX's linker will throw exceptions on invalid eh_frame FDE
        # addresses, the processed data can't be inserted into the binary
        # directly.
        #
        # Since one can't add more data to the eh_frame section after the
        # compilation ends, forcibly adding space to the end of the eh_frame
        # section to store the processed data was the approach chosen.
        #
        # Prior tests showed that the linker will ignore any data that is added
        # to this section passed the terminator and will throw exceptions on
        # CFI sections that are too long.
        #
        # We chose to add the space needed to hold the data as several fake
        # CIEs.
        if platform.system() == 'Darwin':
            final_prep: bytes = (
                b'\x18\x00\x00\x00' +
                capierre_magic.CIE_INFORMATION +
                capierre_magic.MAGIC_NUMBER_START +
                b'\x00\x00\x00'
            )
            final_size = (
                len(information_to_hide) -
                capierre_magic.MAGIC_NUMBER_START_LEN -
                20
            )
            final_count = final_size // 20
            final_remain = final_size % 20
            i = 0
            while i < (final_count - 1):
                final_prep += (
                    b'\x10\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00'
                )
                i += 1

            if final_remain != 0:
                final_prep += (
                    struct.pack('b', 16 + final_remain) +
                    b'\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00' +
                    (b'\x00' * final_remain)
                )
            else:
                final_prep += (
                    b'\x10\x00\x00\x00' +
                    capierre_magic.CIE_INFORMATION +
                    b'\x00\x00\x00'
                )

            sentence_to_hide = information_to_hide
            information_to_hide = final_prep

        # Otherwise, the regular Linux linker will not check anything.
        #
        # Because Linux's linker doesn't care about the size of the eh_frame
        # section, the processed data can be inserted directly into the binary.
        sentence_to_hide_fd.write(information_to_hide)

        sentence_to_hide_fd.close()

        if platform.system() == 'Windows':
            sentence_to_hide_fd.name = sentence_to_hide_fd.name.replace(
                '\\', '/')
        if (platform.system() == 'Darwin'):
            information_to_hide = sentence_to_hide

        malicious_code = f"""
        #include <stdio.h>
        #include <stdint.h>

        __asm (
        ".section {section}\\n"
        ".incbin \\"{sentence_to_hide_fd.name}\\"\\n"
        );
        """

        # https://stackoverflow.com/a/65156317/23570806
        malicious_code_fd = tempfile.NamedTemporaryFile(
            delete=False, suffix=".c")
        malicious_code_fd.write(malicious_code.encode())
        malicious_code_fd.close()

        return (
            malicious_code_fd.name,
            sentence_to_hide_fd.name,
            information_to_hide
        )
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


### 🧪 Function `complete_eh_frame`

Purpose:\
Finalizes the .eh_frame by replacing fake address placeholders with realistic values, improving stealth and preventing binary loaders from crashing.

Steps:
1. Find the .eh_frame-like section in the compiled binary using angr.
2. Locate Magic Marker (MAGIC_NUMBER_START) to find the start of inserted data.
3. Fake Address Patching:
    - Walks through the crafted entries.
    - Replaces placeholder values (\x11\x11\x11\x11) with realistic symbol-based offsets.
4. macOS Handling:
    - For Darwin, the .eh_frame block is truncated or updated differently to ensure compatibility.

5. Write-Back:
    - The updated binary data is written back to disk, completing the embedding.

```python
    def complete_eh_frame_section(  # pylint: disable=C0116
        self: Capierre,
        encoded_message: bytes
    ) -> None:
        capierre_magic = CapierreMagic()
        eh_frame_section = {}
        project = angr.Project(
            self.binary_file,
            load_options={'auto_load_libs': False}
        )
        symbols = project.loader.main_object.symbols
        eh_frame_section = None

        for section in project.loader.main_object.sections:
            if section.name == capierre_magic.SECTION_RETRIEVE:
                eh_frame_section = section
                break
        if eh_frame_section is None:
            raise NonexistentEhFrameSection()
        # To make the fake eh_frame entries more believable, the binary is
        # opened again and its compiled symbols' addresses are added to the
        # FDEs by removing their placeholder values.
        with open(self.binary_file, 'r+b') as binary:
            read_bin = binary.read()
            binary.seek(0)
            eh_frame_block = read_bin[
                eh_frame_section.offset:eh_frame_section.offset +
                eh_frame_section.memsize
            ]

            i = eh_frame_block.find(capierre_magic.MAGIC_NUMBER_START)
            length = 0
            fake_addr = 0

            if i == -1:
                msg_warning("Failure to locate compiled block")
            if platform.system() == 'Darwin':
                eh_frame_block = (
                    eh_frame_block[:i - len(capierre_magic.CIE_INFORMATION) - 4] +
                    encoded_message
                )
            i -= 4 + len(capierre_magic.CIE_INFORMATION)
            while i < len(eh_frame_block):
                length = int.from_bytes(eh_frame_block[i: i + 4], "little")

                if length == 0:
                    break
                if int.from_bytes(eh_frame_block[i + 4: i + 8], "little") != 0:
                    fake_addr = (
                        project.loader.main_object.min_addr +
                        symbols[random.randint(
                            0, len(symbols) - 1)].relative_addr
                    ) - (
                        eh_frame_section.vaddr + i + 8
                    )
                    eh_frame_block = (
                        eh_frame_block[:i + 8] +
                        fake_addr.to_bytes(4, byteorder="little", signed=True) +
                        eh_frame_block[i + 12:]
                    )
                i += length + 4
            read_bin = (
                read_bin[:eh_frame_section.offset] +
                eh_frame_block +
                read_bin[eh_frame_section.offset + eh_frame_section.memsize:]
            )
            binary.truncate(0)
            binary.write(read_bin)
            binary.close()
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

### 🧪 Function `load_angr_project`

Purpose:
Loads the binary into an angr project, parses the .text section, and extracts arithmetic instructions (add/sub) suitable for steganographic encoding.

Steps:

- Uses LIEF to identify .text section heuristically.
- Disassembles the code using Capstone.
- Filters for arithmetic instructions with immediate values.
- Handles both standard (PE and ELF binaries) and Mach-O binaries, which lack proper symbol sizing.

Returns:

- A list of usable Instruction objects.
- .text section's offset, size, and virtual address.

```python
def load_angr_project(self: Capierre, filepath: str):
        try:
            capierre_magic = CapierreMagic()
            capstoneProjModule, project, supported = self.get_correct_architecture(filepath)

            # WARN: Pylint doesn't recognise the angr library's definitions.
            # pylint: disable=E1101

            #if supported == False:
            #    return self.load_mac_binaries(filepath)

            text_section = None
            # This is done instead of calling get_section() because some binaries we tested had improperly named sections.
            for section in project.sections:
                if section.name.startswith(capierre_magic.SECTION_HIDE_TEXT):
                    text_section = section
                    break
                elif section.name.startswith('__text'):
                    text_section = section
                    break

            if text_section is None:
                raise NonexistentTextSection()

            end_text_section: int = text_section.virtual_address + text_section.size
            instruction_list: list = []
            tmp_unduplicated: list = []
            instruction_list_unique: list = []
            len_sentence: int = len(self.sentence) * 8 + 32
            valid_func_list: deque = deque()

            if supported == True:
                valid_func_list = deque(filter(lambda sym: text_section.virtual_address <= sym.value < end_text_section and 0 < sym.size, project.functions))

                while 0 < len(valid_func_list) and len(instruction_list) < len_sentence:
                    for func in list(valid_func_list):
                        if len_sentence <= len(instruction_list):
                            break
                        code = project.get_content_from_virtual_address(func.value, func.size)
                        instruction_list += list(map(InstructionSetWrapper, filter(lambda ins: ins.mnemonic in ("add", "sub") and len(ins.operands) == 2 and ins.operands[1].type == capstone.CS_OP_IMM, capstoneProjModule.disasm(code, func.value))))
                        valid_func_list.popleft()

                    instruction_list = list(dict.fromkeys(instruction_list))

            else:
                # Mach-O binaries are strange in that, while they will provide symbols... somewhat, non of them have an explicit size.
                # The obvious logical thing to do is reorder the symbols by value and calculate the difference between their respective addresses.
                # Due to alignment however, the next address might begin after padding data which might be 0s or NOP instructions.
                # In very rare cases, there is a non zero chance that padding data might be garbage.
                # We'll assume for this release that it might be negligible enough.
                valid_func_list = deque(sorted(filter(lambda sym: sym.type == lief.MachO.Symbol.TYPE.SECTION and text_section.virtual_address <= sym.value < end_text_section, project.symbols), key=lambda sym: sym.value))
                print(len(valid_func_list))
                while 1 < len(valid_func_list) and len(instruction_list) < len_sentence:
                    #The final value will be ignored, that's okay for now.
                    for sym1, sym2 in zip(list(valid_func_list), list(valid_func_list)[1:]):
                        if len_sentence <= len(instruction_list):
                            break
                        code = project.get_content_from_virtual_address(sym1.value, sym2.value - sym1.value)
                        instruction_list += list(map(InstructionSetWrapper, filter(lambda ins: ins.mnemonic in ("add", "sub") and len(ins.operands) == 2 and ins.operands[1].type == capstone.CS_OP_IMM, capstoneProjModule.disasm(code, sym1.value))))
                        valid_func_list.popleft()

                    instruction_list = list(dict.fromkeys(instruction_list))

            instruction_list_unique = [wrapped.ins for wrapped in instruction_list[0:len_sentence]]
            return instruction_list_unique, text_section.offset, text_section.size, text_section.virtual_address

        except cle.errors.CLECompatibilityError:
            msg_error("The chosen file is incompatible")
            return [], 0, 0, 0
        except cle.errors.CLEUnknownFormatError:
            msg_error("The file format is incompatible")
            return [], 0, 0, 0
        except cle.errors.CLEInvalidBinaryError:
            msg_error("The chosen binary file is incompatible")
            return [], 0, 0, 0
        except NonexistentTextSection:
            msg_error("The chosen binary file doesn't have a properly named text section.")
            return [], 0, 0, 0
        except Exception as e:
            raise e
            msg_error("An uncatalogued exception occured.")
            return [], 0, 0, 0
```

### 🧪 Function `compile_asm`

Purpose:\
Compiles an assembly instruction (add or sub) based on the input bit. If the bit is 1, the instruction is inverted (e.g., sub becomes add) and vice versa, effectively encoding the bit.

Process:
- Converts the instruction to Intel syntax.
- Compiles it using GCC via subprocess.
- Strips unnecessary sections (e.g., .note.gnu.property).

Returns:\
Tuple containing the instruction's address and compiled bytes, or None if no change is needed.

```python
    def compile_asm(
        self: Capierre,
        bit: int,
        instruction: Instruction
    ) -> None | tuple[int, bytes]:
        """
        This function is used with external programs to convert assembly op
        codes.

        @param bit: `int` - The bit for the conversion.
        @param instruction: `Instruction` - The instruction object.
        """
        capierre_magic = CapierreMagic()

        if (
            (bit and instruction.mnemonic == 'add') or
            (not bit and instruction.mnemonic == 'sub')
        ):
            return None
        if (
            (bit and instruction.mnemonic == 'sub') or
            (not bit and instruction.mnemonic == 'add')
        ):
            args = instruction.op_str.split(', ')
            immediate = -int(args[1], 16)

            if instruction.mnemonic == 'sub':
                asm = f".intel_syntax noprefix\nadd {args[0]}, {immediate}\n"
            else:
                asm = f".intel_syntax noprefix\nsub {args[0]}, {immediate}\n"
            with tempfile.NamedTemporaryFile() as tmpfile:
                # TODO: Check the GNU C Compiler to be above 14.
                subprocess.run(
                    capierre_magic.COMPILE_GCC + (tmpfile.name, '-'),
                    input=bytes(asm, "ascii"),
                    check=False
                )

                binary = tmpfile.read()
                # Filter out the .note.gnu.property section that is forcibly added by ld in gcc versions > 11.
                if len(binary) > 4096:
                    binary = binary[4096:]

            return (instruction.address, list(binary))
        msg_error('[!] Invalid operand.')
        return None
```

### 🧪 Function `hide_in_compiled_binaries`

Purpose:\
Embeds a message into a binary's executable code section by modifying machine instructions to encode bits (0 or 1) based on instruction choice (add vs sub).

Steps:
1. Extract Instruction List and .text Section Metadata:
    - Calls load_angr_project(filepath) to get:

        - Instructions to modify.
        - Offset/size/address of the .text section.

2. Message Preparation:

    - Converts the message (sentence_to_hide) into a bitstream.
    - Prefixes the bitstream with 32 bits encoding the message length.

3. Instruction Capacity Check:

    - Verifies the binary has enough modifiable instructions to store all bits.

4. Instruction Replacement via Multithreading:

    - Uses a ThreadPool to replace instructions based on bit values:

        - bit=1: Generate an add instruction.
        - bit=0: Generate a sub instruction.

    - The result is a sequence of binary instructions (bytes) and their corresponding addresses.

5. Binary Modification:

    - Patches the .text section by replacing original instructions with generated ones.
    - Writes the modified binary back to disk.

```python
    def hide_in_compiled_binaries(
        self: Capierre,
        filepath: str,
        sentence_to_hide: bytes
    ):
        """
        Hides the current sentence into the already compiled binary.

        @param filepath: `str` - The path to the binary file.
        @param sentence_to_hide: `bytes` - The sentence to hide.
        """
        instruction_list, text_section_offset, text_section_size, text_section_addr = self.load_angr_project(filepath)

        if instruction_list == []:
            msg_error("FATAL: Instruction list is empty.")
            return

        with open(filepath, 'r+b') as file:
            read_bin = file.read()
            text_block = bytearray(
                read_bin[
                    text_section_offset:text_section_offset +
                    text_section_size
                ]
            )

            bitstream: list[int] = [
                self.access_bit(sentence_to_hide, i) for i in range(
                    len(sentence_to_hide) * 8
                )
            ]
            bitstream = [self.retrieve_int_byte(len(sentence_to_hide), i, 32) for i in range(0, 32)] + bitstream

            if (len(instruction_list) < len(bitstream)):
                msg_error(f"FATAL: Binary has {len(instruction_list)} bits available but at least {len(bitstream)} are required.")
                return

            threads = ThreadPool(os.cpu_count())
            instructions: tuple[tuple[int, bytes]] = tuple(filter(
                lambda ins: ins is not None,
                threads.starmap(
                    self.compile_asm, zip(bitstream, instruction_list)
                )
            ))  # type: ignore

            for instruction in instructions:
                text_block[
                    instruction[0] - text_section_addr:
                    instruction[0] - text_section_addr +
                        len(instruction[1])
                ] = instruction[1]
            read_bin = (
                read_bin[:text_section_offset] +
               text_block +
                read_bin[text_section_offset + text_section_size:]
            )

            file.seek(0)
            file.truncate(0)
            file.write(read_bin)
            file.close()
```

---

## 📌 Conclusion

Thanks to an intelligent system of analysis, compilation and injection, Capierre makes it possible to hide data in compiled binary files, without altering their operation.\
The precise choice of the .eh_frame section ensures the reliability of the operation on all platforms.