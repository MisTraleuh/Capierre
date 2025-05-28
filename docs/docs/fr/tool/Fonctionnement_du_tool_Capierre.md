# 🧠 Documentation des algorithmes du CAPIERRE

## 🔧 Gestion des différents types de fichiers

L'**outil Capierre** peut prendre en charge plusieurs formats de fichiers, et adapte son comportement en fonction de celui-ci :

- **`.c`** : Fichier source C (non compilé)  
- **`.cpp`** : Fichier source C++ (non compilé)  
- **`.exe`** : Binaire compilé pour **Windows**  
- **`.out`** : Binaire compilé pour **Linux (Ubuntu)**  
- **`.app`** : Binaire compilé pour **macOS**

---

## 📂 Fichiers source : `.c` et `.cpp`

Lorsque l'utilisateur fournit un fichier source, Capierre :

1. Détecte le type de fichier.
2. Compile le fichier source avec `gcc` ou `g++` selon l’extension.
3. Intègre une phrase cachée dans le binaire via une section personnalisée.

### 🔍 Détection de l’extension

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

### ⚙️ Compilation conditionnelle

Selon l’extension détectée, le compilateur adéquat est sélectionné (`gcc` ou `g++`) :

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

## 🛠 Injection des informations dans le binaire

L’objectif de ces étapes est d’insérer discrètement **une phrase à cacher** dans le fichier binaire.

### 🧪 Fonction `create_malicious_file`

Cette fonction génère deux fichiers temporaires :

1. Un fichier binaire contenant la phrase à dissimuler.

2. Un fichier source `.c` contenant une directive assembleur pour inclure ce binaire via `.incbin` dans une section personnalisée.


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

#### ⚠️ Pourquoi utiliser __asm et .incbin ?
>En C (GCC), la directive `__asm` permet d’écrire du code assembleur inline.\
>La directive `.incbin` permet d’inclure un fichier binaire directement dans un fichier source.\
>La directive `.section` permet de choisir une section spécifique pour insérer le contenu.

Plus d'informations sont disponibles [ici](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html).


---

### 🧪 Fonction `compile_code`

Cette fonction réalise les étapes suivantes:

1. Crée les fichiers temporaires avec `create_malicious_file`.

2. Compile le fichier source + code injecté.

3. Supprime les fichiers temporaires.

4. Gère les erreurs de compilation.

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

**Lors de la compilation automatisée, un exemple de commande générée pourrait être:**
```bash
$ gcc file.c /tmp/TMP_DIR123456789/tmp_file.c -o capierre_binary
```

---

## 📑 Choix de la section dans le binaire
Au lieu d’utiliser `.rodata`, Capierre utilise la section `.eh_frame` ou équivalent selon l’OS.

### ❌ Pourquoi ne pas utiliser .rodata ?
Utiliser .rodata peut causer des conflits : des constantes utilisateur contenant les mêmes magic numbers (comme vu précedemment [ici](#📑-les-sections-dans-un-binaire) 👀) que Capierre peuvent être interprétées à tort comme des messages cachés.

Par exemple, le code problématique suivant introduit la valeur `CapierreMagic.MAGIC_NUMBER_START` au sein de cette section:
```c
const char *brokeCapierre = "\x43\x41\x50\x49\x45\x52\x52\x45";
```

Après plusieurs recherches sur les sections sur ce site [la](https://sysblog.informatique.univ-paris-diderot.fr/2024/04/01/le-format-elf-executable-and-linkable-format/). Nous avons choisi d'utiliser la section ``.eh_frame``.

### ✅ Pourquoi utiliser .eh_frame ?
Capierre utilise la section .eh_frame (ou équivalent) pour plusieurs raisons :

1. Présente par défaut sur toutes les plateformes (Windows, Linux, macOS)

2. Peu susceptible d’interférer avec les autres données du programme

3. Permet une injection discrète et robuste


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

### 🧬 Classe CapierreMagic

Cette classe centralise:

- Les magic numbers pour repérer les données cachées

- Les sections utilisées pour dissimuler ou retrouver les messages


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

### 🧪 Fonction `load_angr_project`

Objet :
Charge le binaire dans un projet angr, analyse la section .text et extrait les instructions arithmétiques (add/sub) adaptées à l'encodage stéganographique.

Étapes :

- Utilisation de LIEF pour identifier la section .text de manière heuristique.
- Démonte le code à l'aide de Capstone.
- Filtre les instructions arithmétiques avec des valeurs immédiates.
- Traite à la fois les binaires standard (PE et ELF) et les binaires Mach-O, qui n'ont pas de dimensionnement correct des symboles.

Retourne :

- Une liste d'objets Instruction utilisables.
- Les valeurs de l'offset, de la taille et de l'adresse virtuelle de la section .text.

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

### 🧪 Fonction `compile_asm`

Compile une instruction d'assemblage (add ou sub) en fonction du bit d'entrée. Si le bit est à 1, l'instruction est inversée (par exemple, sub devient add) et vice versa, ce qui permet de coder efficacement le bit.

Traitement :
- Convertit l'instruction en syntaxe Intel.
- Compile l'instruction à l'aide de GCC via un sous-processus.
- Supprime les sections inutiles (par exemple, .note.gnu.property).

Valeur de retour:

Tuple contenant l'adresse de l'instruction et les octets compilés, ou None si aucune modification n'est nécessaire.

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

### 🧪 Fonction `hide_in_compiled_binaries`

Incorporer un message dans la section du code exécutable d'un binaire en modifiant les instructions de la machine pour coder les bits (0 ou 1) en fonction du choix de l'instruction (add vs sub).

Etapes :

1. Extraction de la liste des instructions et des métadonnées de la section .text :

    - Appelle load_angr_project(filepath) pour obtenir :
        - Instructions à modifier.
        - Offset/taille/adresse de la section .text.

2. Préparation du message :

    - Convertit le message (phrase_à_cacher) en un flux binaire.
    - Préfixe le flux binaire avec 32 bits codant la longueur du message.

3. Vérification de la capacité d'instruction :

    - Vérifie que le système binaire contient suffisamment d'instructions modifiables pour stocker tous les bits.

4. Remplacement des instructions via le multithreading :

    - Utilise un ThreadPool pour remplacer les instructions en fonction des valeurs des bits :

        - bit=1 : génère une instruction d'addition.
        - bit=0 : génère une instruction de soustraction.

    - Le résultat est une séquence d'instructions binaires (octets) et leurs adresses correspondantes.

5. Modification binaire :

    - Modifie la section .text en remplaçant les instructions d'origine par des instructions générées.
    - Écriture du binaire modifié sur le disque.

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

Grâce à un système intelligent d’analyse, de compilation et d’injection, Capierre permet de cacher des données dans des fichiers binaires compilés, sans altérer leur fonctionnement.\
Le choix précis de la section .eh_frame assure la fiabilité de l’opération sur toutes les plateformes.
