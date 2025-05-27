## 🧠 Gestion des différents types de fichiers

Le **tool Capierre** peut prendre en charge plusieurs formats de fichiers, et adapte son comportement en fonction de celui-ci :

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

### 🔧 Fonction `create_malicious_file`

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

---

## 📌 Conclusion

Grâce à un système intelligent d’analyse, de compilation et d’injection, Capierre permet de cacher des données dans des fichiers binaires compilés, sans altérer leur fonctionnement.\
Le choix précis de la section .eh_frame assure la fiabilité de l’opération sur toutes les plateformes.
