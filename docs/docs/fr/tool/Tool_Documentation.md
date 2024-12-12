# 📖 Tool documentation

Premièrement avant de commencer à expliquer la manière dont l'outil fonctionne dans ces moindres détails, il est important de comprendre les concepts de base de la stéganographie et de la manipulation binaire. Ces deux domaines sont essentiels pour comprendre comment **Capierre** fonctionne et comment il peut être utilisé pour intégrer des informations dans des fichiers binaires et garder le binaires fonctionnel peut importe la quantité d'informations intégrées et la plateforme utilisée.

## 📚 Concepts de base

### 🤔 Stéganographie

Comme vous le savez probablement, la stéganographie est l'art de cacher des informations dans des supports numériques sans que cela ne soit détecté. Dans le cas de **Capierre**, la stéganographie est utilisée pour intégrer des informations dans des fichiers binaires sans compromettre leur fonctionnalité.

Comme nous voulons qu'un message puisse à la fois être caché et transmis sans être détecté, mais également retrouver son intégrité et sa fonctionnalité une fois extrait, la stéganographie est un choix naturel pour ce projet.

### 🧑‍💻 Manipulation binaire

Dans cette partie nous allons voir comment un binaires est structuré et comment nous pouvons manipuler ces données pour intégrer des informations supplémentaires. La manipulation binaire est une compétence essentielle pour comprendre comment **Capierre** fonctionne et comment il peut être utilisé pour intégrer des informations dans des fichiers binaires.

:::warning 📚 Prérequis
Nous allons voir les concepts de base de la manipulation binaire, mais il est recommandé d'avoir une connaissance de base des structures de fichiers binaires, de la programmation et des nuances des systèmes d'exploitation. Si ce n'est pas le cas, nous vous recommandons de consulter des ressources supplémentaires pour mieux comprendre ces concepts.
:::

Un fichier binaire est composé de plusieurs éléments, dont les en-têtes, les sections, les données et les instructions. Chacun de ces éléments a un rôle spécifique dans le fonctionnement du binaire et peut être modifié pour intégrer des informations supplémentaires.

Voici globallement la structure d'un fichier binaire :

![Binary Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)

Dans notre cas du capierre, nous allons nous concentrer sur les en-têtes et les sections du binaire pour intégrer des informations supplémentaires sans compromettre la fonctionnalité du binaire.

## 🛠️ Fonctionnement du tool Capierre

Vu que le tool peut à la fois prendre en paramètre:
- un fichier `.c`, donc un fichier source C, pas encore compilé,
- un fichier `.cpp` donc un fichier source C++, pas encore compilé,
- un fichier `.exe` déjà compilé, (c'est à dire compilé sur Windows) qui est un fichier binaire exécutable qui peut être exécuté sur Windows, 
- un fichier `.out` déjà compilé, (c'est à dire compilé sur Ubuntu) qui est un fichier binaire exécutable qui peut être exécuté sur Ubuntu.
- un fichier `.app` déjà compilé, (c'est à dire compilé sur macOS) qui est un fichier binaire exécutable qui peut être exécuté sur macOS.

Nous allons voir comment le tool s'adaptera à ces cas de figure.

### 📂 Fichier source

Pour les fichiers `.c` et `.cpp`, le tool va compiler le fichier source en un fichier binaire exécutable `.exe` sur Windows, `.out` sur Ubuntu et `.app` sur macOS. Ensuite, il va intégrer les informations dans le binaire exécutable et le rendre fonctionnel.

Pour se faire nous avons cette partie là qui regarde si le fichier à une extension `.c` ou `.cpp`:

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

Ensuite, pour intégrer les informations dans le binaire exécutable, nous avons cette partie pour cacher les informations:

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

Si on décompase les fonctions `create_malicious_file` et `compile_code`, on peut voir que la fonction `create_malicious_file` crée un fichier temporaire qui contient les informations à cacher et la fonction `compile_code` compile le fichier source avec les informations cachées.

#### Que fais la fonction ``create_malicious_file`` ?

Notre fonction ``create_malicious_file``:
- Prend en paramètre une phrase à cacher
- Elle va créer un ``fichier temporaire`` qui contient la phrase à cacher et la ``section`` où nous allons cacher la phrase
- Elle va créer un nouveau ``fichier temporaire`` qui contient le code assembleur qui va inclure l'ancien ``fichier temporaire`` qui contient la phrase à cacher dans la section que nous avons créée.
- Elle va retourner le chemin du fichier temporaire qui contient le code assembleur et le chemin du fichier temporaire qui contient la phrase à cacher.

:::tip 📚 C'est quoi asm ?!

En C et surtout dans le compilateur GCC, nous avons une directive qui s'appelle ``__asm``. Elle existe sous plusieurs variantes comme:
- ``__asm__``
- ``__asm``
- ``asm``
- ``asm__``

Ce qui nous permet d'écrire directement du code assembleur dans un fichier source C ou C++.
Et dans les instructions assembleur nous avons une directive qui s'appelle ``.incbin`` qui nous permet comme son nom l'indique d'inclure un fichier binaire dans le fichier source ``incbin -> inlcude binary``. Comme nous ne voullons pas que le fichier binaire soit visible, nous allons le cacher dans une section spécifique du binaire c'est pourquoi nous avons une autre directive qui s'appelle ``.section`` qui nous permet de créer une section dans le binaire.

Vous pouvez avoir plus d'information sur cette directive [ici](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html).
:::

Maintenant nous allons parler de la fonction ``compile_code``.

#### Que fais la fonction ``compile_code`` ?

Notre fonction ``compile_code``:
- Prend en paramètre le chemin du fichier source, la phrase à cacher et le compilateur à utiliser
- Elle va appeler la fonction ``create_malicious_file`` pour créer les fichiers temporaires
- Elle va compiler le fichier source avec les fichiers temporaires
- Elle va supprimer les fichiers temporaires
- Si la compilation échoue, elle va lever une exception

Ce qui nous fais par exemple une commande comme celle-ci:

```bash
$ gcc file.c /tmp/TMP_DIR123456789/tmp_file.c -o capierre_binary
```

:::tip 🤓 Mais comment notre fichier temporaire tmp_file.c inclus notre malicious_file dans le binaire compilé ?
A la compilation de notre fichier source, le compilateur va inclure le contenu de notre fichier temporaire dans le binaire compilé. C'est pourquoi nous avons créé une section spécifique pour cacher notre fichier temporaire. Et c'est pourquoi nous avons utilisé la directive ``.incbin`` pour inclure notre fichier temporaire dans le binaire compilé.

**L'instruction ``__asm`` est directement prise en compte quand le compilateur compile le fichier source.**
:::

### 📑 Les sections dans un binaire

Si vous avez lu jusqu'ici, vous avez compris que nous avons créé une section spécifique pour cacher notre fichier temporaire. Mais comment choisir une section d'un binaire qui n'aura **jamais et aucun impact** sur le fonctionnement du binaire ?

Pour cela, nous avons créé une classe qui s'appelle ``CapierreMagic`` qui contient toutes les informations cruciales pour cacher les informations dans un binaire.

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

Pour être totalement transparent, au tout début de la création de l'outil, nous avons choisi une section nommée ``.rodata`` pour cacher les informations. Mais après plusieurs tests, nous avons remarqué que cette section est utilisée par le compilateur pour stocker les constantes du programme. 

:::warning 🚨 Pourquoi ne pas utiliser la section <code>.rodata</code> ?
Si nous utilisons la section ``.rodata`` pour cacher les informations, nous allons avoir certains problèmes majeurs comme:

- Vu que pour retrouver le message nous utilisons des magics number (comme vous l'avez vu avant [ici](#📑-les-sections-dans-un-binaire) 👀), si des personnes mettent des constantes tel comme ça:
```c
const char *brokeCapierre = "\x43\x41\x50\x49\x45\x52\x52\x45";
```
Le compilateur va alors mettre cette constante dans ``.rodata``. Et alors la valeur de cette variable va être le début de notre ``Magic Number`` soit ``CapierreMagic.MAGIC_NUMBER_START``. Ce qui va faire que notre tool, va alors pensé que c'est le début d'un message caché. Alors que ce n'est pas le cas.

:::

Après plusieurs recherches sur les sections sur ce site [la](https://sysblog.informatique.univ-paris-diderot.fr/2024/04/01/le-format-elf-executable-and-linkable-format/). Nous avons choisi d'utiliser la section ``.eh_frame``.

:::tip 🤓 Pourquoi la section <code>.eh_frame</code> ?
La section ``.eh_frame`` est une section qui est utilisée pour stocker les informations sur les exceptions. Voici les raisons pour lequelles nous avons choisi cette section:
- Vu qu'uniquement les exeptions sont stocker, nous empêchons des possibles recidive avec l'utilisateur comme vu dans l'exemple précedent. Le binaire final ne sera impacté par les informations cachées.
- Cette section est toujours présente dans un binaire, peu importe la plateforme utilisée. Ce qui n'est pas forcément le cas pour la section ``.note`` et/ou ``.comment``.
- Elle a très peu d'impace sur le binaire final.
:::

Avec toutes ces informations, la section ``.eh_frame`` est la section parfaite pour cacher les informations dans un binaire.

### 📦 Fichier binaire exécutable

[...]
