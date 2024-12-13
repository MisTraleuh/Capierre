# 📚 Concepts de base

## 🤔 Stéganographie

:::tip 📖 Mais c'est quoi la stéganographie ?

Comme vous le savez probablement, la **stéganographie est l'art de cacher des informations dans des supports numériques sans que cela ne soit détecté**. Dans le cas de **Capierre**, la stéganographie est utilisée pour intégrer des informations dans des fichiers binaires sans compromettre leur fonctionnalité.

Cela signifie que les informations intégrées dans le binaire ne doivent pas affecter le fonctionnement du binaire et doivent être extraites sans compromettre l'intégrité du binaire.

D'une manière théorique, et purement théorique cela est possible, mais dans la pratique, cela peut être un peu plus compliqué.
:::

Comme nous voulons qu'un message puisse à la fois être caché et transmis sans être détecté, mais également retrouver son intégrité et sa fonctionnalité une fois extrait, la stéganographie est un choix naturel pour ce projet.

## 🧑‍💻 Manipulation binaire

Dans cette partie nous allons voir comment un binaires est structuré et comment nous pouvons manipuler ces données pour intégrer des informations supplémentaires. La manipulation binaire est une compétence essentielle pour comprendre comment **Capierre** fonctionne et comment il peut être utilisé pour intégrer des informations dans des fichiers binaires.

:::warning 📚 Prérequis
Nous allons voir les concepts de base de la manipulation binaire, mais il est recommandé d'avoir une connaissance de base des structures de fichiers binaires, de la programmation et des nuances des systèmes d'exploitation. Si ce n'est pas le cas, nous vous recommandons de consulter des ressources supplémentaires pour mieux comprendre ces concepts.

- [Binary File Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)
- [Binary File Manipulation](https://www.tutorialspoint.com/assembly_programming/assembly_file_management.htm)
- [Binary File Format](https://en.wikipedia.org/wiki/Binary_file)
- [Binary File Analysis](https://www.hex-rays.com/products/ida/support/tutorials/binary_analysis.pdf)
- [Binary File Editing](https://www.hex-rays.com/products/ida/support/tutorials/binary_editing.pdf)
:::

Un fichier binaire est composé de plusieurs éléments, dont les en-têtes, les sections, les données et les instructions. Chacun de ces éléments a un rôle spécifique dans le fonctionnement du binaire et peut être modifié pour intégrer des informations supplémentaires.

Voici globalement la structure d'un fichier binaire :

![Binary Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)

Dans notre cas du Capierre, nous allons nous concentrer sur les en-têtes et les sections du binaire pour intégrer des informations supplémentaires sans compromettre la fonctionnalité du binaire.

## 🍰 Explication concrète

Prenons le cas simplement de ce magnifique gateau 🎂. Un gateau est composé de plusieurs couches, et chaque couche a un rôle spécifique dans le gateau. Si nous voulons ajouter des ingrédients supplémentaires à une couche sans affecter les autres couches, nous devons être précis et délicat pour ne pas compromettre la structure du gateau, son goût et sa texture.

Si nous regardons de loin ce gateau:

![](/gateau.jpg)

Nous pouvons avoir une idée générale de sa composition, mais si nous voulons comprendre comment chaque ingrédient est intégré dans chaque couche, nous devons examiner de plus près chaque couche et chaque ingrédient.

![](/gateau_etapes.png)

Si nous effectuons la même description pour un fichier binaire, toujours en gardant l'exemple d'un gateau nous aurons :

![](/geateau_etapes_elf.png)

:::warning ⚠️ WARNING ⚠️
Dans cette exemple, nous avons pris un fichier binaire de type ELF (Executable and Linkable Format) qui est un format de fichier binaire utilisé pour les binaires exécutables sur les systèmes Unix et Linux. Ce format est plus complexe que les autres formats de fichiers binaires, mais il est couramment utilisé pour les binaires exécutables sur les systèmes Unix et Linux.

**Toutes les sections ne sont pas toutes visibles dans cette image, mais toutes celles présenter sont indispensable pour le fonctionnement du binaire.**
:::

Et maintenant avec une vision sans analysé appronfondie :

```bash
$ file /bin/ls
/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=36b86f957a1be53733633d184c3a3354f3fc7b12, for GNU/Linux 3.2.0, stripped
```

:::tip 📖 Ils existent combien de sections ?!
Dans un fichier binaire ELF, il existe plusieurs sections, dont les plus courantes sont :

- **.text** : Contient le code exécutable du binaire.
- **.data** : Contient les données initialisées du binaire.
- **.bss** : Contient les données non initialisées du binaire.
- **.rodata** : Contient les données en lecture seule du binaire.
- **.symtab** : Contient la table des symboles du binaire.
- **.strtab** : Contient la table des chaînes du binaire.
- **.shstrtab** : Contient la table des noms de section du binaire.
- **.rela.text** : Contient les entrées de réadressage du code exécutable.
- **.rela.data** : Contient les entrées de réadressage des données initialisées.
- **.rela.bss** : Contient les entrées de réadressage des données non initialisées.
- **.rela.rodata** : Contient les entrées de réadressage des données en lecture seule.
- **.rela.symtab** : Contient les entrées de réadressage de la table des symboles.
- **.rela.strtab** : Contient les entrées de réadressage de la table des chaînes.
- **.rela.shstrtab** : Contient les entrées de réadressage de la table des noms de section.
- **.dynamic** : Contient les informations dynamiques du binaire.
- **.dynsym** : Contient la table des symboles dynamiques du binaire.
- **.dynstr** : Contient la table des chaînes dynamiques du binaire.
- **.plt** : Contient la table de procédures de liaison du binaire.
- **.got** : Contient la table des adresses globales du binaire.
- **.got.plt** : Contient la table des adresses globales de la table de procédures de liaison.
- **.hash** : Contient la table de hachage des symboles du binaire.
- **.gnu.version** : Contient les versions des symboles du binaire.
- **.gnu.version_r** : Contient les versions des symboles requis du binaire.
- **.gnu.hash** : Contient la table de hachage GNU des symboles du binaire.
- **.note** : Contient les notes du binaire.
- **.eh_frame** : Contient les informations de débogage du binaire.
- **.eh_frame_hdr** : Contient les en-têtes des informations de débogage du binaire.
- **.comment** : Contient les commentaires du binaire.
- **.debug** : Contient les informations de débogage du binaire.
- **.debug_info** : Contient les informations de débogage du binaire.
- **.debug_abbrev** : Contient les abréviations des informations de débogage du binaire.
- **.debug_line** : Contient les informations de débogage du binaire.
- **.debug_str** : Contient les chaînes de débogage du binaire.
- **.debug_ranges** : Contient les plages de débogage du binaire.
- **.debug_loc** : Contient les emplacements de débogage du binaire.
- **.debug_aranges** : Contient les plages d'adresses de débogage du binaire.
- **.debug_pubnames** : Contient les noms publics de débogage du binaire.
- **.debug_pubtypes** : Contient les types publics de débogage du binaire.
- **.debug_gdb_scripts** : Contient les scripts GDB de débogage du binaire.
- **.interp** : Contient l'interpréteur du binaire.
- **.note.ABI-tag** : Contient les informations de l'étiquette ABI du binaire.
- **.gnu_debuglink** : Contient les liens de débogage GNU du binaire.
- **.shstrtab** : Contient la table des noms de section du binaire.
- **.init_array** : Contient le tableau d'initialisation du binaire.
- **.fini_array** : Contient le tableau de finition du binaire.

[...]

Vous aurez bien compris qu'il était impossible de tous les lister ici (et encore moins dans une image 🤭), mais vous pouvez consulter la [documentation officielle](https://refspecs.linuxfoundation.org/elf/elf.pdf) pour plus d'informations sur les sections d'un fichier binaire ELF.
:::

Maintenant que nous avons compris l'idée théorique, nous allons voir comment nous pouvons intégrer des informations supplémentaires dans un binaire sans compromettre sa fonctionnalité.
