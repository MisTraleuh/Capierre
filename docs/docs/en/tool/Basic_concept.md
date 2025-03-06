# 📚 Basic Concepts

## 🤔 Steganography

:::tip 📖 What is Steganography?

As you probably know, **steganography is the art of hiding information within digital media in such a way that it is undetectable**. In the case of **Capierre**, steganography is used to embed information into binary files without compromising their functionality.

This means that the information embedded in the binary should not affect its operation and should be extractable without compromising the binary's integrity.

Theoretically, this is possible, but in practice, it can be more complicated.
:::

Since we want a message to be both hidden and transmitted undetected, while also preserving its integrity and functionality once extracted, steganography is a natural choice for this project.

## 🧑‍💻 Binary Manipulation

In this section, we will explore how a binary file is structured and how its data can be manipulated to embed additional information. Binary manipulation is an essential skill for understanding how **Capierre** works and how it can be used to embed information into binary files.

:::warning 📚 Prerequisites
We will cover the basics of binary manipulation, but it is recommended to have a basic understanding of binary file structures, programming, and operating system nuances. If you lack this background, we recommend consulting additional resources to better grasp these concepts:

- [Binary File Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)
- [Binary File Manipulation](https://www.tutorialspoint.com/assembly_programming/assembly_file_management.htm)
- [Binary File Format](https://en.wikipedia.org/wiki/Binary_file)
- [Binary File Analysis](https://www.hex-rays.com/products/ida/support/tutorials/binary_analysis.pdf)
- [Binary File Editing](https://www.hex-rays.com/products/ida/support/tutorials/binary_editing.pdf)
:::

A binary file consists of several elements, including headers, sections, data, and instructions. Each of these elements plays a specific role in the binary's functionality and can be modified to embed additional information.

Here is a general structure of a binary file:

![Binary Structure](https://sysblog.informatique.univ-paris-diderot.fr/wp-content/uploads/2024/04/image.png)

In the case of Capierre, we focus on the headers and sections of the binary to embed additional information without compromising its functionality.

## 🍰 Concrete Example

Consider a delicious cake 🎂. A cake is made up of multiple layers, and each layer has a specific role. If we want to add extra ingredients to a layer without affecting the other layers, we must be precise and careful to avoid compromising the cake's structure, taste, or texture.

If we look at this cake from afar:

![](/gateau.jpg)

We can get a general idea of its composition, but to truly understand how each ingredient fits into each layer, we must take a closer look at every layer and ingredient.

![](/gateau_etapes_en.png)

If we apply this analogy to a binary file, using the example of a cake, we get:

![](/geateau_etapes_elf_en.png)

:::warning ⚠️ WARNING ⚠️
In this example, we used a binary file in the ELF (Executable and Linkable Format) format, which is commonly used for executable binaries on Unix and Linux systems. This format is more complex than other binary formats but is widely used for Unix and Linux executables.

**Not all sections are visible in this image, but the ones shown are essential for the binary's functionality.**
:::

And now, with a basic analysis view:

```bash
$ file /bin/ls
/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=36b86f957a1be53733633d184c3a3354f3fc7b12, for GNU/Linux 3.2.0, stripped
```

:::tip 📖 How many sections exist in a binary ?
In an ELF binary file, there are several sections, with some of the most common being:

- **.text**: Contains the binary's executable code.
- **.data** : Contains the binary's initialized data.
- **.bss** : Contains the binary's uninitialized data.
- **.rodata**: Contains the binary's read-only data.
- **symtab**: Contains the binary symbol table.
- **strtab**: Contains the binary string table.
- **shstrtab**: Contains binary section name table.
- **rela.text**: Contains re-addressing entries for executable code.
- **rela.data**: Contains readdressing entries for initialized data.
- **rela.bss**: Contains readdressing entries for uninitialized data.
- **rela.rodata**: Contains read-only data re-addressing entries.
- **rela.symtab**: Contains symbol table readdress entries.
- **rela.strtab**: Contains string table readdressing entries.
- **rela.shstrtab**: Contains section name table readdress entries.
- **dynamic**: Contains dynamic binary information.
- **dynsym**: Contains the binary's dynamic symbol table.
- **.dynstr**: Contains table of dynamic binary strings.
- **.plt**: Contains table of binary linking procedures.
- **.got**: Contains binary global address table.
- **.got.plt**: Contains the global address table of the linking procedures table.
- **.hash**: Contains the binary symbol hash table.
- **.gnu.version**: Contains versions of binary symbols.
- **.gnu.version_r**: Contains versions of required binary symbols.
- **.gnu.hash**: Contains the GNU hash table for binary symbols.
- **.note**: Contains binary notes.
- **eh_frame**: Contains debugging information for the binary.
- **eh_frame_hdr**: Contains binary debugging information headers.
- **comment**: Contains the binary's comments.
- **.debug**: Contains debugging information for the binary.
- **debug_info**: Contains binary debugging information.
- **.debug_abbrev**: Contains abbreviations for binary debugging information.
- **debug_line**: Contains binary debugging information.
- **debug_str**: Contains binary debugging strings.
- **debug_ranges**: Contains binary debugging ranges.
- **debug_loc**: Contains binary debugging locations.
- **debug_aranges**: Contains the binary's debug address ranges.
- **debug_pubnames**: Contains the public debug names of the binary.
- **debug_pubtypes**: Contains the public debugging types of the binary.
- **debug_gdb_scripts**: Contains GDB scripts for debugging the binary.
- **interp**: Contains the binary's interpreter.
- **note.ABI-tag**: Contains the binary's ABI tag information.
- **.gnu_debuglink**: Contains the binary's GNU debug links.
- **shstrtab**: Contains the binary's section name table.
- **init_array**: Contains the binary's initialization array.
- **fini_array**: Contains the binary's finishing array.

[...]

It is impossible to list all sections here (or represent them in an image 🤭), but you can consult the [official documentation](https://refspecs.linuxfoundation.org/elf/elf.pdf)  for more information on ELF binary file sections.
:::

Now that we have covered the theoretical concept, we will explore how to embed additional information into a binary without compromising its functionality.
