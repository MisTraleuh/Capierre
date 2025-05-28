# ❓ How to use capierre ?

## 📦 Installation

## 🚀 Quick Start (Binary Download)

If you don't want to build the project manually, you can **simply download the pre-packaged binary** from the [Releases section](https://github.com/MisTraleuh/Capierre/releases) of the repository.

Once downloaded, make it executable and optionally move it to a directory in your `PATH`:

```bash
chmod +x capierre
sudo mv capierre /usr/local/bin
```

You can now run the CLI with:

```bash
capierre --help
```

---

### 🌀  Clone the Project

```bash
$ git clone git@github.com:MisTraleuh/Capierre.git
$ cd Capierre
```

For the following steps, we will be in the ``tool`` directory:

```bash
$ cd tool
```

### 🧰 Install Dependencies

::: warning
Make sure you have ``Python 3.9`` or higher installed on your machine. If not, you can download it from the [official website](https://www.python.org/downloads/).

Make sure you have ``pip3`` installed on your machine. If not, you can install it by running the following command:

<CodeGroup>
  <CodeGroupItem title="Ubuntu">

```bash
$ sudo apt install python3-pip
```
  </CodeGroupItem>

  <CodeGroupItem title="MacOs">

```bash
$ brew install python3
```
  </CodeGroupItem>

  <CodeGroupItem title="Windows">

```bash
$ choco install python
```
  </CodeGroupItem>
</CodeGroup>

:::

And then install the dependencies with the following command:

```bash
$ pip3 install -r requirements.txt
```

### 🏗️ Build the Project

Once the above steps are completed, we will proceed to compile the project

```bash
$ pyinstaller --onefile --name capierre_binary src/__main__.py
```

Now that the project is compiled, we will move the binary to the root of the project and give it execution permissions:

```bash
$ mv dist/capierre_binary ./capierre
$ chmod +x capierre
```

:::tip 📦 Local Binary
If you want to use the binary locally, you can move it to the `/usr/local/bin` directory:

```bash
$ sudo mv capierre /usr/local/bin
```
:::

Once that is done, we will have the following program:

- `capierre` (the main program)

### 🎲 Run Capierre CLI

```bash
$ ./capierre --help
Usage: Capierre <file> <sentence>
Options:
  -h, --help     Show this help message and exit
  -v, --version  Show version of the tool
  -c, --conceal  Hide a message
  -r, --retrieve Retrieve a message
  -i, --image Switch to Image Mode. Default: Normal Mode
  -fth, --file-to-hide <file>  File to hide
  -s, --sentence <sentence>  Sentence to hide
  -p, --password <password>  Password for encryption
  -f, --file <file>  Input file to compile or to retrieve
  -o, --output <file>  Output file
  -sd, --seed <number>  Optional: Seed used by the image algorithm
  -m, --mode Changes the retrieval process into Compiled mode. Default is Compilation mode
```

### 🖥 Capierre Gui

The Gui is the program that allows you to visualize the tool's functionalities in a graphical interface.

[...]

## 📚 Documentation

For more information on each part of the project, you can consult the documentation:

- [Tool](./tool/Tool_Documentation.md)
- [Gui](./gui/Gui_Documentation.md)

## 💖 Support

Your support helps me continue developing projects like Capierre. Consider buying me a coffee ☕ via [Buy Me a Coffee](https://buymeacoffee.com/mistrale). Thank you for your encouragement!
