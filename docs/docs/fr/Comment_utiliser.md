# ❓ Comment utiliser Capierre ?

## 📦 Installation

### 🌀  Cloner le projet

```bash
$ git clone git@github.com:MisTraleuh/Capierre.git
$ cd Capierre
```

Pour les étapes suivantes, nous travaillerons dans le répertoire ``tool`` :

```bash
$ cd tool
```

### 🧰 Installer les dépendances

::: warning
Assurez-vous d'avoir ``Python 3.9`` ou une version supérieure installée sur votre machine. Si ce n'est pas le cas, vous pouvez le télécharger depuis le [site officiel](https://www.python.org/downloads/).

Vérifiez que ``pip3`` est installé sur votre machine. Si ce n'est pas le cas, installez-le avec la commande suivante :

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

```bash
$ pip3 install -r requirements.txt
```

### 🏗️ Compiler le projet

Une fois les étapes précédentes terminées, procédez à la compilation du projet :

```bash
$ pyinstaller --onefile --name capierre_binary src/__main__.py
```

Après la compilation, déplacez le binaire vers la racine du projet et donnez-lui les permissions d'exécution :

```bash
$ mv dist/capierre_binary ./capierre
$ chmod +x capierre
```

:::tip 📦 Binaire local
Si vous souhaitez utiliser le binaire localement, vous pouvez le déplacer vers le répertoire `/usr/local/bin`:

```bash
$ sudo mv capierre /usr/local/bin
```
:::

Une fois cela fait, vous disposerez du programme suivant :

- `capierre` (le programme principal)

### 🎲 Lancer l'interface CLI

```bash
$ ./capierre --help
```

### 🖥 Interface graphique (GUI)

Le GUI est le programme qui permet de visualiser les fonctionnalités de l'outil dans une interface graphique.

[...]

## 📚 Documentation

Pour plus d'informations sur chaque partie du projet, vous pouvez consulter la documentation :

- [Tool](./tool/Tool_Documentation.md)
- [Gui](./gui/Gui_Documentation.md)

## 💖 Support

Votre soutien m'aide à continuer à développer des projets comme Capierre. Pensez à m'offrir un café ☕ via [Buy Me a Coffee](https://buymeacoffee.com/mistrale).
Merci pour votre encouragement !
