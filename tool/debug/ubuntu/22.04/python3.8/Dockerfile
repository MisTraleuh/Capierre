FROM ubuntu:22.04

# Installer Python 3.8 et les outils nécessaires
RUN apt-get update && apt-get install -y \
    python3.8 \
    python3.8-venv \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Définir Python 3.8 comme version par défaut de python3 et pip
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
RUN update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip 1

# Définir le répertoire de travail
WORKDIR /app/tool

# Copier le contenu actuel dans le répertoire de travail
COPY . /app

# Créer un environnement virtuel avec Python 3.8
RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --upgrade pip
RUN /app/venv/bin/pip install -r /app/requirements.txt

# Construire le binaire avec PyInstaller
RUN /app/venv/bin/pyinstaller   \
        --collect-all z3        \
        --collect-all pyvex     \
        --collect-all angr      \
        --collect-all unicorn   \
        --collect-all cle       \
        --onefile --name capierre_binary /app/src/__main__.py

# Définir la commande par défaut
CMD ["bash"]
