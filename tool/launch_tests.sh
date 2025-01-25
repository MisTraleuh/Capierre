#!/bin/bash

# https://stackoverflow.com/a/1744678/23570806
CURRENT_DIR="${PWD##*/}"
EXPECTED_DIR="tool"
BINARY_PATH="./dist/capierre_binary"

echo "Dossier courant : $CURRENT_DIR"

if [ "$CURRENT_DIR" != "$EXPECTED_DIR" ]; then
    echo "Erreur : Ce script doit être exécuté depuis le dossier 'Capierre/tool'"
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Erreur : Le fichier ./dist/capierre est introuvable."
    pip3 install -r requirements.txt
    pyinstaller \
        --collect-all z3        \
        --collect-all pyvex     \
        --collect-all angr      \
        --collect-all unicorn   \
        --collect-all cle       \
        --onefile --name capierre_binary src/__main__.py
    # pyinstaller --collect-all z3 --collect-all pyvex --collect-all angr --collect-all unicorn --collect-all cle --onefile --name capierre_binary src/__main__.py
    exit 1
fi

if [ "$1" == "fonctionnel" ]; then
    pytest tests/fonctionnel/*.py
elif [ "$1" == "unitaire" ]; then
    pytest tests/test_unit.py
else
    echo "Aucune action effectuée."
    echo "Utilisez 'fonctionnel' comme argument pour lancer le test."
    echo "Utilisez 'unitaire' comme argument pour lancer le test."
fi
