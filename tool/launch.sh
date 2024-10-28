#!/bin/bash

# https://stackoverflow.com/a/1744678/23570806
CURRENT_DIR="${PWD##*/}"
EXPECTED_DIR="tool"

echo "Dossier courant : $CURRENT_DIR"

if [ "$CURRENT_DIR" != "$EXPECTED_DIR" ]; then
    echo "Erreur : Ce script doit être exécuté depuis le dossier 'Capierre/tool'"
    exit 1
fi

if [ "$1" == "fonctionnal" ]; then
    pytest tests/fonctionnal/*.py
elif [ "$1" == "unitaire" ]; then
    pytest tests/test_unit.py
else
    echo "Aucune action effectuée."
    echo "Utilisez 'fonctionnal' comme argument pour lancer le test."
    echo "Utilisez 'unitaire' comme argument pour lancer le test."
fi
