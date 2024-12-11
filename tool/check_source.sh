#!/bin/sh

which pylint >/dev/null || (echo "[!] You must install pylint. (sudo pip install pylint)" >&2; exit 1)
pylint -E src
