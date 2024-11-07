@echo off

REM https://stackoverflow.com/a/52557820/23570806
for %%f in ("%CD%") do set CURRENT_DIR=%%~nxf
echo %CURRENT_DIR%

set EXPECTED_DIR=tool
set BINARY_PATH=.\dist\capierre_binary.exe

echo Dossier courant : %CURRENT_DIR%

if not "%CURRENT_DIR%"=="%EXPECTED_DIR%" (
    echo Erreur : Ce script doit etre execute depuis le dossier 'Capierre\tool'
    exit /b 1
)

if not exist "%BINARY_PATH%" (
    echo Erreur : Le fichier .\dist\capierre_binary.exe est introuvable.
    exit /b 1
)

if "%1"=="fonctionnel" (
    for %%f in (tests\fonctionnel\*.py) do (
        pytest %%f
    )
) else if "%1"=="unitaire" (
    pytest tests\test_unit.py
) else (
    echo Aucune action effectuee.
    echo Utilisez 'fonctionnel' comme argument pour lancer le test.
    echo Utilisez 'unitaire' comme argument pour lancer le test.
)
