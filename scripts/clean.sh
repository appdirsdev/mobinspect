#!/bin/bash

echo 
echo '=======================MobInspect Clean Script for Unix======================='
echo 'Running this script will delete the scan database, all files uploaded and generated.'

script_path=$(basename "$(dirname "$0")")
mobinspect_home="$HOME/.MobInspect"

# Ensure the script is run from the correct directory
if [[ "$script_path" != "scripts" ]]; then
    echo 'Please run this script from the MobInspect directory:'
    echo './scripts/clean.sh'
    exit 1
fi

# Confirmation prompt
VAL=${1:-}
if [[ -z "$VAL" ]]; then
    read -p 'Continue? (Y/N): ' confirm
    [[ $confirm =~ ^[yY]([eE][sS])?$ ]] || exit 1
    VAL=$confirm
fi

echo
if [[ "$VAL" =~ ^[yY]$ ]]; then
    echo 'Cleaning up MobInspect directories and files...'

    # Remove files from key directories
    rm -rf ./mobinspect/{uploads,downloads,StaticAnalyzer/migrations,DynamicAnalyzer/migrations,MobInspect/migrations}/*
    
    echo 'Removing Python bytecode and cache files'
    find ./ -type f -name "*.pyc" -o -name "*.pyo" -delete
    find ./ -type d -name "__pycache__" -exec rm -rf {} +

    # Remove temporary, log, and database files
    echo 'Deleting temporary, log, and database files'
    rm -f ./mobinspect/debug.log ./classes* ./mobinspect/db.sqlite3 ./mobinspect/secret

    # Remove the MobInspect data directory if it exists
    if [[ -d "$mobinspect_home" ]]; then
        echo "Deleting MobInspect data directory: $mobinspect_home"
        rm -rf "$mobinspect_home"
    fi

    echo 'Cleanup complete.'
fi
