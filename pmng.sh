#!/bin/bash

cd /home/lebar/projects/password_manager

if ! git branch | grep -q "local"; then
    echo "No local branch"
    read -p "Press any key to exit..."
    exit 1
fi

git checkout local
source pmng_venv/bin/activate
python3 main.py