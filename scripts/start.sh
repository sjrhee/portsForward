#!/bin/bash
# scripts/start.sh

# Exit on error
set -e

# Activate venv
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Error: venv not found. Run scripts/setup.sh first."
    exit 1
fi

# Run application
if [ -f "src/main.py" ]; then
    python src/main.py
elif [ -f "src/ui.py" ]; then
    python src/ui.py
else
    echo "Error: Entry point not found (src/main.py or src/ui.py)."
    exit 1
fi
