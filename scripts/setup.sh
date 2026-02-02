#!/bin/bash
# scripts/setup.sh

# Exit on error
set -e

echo "Setting up environment..."

# 1. Create venv if not exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists."
fi

# 2. Activate venv
source venv/bin/activate

# 3. Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# 4. Check system dependencies (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if ! dpkg -s python3-tk >/dev/null 2>&1; then
        echo "Warning: python3-tk is not installed. You may need to run: sudo apt-get install python3-tk"
    fi
fi

# 5. Permission for daemon
if [ -f "daemon/port-daemon" ]; then
    chmod +x daemon/port-daemon
    echo "Permissions set for port-daemon."
fi

echo "Setup complete."
