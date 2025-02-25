#!/usr/bin/env bash

# Function to check if a command exists
checkDependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "[-] Error: $2 is not installed. Please install it first!"
        exit 1
    fi
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run this script as root."
    exit 1
fi

# Check for required dependencies
checkDependency "brew" "Homebrew"
checkDependency "cmake" "CMake"
checkDependency "cstool" "Capstone"

# Start building process
echo "[+] Starting the build process..."

# Remove existing build directory if it exists
if [ -d "./build" ]; then
    echo "[+] Removing existing build directory..."
    rm -rf ./build
fi

# Create and enter the build directory
mkdir build && cd build || exit 1

# Run CMake build process
cmake ..
cmake --build .

# Move the binary to /usr/local/bin for global access
echo "[+] Moving MachXplorer binary to /usr/local/bin..."
mv ./MachXplorer /usr/local/bin/machXplorer

echo "[+] Installation complete! Run 'machXplorer -h' to get started."