#!/usr/bin/env bash

# Check for dependencies
echo "[+] Checking dependencies..."

# Check for Homebrew
if ! command -v brew &> /dev/null; then
	echo "[-] Homebrew is not installed. Please install Homebrew!"
	exit 1
fi

# Check for Capstone
if ! command -v cstool &> /dev/null; then
	echo "[-] Capstone is not installed. Installing it now..."
	brew install capstone || { echo "[-] Failed to install Capstone!"; exit 1; }
fi

# Get the Capstone include path dynamically
CAPSTONE_PATH="$(brew --prefix capstone)/include"

# Detect shell and update corresponding RC file
case "$SHELL" in
	*/bash) RC_FILE="$HOME/.bashrc" ;;
	*/zsh)  RC_FILE="$HOME/.zshrc" ;;
	*/fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
	*/ksh)  RC_FILE="$HOME/.kshrc" ;;
	*/sh)   RC_FILE="$HOME/.profile" ;;  # Default for generic POSIX sh
	*)      
		echo "[-] Unsupported shell: $SHELL. Please set CPLUS_INCLUDE_PATH manually."
		exit 1
		;;
esac

# Add Capstone include path if not already set
if ! grep -q "export CPLUS_INCLUDE_PATH=$CAPSTONE_PATH" "$RC_FILE"; then
	echo "export CPLUS_INCLUDE_PATH=$CAPSTONE_PATH:\$CPLUS_INCLUDE_PATH" >> "$RC_FILE"
	echo "[+] Added Capstone include path to $RC_FILE"
	source "$RC_FILE"
else
	echo "[+] Capstone include path already set in $RC_FILE"
fi

# Start building the project
echo "[+] Building the project..."

# Remove existing build directory
if [ -d "build" ]; then
	echo "[+] Removing existing build directory..."
	rm -rf build
fi

# Create build directory
mkdir build
cd build || exit

# Run CMake
cmake .. || { echo "[-] CMake configuration failed!"; exit 1; }
cmake --build . || { echo "[-] Build failed!"; exit 1; }

# Move the binary to a local bin directory (no root required)
#INSTALL_PATH="$HOME/bin"
INSTALL_PATH="/usr/local/bin/"
mkdir -p "$INSTALL_PATH"
mv ./MachXplorer "$INSTALL_PATH/machXplorer"

# Ensure $HOME/bin is in the PATH
if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
	echo 'export PATH="$HOME/bin:$PATH"' >> "$RC_FILE"
	source "$RC_FILE"
	echo "[+] Updated PATH to include $HOME/bin in $RC_FILE"
fi

echo "[+] MachXplorer successfully installed in $INSTALL_PATH"
echo "[+] Restart your terminal or run 'source $RC_FILE' to apply changes."
