#!/bin/bash
# Build script for creating standalone pynm executable
# Usage: ./build.sh [--clean] [--debug]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Building pynm standalone executable ===${NC}"

# Parse arguments
CLEAN=false
DEBUG=false
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
    esac
done

# Clean previous builds if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning previous builds...${NC}"
    rm -rf build dist __pycache__ pynm/__pycache__
fi

# Check if PyInstaller is installed
if ! python -m pip show pyinstaller &> /dev/null; then
    echo -e "${YELLOW}Installing PyInstaller...${NC}"
    python -m pip install pyinstaller
fi

# Build with PyInstaller FIRST (before tests)
echo -e "${YELLOW}Building executable with PyInstaller...${NC}"

if [ "$DEBUG" = true ]; then
    # Debug build with more verbose output
    pyinstaller --clean --noconfirm pynm.spec --log-level DEBUG
else
    pyinstaller --clean --noconfirm pynm.spec
fi

# Verify build
if [ -f "dist/pynm" ] || [ -f "dist/pynm.exe" ]; then
    echo -e "${GREEN}=== Build successful! ===${NC}"

    # Show build info
    if [ -f "dist/pynm" ]; then
        BINARY="dist/pynm"
    else
        BINARY="dist/pynm.exe"
    fi

    echo -e "${GREEN}Executable: $BINARY${NC}"
    ls -lh "$BINARY"

    # Quick test
    echo -e "${YELLOW}Testing executable...${NC}"
    "$BINARY" --help | head -5

    # Run tests AFTER successful build
    echo -e "${YELLOW}Running tests...${NC}"
    python -m pytest tests/ -q

    echo -e "${GREEN}Done!${NC}"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
