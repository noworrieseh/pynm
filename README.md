# pynm - Python Implementation of the nm Tool

A Python implementation of the Go `nm` symbol table utility, supporting multiple binary file formats.

## Features

- **Multiple Binary Formats**: Full support for ELF, Mach-O (32/64-bit), PE (Windows), COFF, and AR archives
- **Symbol Table Extraction**: Extracts and displays symbols from compiled binaries
- **Flexible Sorting**: Sort symbols by address, name, size, or original order
- **Archive Support**: Process symbols from archive members (`.a` files)
- **Cross-platform**: Works on Linux, macOS, and Windows

## Installation

```bash
pip install -e .
```

## Usage

### Basic Usage

Display symbols from a binary file:

```bash
pynm myprogram
```

### Command-Line Options

```
pynm [options] file...

Options:
  -n              Sort by address (numeric) - shorthand for -sort address
  -size           Print symbol size in decimal between address and type
  -sort ORDER     Sort output: 'address', 'name' (default), 'size', or 'none'
  -type           Print symbol type after the name
```

### Examples

Sort symbols by address:
```bash
pynm -n myprogram
```

Show symbol sizes:
```bash
pynm -size myprogram
```

Sort by size (largest first):
```bash
pynm -sort size myprogram
```

Show all information:
```bash
pynm -n -size -type myprogram
```

Process multiple files:
```bash
pynm prog1 prog2 prog3
```

## Symbol Types

The tool outputs symbol type codes compatible with the standard `nm` utility:

| Code | Meaning |
|------|---------|
| U    | Undefined (referenced but not defined) |
| T    | Text (code) - external |
| t    | Text (code) - local |
| R    | Read-only data - external |
| r    | Read-only data - local |
| B    | BSS (uninitialized data) - external |
| b    | BSS (uninitialized data) - local |
| D    | Initialized data - external |
| d    | Initialized data - local |
| A    | Absolute address |
| V    | Weak external symbol |
| v    | Weak local symbol |
| C    | Common (uninitialized data) |
| I/i  | Indirect symbols |
| ?    | Unknown |

## Architecture

### Module Structure

- **`reader.py`**: Core binary file parsing logic supporting all formats
- **`symbols.py`**: Data classes for `Symbol` and `Entry` representations
- **`cli.py`**: Command-line argument parsing
- **`__main__.py`**: Entry point and output formatting

### Format Support Details

#### ELF (Linux)
- Reads symbol table from `.symtab` section
- Extracts names from `.strtab` string table
- Supports 32-bit and 64-bit formats
- Handles both little-endian and big-endian

#### Mach-O (macOS)
- Reads LC_SYMTAB load command
- Extracts symbol names from string table
- Supports 32-bit and 64-bit variants

#### PE (Windows)
- Reads COFF symbol table
- Handles string table for long symbol names
- Maps storage classes to symbol types

#### COFF (Object Files)
- Reads COFF header and symbol table
- Supports various storage classes
- Section-aware symbol classification

#### Archives (.a files)
- Parses POSIX AR archive format
- Extracts and parses contained binaries
- Supports members in any supported format

## Building Standalone Executable

You can compile pynm into a standalone executable using PyInstaller. This creates a single binary that doesn't require Python to be installed.

### Prerequisites

Install the development dependencies:

```bash
pip install -e ".[dev]"
```

### Build on Linux/macOS

```bash
./build.sh
```

Options:
- `--clean` - Remove previous builds before building
- `--debug` - Enable verbose debug output

```bash
./build.sh --clean --debug
```

### Build on Windows

```cmd
build.bat
```

Options:
- `--clean` - Remove previous builds before building
- `--debug` - Enable verbose debug output

```cmd
build.bat --clean --debug
```

### Manual Build

You can also build manually using PyInstaller:

```bash
# One-file executable (default)
pyinstaller pynm.spec

# Or use command-line options
pyinstaller --onefile --name pynm pynm/__main__.py
```

### Output

The built executable will be in the `dist/` directory:
- **Linux/macOS**: `dist/pynm`
- **Windows**: `dist\pynm.exe`

### Usage

The standalone executable works the same as the Python module:

```bash
# Using the executable
./dist/pynm myprogram

# Or on Windows
dist\pynm.exe myprogram
```

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Test Coverage

The project includes 33 tests covering:
- Format detection for all supported formats
- Symbol extraction from real binaries
- CLI argument parsing
- Integration tests with actual Go and C binaries

### Project Layout

```
pynm/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point and output formatting
├── cli.py              # Command-line argument parsing
├── reader.py           # Binary format parsing
└── symbols.py          # Data classes

tests/
├── conftest.py         # Test fixtures
├── test_cli.py         # CLI parsing tests
├── test_integration.py # Integration tests
├── test_reader.py      # Reader tests
└── test_symbols.py     # Data class tests
```

## Compatibility

- **Python**: 3.10+
- **Dependencies**: None (only standard library)

## Known Limitations

- Symbol sizes are not extracted from Mach-O, PE, or COFF formats (always 0)
  - This is a limitation of these formats which don't always store size information
- Weak symbols and indirect symbols may not be fully distinguished in all formats

## Contributing

When adding support for new formats or fixing bugs:

1. Add comprehensive docstrings to all public methods
2. Update the test suite with format detection and parsing tests
3. Ensure all existing tests continue to pass
4. Use the `_extract_string()` helper for string table lookups to reduce code duplication

## Implementation Notes

### Code Quality

- All source files include module and function docstrings
- Type hints are used throughout
- The `Reader` class implements the context manager protocol for proper resource management
- String extraction is centralized in the `_extract_string()` helper method

### Resource Management

The `Reader` class should always be used with a context manager to ensure proper cleanup:

```python
with Reader("binary") as reader:
    entries = reader.entries()
    # Process entries
    # File is automatically closed
```

## License

(Add your license information here)