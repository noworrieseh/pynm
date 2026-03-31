"""Entry point for the pynm command-line tool."""

import sys

# Use absolute imports for PyInstaller compatibility
from pynm.cli import parse_args
from pynm.reader import Reader


def main():
    """Main entry point for the nm tool.

    Reads one or more binary files and outputs their symbol tables.
    Supports multiple binary formats (ELF, Mach-O, PE, COFF, and archives).

    Exits with code 0 on success, 1 if any file cannot be processed,
    or 2 if command-line arguments are invalid.
    """
    args = parse_args()

    exit_code = 0
    file_prefix = len(args.files) > 1

    for file_path in args.files:
        try:
            with Reader(file_path, use_pclntab=args.pclntab) as reader:
                entries = reader.entries()
                addr_width = reader.addr_width

                for entry in entries:
                    syms = entry.symbols

                    if args.sort == "address":
                        syms = sorted(syms, key=lambda s: s.addr)
                    elif args.sort == "name":
                        syms = sorted(syms, key=lambda s: s.name)
                    elif args.sort == "size":
                        # Go sorts undefined symbols (code="U") first, then by size descending
                        # Undefined symbols have size 0, but Go shows them as "largest"
                        syms = sorted(
                            syms,
                            key=lambda s: (
                                s.code != "U",
                                -s.size if s.code != "U" else 0,
                            ),
                        )

                    for sym in syms:
                        if len(entries) > 1:
                            entry_name = entry.name if entry.name else "_go_.o"
                            print(f"{file_path}({entry_name}):\t", end="")
                        elif file_prefix:
                            print(f"{file_path}:\t", end="")

                        if sym.code == "U":
                            print(f"{'':>{addr_width}}", end="")
                        else:
                            print(f"{sym.addr:0{addr_width}x}", end="")

                        if args.size:
                            print(f" {sym.size:10d}", end="")

                        print(f" {sym.code} {sym.name}", end="")

                        if args.type and sym.sym_type:
                            print(f" {sym.sym_type}", end="")

                        print()
        except Exception as e:
            print(f"nm: {e}", file=sys.stderr)
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
