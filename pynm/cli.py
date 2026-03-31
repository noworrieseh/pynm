"""Command-line interface for the nm symbol table tool."""

import argparse
import sys

HELP_TEXT = """usage: pynm [options] file...
  -n
      an alias for -sort address (numeric),
      for compatibility with other nm commands
  -size
      print symbol size in decimal between address and type
  -sort {address,name,none,size}
      sort output in the given order (default name)
      size orders from largest to smallest
  -type
      print symbol type after name
  -pclntab
      force use of Go pclntab instead of native symbol table
"""


def parse_args():
    """Parse and validate command-line arguments.

    Returns:
        An argparse.Namespace with attributes:
        - n (bool): Whether to sort by address
        - size (bool): Whether to print symbol sizes
        - sort (str): Sort order ('address', 'name', 'size', or 'none')
        - type (bool): Whether to print symbol types
        - pclntab (bool): Whether to force Go pclntab parsing
        - files (list[str]): Binary files to process

    Raises:
        SystemExit: If no files are provided or invalid arguments are given.
    """
    parser = argparse.ArgumentParser(
        usage=HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-n",
        action="store_true",
        help="alias for -sort address",
    )
    parser.add_argument(
        "-size",
        dest="size",
        action="store_true",
        help="print symbol size in decimal between address and type",
    )
    parser.add_argument(
        "-sort",
        dest="sort",
        default="name",
        choices=["address", "name", "none", "size"],
        help="sort output in the given order (default name)",
    )
    parser.add_argument(
        "-type", dest="type", action="store_true", help="print symbol type after name"
    )
    parser.add_argument(
        "-pclntab",
        dest="pclntab",
        action="store_true",
        help="force use of Go pclntab instead of native symbol table",
    )
    parser.add_argument("files", nargs="*", default=[], help="files to process")

    args = parser.parse_args()

    if args.n:
        args.sort = "address"

    if not args.files:
        parser.print_help()
        sys.exit(2)

    return args
