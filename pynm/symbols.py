"""Data classes for representing symbols extracted from binary files."""

from dataclasses import dataclass


@dataclass
class Symbol:
    """Represents a symbol from a binary file.

    Attributes:
        name: The symbol's name/identifier.
        addr: The symbol's address in the binary.
        size: The symbol's size in bytes (0 if unknown).
        code: The symbol type code (e.g., 'T' for text, 'U' for undefined).
        sym_type: Optional additional type information for the symbol.
    """

    name: str
    addr: int
    size: int
    code: str
    sym_type: str = ""


@dataclass
class Entry:
    """Represents an entry in a binary file (e.g., an archive member or the main binary).

    Attributes:
        name: The entry's name (empty string for main binary, archive member name for archives).
        symbols: List of Symbol objects found in this entry.
    """

    name: str
    symbols: list[Symbol]
