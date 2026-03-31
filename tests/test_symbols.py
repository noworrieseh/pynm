import pytest
from pynm.symbols import Symbol, Entry


class TestSymbol:
    def test_symbol_creation(self):
        sym = Symbol(name="main", addr=0x1000, size=100, code="T", sym_type="func")
        assert sym.name == "main"
        assert sym.addr == 0x1000
        assert sym.size == 100
        assert sym.code == "T"
        assert sym.sym_type == "func"

    def test_symbol_defaults(self):
        sym = Symbol(name="foo", addr=0, size=0, code="U")
        assert sym.sym_type == ""


class TestEntry:
    def test_entry_creation(self):
        symbols = [
            Symbol(name="a", addr=1, size=10, code="T"),
            Symbol(name="b", addr=2, size=20, code="t"),
        ]
        entry = Entry(name="test.o", symbols=symbols)
        assert entry.name == "test.o"
        assert len(entry.symbols) == 2

    def test_entry_empty_symbols(self):
        entry = Entry(name="empty.o", symbols=[])
        assert entry.name == "empty.o"
        assert len(entry.symbols) == 0
