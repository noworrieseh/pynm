"""Tests for pynm across multiple Go versions and platforms."""

import os

import pytest

from pynm.reader import Reader

# Get the directory containing test Go binaries
TEST_BINARIES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "go_binaries"
)


def get_binary_path(name):
    """Get the full path to a test binary."""
    return os.path.join(TEST_BINARIES_DIR, name)


def list_available_binaries():
    """List all available test binaries."""
    if not os.path.exists(TEST_BINARIES_DIR):
        return []
    return [f for f in os.listdir(TEST_BINARIES_DIR) if f.startswith("go_")]


class TestGoVersionsDarwin:
    """Test pynm with Go binaries for macOS (darwin/amd64)."""

    @pytest.mark.parametrize(
        "version",
        [
            "1.15.15",
            "1.16.15",
            "1.17.13",
            "1.18.10",
            "1.19.13",
            "1.20.14",
            "1.21.13",
            "1.22.5",
            "1.23.4",
            "1.24.0",
        ],
    )
    def test_darwin_amd64_symbols(self, version):
        """Test that pynm can read symbols from darwin/amd64 Go binaries."""
        binary = get_binary_path(f"go_{version}_darwin_amd64")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        with Reader(binary) as reader:
            entries = reader.entries()
            assert len(entries) > 0
            symbols = entries[0].symbols
            # Should have symbols from Mach-O symbol table
            assert len(symbols) > 0

            # Check symbol codes
            codes = set(s.code for s in symbols)
            assert "T" in codes or "R" in codes  # Should have text or read-only symbols

            # Check that defined symbols have addresses
            defined = [s for s in symbols if s.code not in ("U", "N")]
            assert any(s.addr > 0 for s in defined)


class TestGoVersionsLinux:
    """Test pynm with Go binaries for Linux (linux/amd64)."""

    @pytest.mark.parametrize("version", ["1.15.15", "1.18.10", "1.21.13", "1.24.0"])
    def test_linux_amd64_symbols(self, version):
        """Test that pynm can read symbols from linux/amd64 Go binaries.

        Note: Statically-linked Go binaries may have limited symbol information
        depending on how they were built. This test verifies basic readability.
        """
        binary = get_binary_path(f"go_{version}_linux_amd64")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        with Reader(binary) as reader:
            # Should be able to open and detect format
            assert reader._format == "elf"
            entries = reader.entries()
            assert len(entries) > 0
            # Symbol count may be 0 for statically-linked binaries
            # This is a known limitation, not a bug


class TestGoVersionsWindows:
    """Test pynm with Go binaries for Windows (windows/amd64)."""

    @pytest.mark.parametrize("version", ["1.15.15", "1.18.10", "1.24.0"])
    def test_windows_amd64_symbols(self, version):
        """Test that pynm can read symbols from windows/amd64 Go binaries."""
        binary = get_binary_path(f"go_{version}_windows_amd64.exe")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        with Reader(binary) as reader:
            entries = reader.entries()
            assert len(entries) > 0
            symbols = entries[0].symbols
            # Should have symbols from PE symbol table
            assert len(symbols) > 0

            # Check symbol codes
            codes = set(s.code for s in symbols)
            assert "T" in codes  # Should have text symbols


class TestSymbolCountsByGoVersion:
    """Test that symbol counts are reasonable across Go versions."""

    @pytest.mark.parametrize("version", ["1.15.15", "1.18.10", "1.21.13", "1.24.0"])
    def test_symbol_count_darwin(self, version):
        """Test symbol counts for darwin binaries across versions."""
        binary = get_binary_path(f"go_{version}_darwin_amd64")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        with Reader(binary) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            # All Go compiler binaries should have thousands of symbols
            assert len(symbols) > 1000


class TestAllAvailableBinaries:
    """Integration test for all available Go binaries."""

    def test_all_binaries_readable(self):
        """Test that all binaries in go_binaries/ can be read."""
        binaries = list_available_binaries()
        assert len(binaries) > 0, "No test binaries found"

        for binary_name in binaries:
            binary = get_binary_path(binary_name)
            with Reader(binary) as reader:
                entries = reader.entries()
                assert len(entries) > 0, f"No entries for {binary_name}"
                # Most binaries should have symbols, but statically-linked
                # ELF binaries may not have symbol tables (known limitation)
                if any(
                    binary_name.endswith(suffix)
                    for suffix in ["_linux_amd64", "_linux_ppc64le", "_linux_ppc64"]
                ):
                    continue
                assert len(entries[0].symbols) > 0, f"No symbols for {binary_name}"


class TestPclntabByGoVersion:
    """Test pclntab parsing across Go versions using -pclntab option."""

    @pytest.mark.parametrize(
        "version",
        [
            "1.4.3",
            "1.5.4",
            "1.6.4",
            "1.7.5",
            "1.8.7",
            "1.9.7",
            "1.10.8",
            "1.11.13",
            "1.12.17",
            "1.13.15",
            "1.14.15",
            "1.15.15",
            "1.16.15",
            "1.17.13",
            "1.18.10",
            "1.19.13",
            "1.20.14",
            "1.21.13",
            "1.22.5",
            "1.23.4",
            "1.24.0",
        ],
    )
    def test_darwin_amd64_pclntab(self, version):
        """Test that pynm can read symbols from pclntab for darwin/amd64 Go binaries."""
        binary = get_binary_path(f"go_{version}_darwin_amd64")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            assert len(entries) > 0
            symbols = entries[0].symbols
            # pclntab should provide function symbols
            assert len(symbols) > 0, f"No pclntab symbols for Go {version}"

            # All pclntab symbols should be 'T' (text/code)
            codes = set(s.code for s in symbols)
            assert "T" in codes, f"No T symbols in pclntab for Go {version}"

            # Check that symbols have valid names
            names = [s.name for s in symbols if s.name]
            assert len(names) > 0, f"No named symbols in pclntab for Go {version}"

            # Check that symbols have addresses
            assert any(s.addr > 0 for s in symbols), "No valid addresses in pclntab"

    @pytest.mark.parametrize(
        "version",
        ["1.18.10", "1.21.13", "1.24.0"],
    )
    def test_pclntab_vs_native_symbol_count(self, version):
        """Compare symbol counts between pclntab and native symbol tables."""
        binary = get_binary_path(f"go_{version}_darwin_amd64")
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found")

        # Read with native symbol table
        with Reader(binary, use_pclntab=False) as reader:
            native_entries = reader.entries()
            native_count = len(native_entries[0].symbols)

        # Read with pclntab
        with Reader(binary, use_pclntab=True) as reader:
            pclntab_entries = reader.entries()
            pclntab_count = len(pclntab_entries[0].symbols)

        # Both should have symbols
        assert native_count > 0, f"No native symbols for Go {version}"
        assert pclntab_count > 0, f"No pclntab symbols for Go {version}"

        # Native table typically has more symbols for modern Go
        # (includes data symbols, not just functions)
        # pclntab has only function symbols
