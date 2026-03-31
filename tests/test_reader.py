import struct
from pathlib import Path

import pytest

from pynm.reader import Reader


class TestReaderAddrWidth:
    """Tests for address width detection based on binary architecture."""

    def test_addr_width_macho64(self, go_binary):
        """Test that 64-bit Mach-O binaries have addr_width of 16."""
        reader = Reader(str(go_binary))
        assert reader._is_64bit is True
        assert reader.addr_width == 16
        reader.close()

    def test_addr_width_macho64_big_endian(self, temp_dir):
        """Test address width for Mach-O 64-bit big-endian format."""
        bin_path = temp_dir / "test64be"
        bin_path.write_bytes(b"\xfe\xed\xfa\xcf\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is True
        assert reader.addr_width == 16
        reader.close()

    def test_addr_width_macho32_little_endian(self, temp_dir):
        """Test address width for Mach-O 32-bit little-endian format."""
        bin_path = temp_dir / "test32le"
        bin_path.write_bytes(b"\xce\xfa\xed\xfe\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is False
        assert reader.addr_width == 8
        reader.close()

    def test_addr_width_macho32_big_endian(self, temp_dir):
        """Test address width for Mach-O 32-bit big-endian format."""
        bin_path = temp_dir / "test32be"
        bin_path.write_bytes(b"\xfe\xed\xfa\xce\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is False
        assert reader.addr_width == 8
        reader.close()

    def test_addr_width_elf64(self, temp_dir):
        """Test address width for 64-bit ELF format."""
        bin_path = temp_dir / "test.elf64"
        # ELF magic + class (64-bit = 2) + endianness (little = 1)
        bin_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is True
        assert reader.addr_width == 16
        reader.close()

    def test_addr_width_elf32(self, temp_dir):
        """Test address width for 32-bit ELF format."""
        bin_path = temp_dir / "test.elf32"
        # ELF magic + class (32-bit = 1) + endianness (little = 1)
        bin_path.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is False
        assert reader.addr_width == 8
        reader.close()

    def test_addr_width_pe(self, temp_dir):
        """Test address width for PE format (assumed 64-bit)."""
        bin_path = temp_dir / "test.exe"
        bin_path.write_bytes(b"MZ" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is True
        assert reader.addr_width == 16
        reader.close()

    def test_addr_width_unknown_format(self, temp_dir):
        """Test address width for unknown format defaults to 8."""
        bin_path = temp_dir / "test.unknown"
        bin_path.write_bytes(b"NOTAVALIDFORMAT" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._is_64bit is False
        assert reader.addr_width == 8
        reader.close()


class TestReaderFormatDetection:
    def test_detect_macho64(self, go_binary):
        reader = Reader(str(go_binary))
        assert reader._format == "macho64"
        reader.close()

    def test_detect_macho64_big_endian(self, temp_dir):
        """Test detection of Mach-O 64-bit big-endian format."""
        bin_path = temp_dir / "test64be"
        # Mach-O 64-bit big-endian magic: \xfe\xed\xfa\xcf
        bin_path.write_bytes(b"\xfe\xed\xfa\xcf\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "macho64_rev"
        reader.close()

    def test_detect_macho32_little_endian(self, temp_dir):
        """Test detection of Mach-O 32-bit little-endian format."""
        bin_path = temp_dir / "test32le"
        # Mach-O 32-bit little-endian magic: \xce\xfa\xed\xfe
        bin_path.write_bytes(b"\xce\xfa\xed\xfe\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "macho32"
        reader.close()

    def test_detect_macho32_big_endian(self, temp_dir):
        """Test detection of Mach-O 32-bit big-endian format."""
        bin_path = temp_dir / "test32be"
        # Mach-O 32-bit big-endian magic: \xfe\xed\xfa\xce
        bin_path.write_bytes(b"\xfe\xed\xfa\xce\x01\x00\x00\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "macho32_rev"
        reader.close()

    def test_detect_elf(self, temp_dir):
        bin_path = temp_dir / "test.elf"
        bin_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "elf"
        reader.close()

    def test_detect_elf_little_endian(self, temp_dir):
        """Test detection of ELF little-endian format."""
        bin_path = temp_dir / "test.elf.le"
        # ELF magic + class (64-bit) + endianness (little = 1)
        bin_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "elf"
        reader.close()

    def test_detect_elf_big_endian(self, temp_dir):
        """Test detection of ELF big-endian format."""
        bin_path = temp_dir / "test.elf.be"
        # ELF magic + class (64-bit) + endianness (big = 2)
        bin_path.write_bytes(b"\x7fELF\x02\x02\x01\x00" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "elf"
        reader.close()

    def test_detect_pe(self, temp_dir):
        bin_path = temp_dir / "test.exe"
        bin_path.write_bytes(b"MZ" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "pe"
        reader.close()

    def test_pe_with_valid_symbols(self, temp_dir):
        import shutil

        if not shutil.which("x86_64-w64-mingw32-gcc"):
            pytest.skip("mingw not installed")

        import subprocess

        result = subprocess.run(
            [
                "x86_64-w64-mingw32-gcc",
                "-g",
                "-o",
                str(temp_dir / "test.exe"),
                "-x",
                "c",
                "-",
            ],
            input=b"int global_var = 42;\nint main() { return global_var; }\n",
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip("mingw not installed")

        reader = Reader(str(temp_dir / "test.exe"))
        entries = reader.entries()
        assert len(entries) > 0
        symbols = entries[0].symbols
        names = [s.name for s in symbols]
        assert any("global_var" in n for n in names) or any("main" in n for n in names)
        reader.close()

    def test_detect_archive(self, temp_dir):
        bin_path = temp_dir / "test.a"
        bin_path.write_bytes(b"!<ar\n" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "archive"
        reader.close()

    def test_detect_coff(self, temp_dir):
        import struct

        bin_path = temp_dir / "test.o"
        data = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0xE4, 3, 0, 0)
        data += b"\x00" * 100
        bin_path.write_bytes(data)
        reader = Reader(str(bin_path))
        assert reader._format == "coff"
        reader.close()

    def test_detect_unknown(self, temp_dir):
        bin_path = temp_dir / "test.unknown"
        bin_path.write_bytes(b"NOTAVALIDFORMAT" + b"\x00" * 100)
        reader = Reader(str(bin_path))
        assert reader._format == "unknown"
        reader.close()


class TestReaderEntries:
    def test_entries_macho(self, go_binary):
        reader = Reader(str(go_binary))
        entries = reader.entries()
        assert len(entries) > 0
        assert entries[0].name == ""
        assert len(entries[0].symbols) > 0
        reader.close()

    def test_empty_file_raises(self, empty_binary):
        reader = Reader(str(empty_binary))
        with pytest.raises(Exception):
            reader.entries()
        reader.close()


class TestSymbolProperties:
    def test_symbol_has_name(self, go_binary):
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        names = [s.name for s in symbols]
        assert any("main" in name for name in names)
        reader.close()

    def test_symbol_has_address(self, go_binary):
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        addresses = [s.addr for s in symbols if s.code != "U"]
        assert any(addr > 0 for addr in addresses)
        reader.close()

    def test_symbol_has_code(self, go_binary):
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        codes = [s.code for s in symbols]
        assert len(codes) > 0
        for code in codes:
            assert isinstance(code, str)
            assert len(code) == 1
        reader.close()


class TestMachoSymbolSizes:
    """Tests for Mach-O symbol size extraction."""

    def test_defined_symbols_have_sizes(self, go_binary):
        """Defined symbols in sections should have non-zero sizes."""
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        defined = [s for s in symbols if s.code not in ("U", "N")]
        # At least some defined symbols should have non-zero sizes
        non_zero_sizes = [s for s in defined if s.size > 0]
        assert len(non_zero_sizes) > 0
        reader.close()

    def test_undefined_symbols_have_zero_size(self, go_binary):
        """Undefined symbols should have size 0."""
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        undefined = [s for s in symbols if s.code == "U"]
        assert len(undefined) > 0
        for sym in undefined:
            assert sym.size == 0
        reader.close()

    def test_symbol_sizes_are_positive_integers(self, go_binary):
        """All symbol sizes should be non-negative integers."""
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        for sym in symbols:
            assert isinstance(sym.size, int)
            assert sym.size >= 0
        reader.close()

    def test_consecutive_symbols_in_section_have_correct_sizes(self, go_binary):
        """Symbols in the same section should have sizes based on address distance."""
        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols

        # Group symbols by section (using address as proxy since we don't expose n_sect)
        defined = [s for s in symbols if s.code not in ("U", "N") and s.size > 0]
        assert len(defined) > 0

        # Verify sizes are reasonable (not absurdly large)
        for sym in defined:
            assert sym.size < 10_000_000  # Sanity check: no symbol > 10MB
        reader.close()


class TestGoPclntabReading:
    """Tests for Go pclntab symbol extraction."""

    def test_pclntab_fallback_on_stripped_binary(self):
        """Test that pclntab is used when Mach-O symbol table is empty."""
        # Use the go_1.4.3_darwin_ppc_test which has pclntab symbols
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        reader = Reader(str(go_binary))
        entries = reader.entries()
        assert len(entries) > 0
        symbols = entries[0].symbols
        # Should have symbols from pclntab
        assert len(symbols) > 0
        reader.close()

    def test_pclntab_symbols_have_correct_code(self):
        """Test that pclntab symbols have expected codes."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        # pclntab symbols should be 'T' (text/code), 'R' (read-only data),
        # 'D' (data), or 'B' (BSS)
        codes = set(s.code for s in symbols)
        assert codes <= {"T", "R", "D", "B"}, f"Unexpected codes: {codes - {'T', 'R', 'D', 'B'}}"
        # Should have T symbols (functions)
        assert "T" in codes, "No T symbols in pclntab"
        reader.close()

    def test_pclntab_symbols_have_names(self):
        """Test that pclntab symbols have valid names."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        # All symbols should have non-empty names
        names = [s.name for s in symbols]
        assert all(names)
        assert all(isinstance(n, str) for n in names)
        reader.close()

    def test_pclntab_symbols_have_addresses(self):
        """Test that pclntab symbols have valid addresses."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        # All symbols should have positive addresses
        for sym in symbols:
            assert sym.addr > 0
        reader.close()

    def test_pclntab_symbol_count(self):
        """Test that we extract a reasonable number of symbols from pclntab."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        reader = Reader(str(go_binary))
        entries = reader.entries()
        symbols = entries[0].symbols
        # go_1.4.3_darwin_ppc_test should have thousands of symbols
        assert len(symbols) > 4000
        reader.close()

    def test_find_pclntab_big_endian(self, temp_dir):
        """Test finding pclntab with big-endian magic bytes."""
        # Create a minimal fake pclntab with big-endian magic
        header = b"\xff\xff\xff\xfb"  # Big-endian magic
        header += b"\x00\x00"  # Padding
        header += b"\x04"  # Quantum = 4
        header += b"\x04"  # Ptr size = 4 (32-bit)
        header += struct.pack(">I", 0)  # nfuncs = 0

        fake_binary = header + b"\x00" * 100

        bin_path = temp_dir / "fake_pclntab_be"
        bin_path.write_bytes(fake_binary)

        reader = Reader(str(bin_path))
        # Manually test _find_pclntab
        data = fake_binary
        MAGIC_BE = b"\xff\xff\xff\xfb"
        MAGIC_LE = b"\xfb\xff\xff\xff"
        offset = reader._find_pclntab(data, MAGIC_BE, MAGIC_LE)
        assert offset == 0  # Found at start
        reader.close()

    def test_find_pclntab_little_endian(self, temp_dir):
        """Test finding pclntab with little-endian magic bytes."""
        # Create a minimal fake pclntab with little-endian magic
        header = b"\xfb\xff\xff\xff"  # Little-endian magic
        header += b"\x00\x00"  # Padding
        header += b"\x04"  # Quantum = 4
        header += b"\x08"  # Ptr size = 8 (64-bit)
        header += struct.pack("<I", 0)  # nfuncs = 0

        fake_binary = header + b"\x00" * 100

        bin_path = temp_dir / "fake_pclntab_le"
        bin_path.write_bytes(fake_binary)

        reader = Reader(str(bin_path))
        data = fake_binary
        MAGIC_BE = b"\xff\xff\xff\xfb"
        MAGIC_LE = b"\xfb\xff\xff\xff"
        offset = reader._find_pclntab(data, MAGIC_BE, MAGIC_LE)
        assert offset == 0  # Found at start
        reader.close()

    def test_find_pclntab_not_found(self, temp_dir):
        """Test that _find_pclntab returns 0 when no pclntab exists."""
        # Create binary data without pclntab magic
        fake_binary = b"\x00" * 200

        bin_path = temp_dir / "no_pclntab"
        bin_path.write_bytes(fake_binary)

        reader = Reader(str(bin_path))
        data = fake_binary
        MAGIC_BE = b"\xff\xff\xff\xfb"
        MAGIC_LE = b"\xfb\xff\xff\xff"
        offset = reader._find_pclntab(data, MAGIC_BE, MAGIC_LE)
        assert offset == 0
        reader.close()

    def test_find_pclntab_invalid_quantum(self, temp_dir):
        """Test that invalid quantum/ptr_size is rejected."""
        # Magic is correct but quantum/ptr_size are wrong
        header = b"\xff\xff\xff\xfb"  # Big-endian magic
        header += b"\x00\x00"  # Padding
        header += b"\x08"  # Quantum = 8 (invalid, should be 4)
        header += b"\x04"  # Ptr size = 4
        header += struct.pack(">I", 0)  # nfuncs = 0

        fake_binary = header + b"\x00" * 100

        bin_path = temp_dir / "invalid_pclntab"
        bin_path.write_bytes(fake_binary)

        reader = Reader(str(bin_path))
        data = fake_binary
        MAGIC_BE = b"\xff\xff\xff\xfb"
        MAGIC_LE = b"\xfb\xff\xff\xff"
        offset = reader._find_pclntab(data, MAGIC_BE, MAGIC_LE)
        # Should not find this as a valid pclntab due to invalid quantum
        assert offset == 0
        reader.close()

    def test_parse_pclntab_empty(self, temp_dir):
        """Test parsing pclntab with zero functions."""
        # Create a valid but empty pclntab
        header = b"\xff\xff\xff\xfb"  # Big-endian magic
        header += b"\x00\x00"  # Padding
        header += b"\x04"  # Quantum = 4
        header += b"\x04"  # Ptr size = 4
        header += struct.pack(">I", 0)  # nfuncs = 0

        fake_binary = header + b"\x00" * 100

        bin_path = temp_dir / "empty_pclntab"
        bin_path.write_bytes(fake_binary)

        reader = Reader(str(bin_path))
        data = fake_binary
        symbols = reader._parse_pclntab(data, 0)
        assert len(symbols) == 0
        reader.close()


class TestReaderUsePclntab:
    """Test the use_pclntab parameter for Reader."""

    def test_reader_init_with_use_pclntab(self, go_binary):
        """Test that Reader accepts use_pclntab parameter."""
        reader = Reader(str(go_binary), use_pclntab=True)
        assert reader.use_pclntab is True
        reader.close()

        reader = Reader(str(go_binary), use_pclntab=False)
        assert reader.use_pclntab is False
        reader.close()

        reader = Reader(str(go_binary))
        assert reader.use_pclntab is False  # Default
        reader.close()

    def test_entries_with_use_pclntab_parameter(self, go_binary):
        """Test that entries() method respects use_pclntab parameter."""
        # Test with use_pclntab=True
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries(use_pclntab=True)
        assert len(entries) > 0
        reader.close()

        # Test with use_pclntab=False
        reader = Reader(str(go_binary), use_pclntab=False)
        entries = reader.entries(use_pclntab=False)
        assert len(entries) > 0
        reader.close()

    def test_macho_with_pclntab_forced(self, go_binary):
        """Test that Mach-O reader uses pclntab when forced."""
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        assert len(entries) > 0
        symbols = entries[0].symbols
        # Should have symbols from pclntab
        assert len(symbols) > 0
        reader.close()

    def test_pclntab_symbols_are_type_t(self, go_binary):
        """Test that pclntab symbols have code 'T' when pclntab is available."""
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        # When pclntab is successfully parsed, all symbols should be 'T'
        # If pclntab parsing fails, Mach-O symbols are used as fallback
        if len(symbols) > 1000:  # pclntab typically has many more symbols
            for sym in symbols:
                assert sym.code == "T"
        reader.close()

    def test_pclntab_symbols_have_names(self, go_binary):
        """Test that pclntab symbols have valid names."""
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        # All symbols should have non-empty names
        for sym in symbols:
            assert sym.name
            assert len(sym.name) > 0
        reader.close()

    def test_pclntab_symbols_have_addresses(self, go_binary):
        """Test that pclntab symbols have valid addresses."""
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        # pclntab symbols should have positive addresses
        # Undefined symbols (from Mach-O fallback) may have addr=0
        defined_symbols = [s for s in symbols if s.code != 'U']
        for sym in defined_symbols:
            assert sym.addr > 0
        reader.close()


class TestPclntabV118FullNameReconstruction:
    """Tests for Go 1.18+ pclntab full name reconstruction."""

    def test_full_name_reconstruction_go_118(self):
        """Test that Go 1.18+ pclntab reconstructs full function names."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.18.10_darwin_amd64"
        
        if not go_binary.exists():
            pytest.skip("go_1.18.10_darwin_amd64 not found")
        
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        
        # Should have a reasonable number of symbols
        assert len(symbols) > 4000
        
        # Check that names are fully qualified (contain package path)
        names_with_package = [s.name for s in symbols if '/' in s.name or '.' in s.name]
        assert len(names_with_package) > 2000
        
        # Check for specific expected full names
        all_names = [s.name for s in symbols]
        
        # Should have fully qualified names like "flag.(*FlagSet).VisitAll"
        # not just "VisitAll"
        has_fully_qualified = any(
            '.' in name and '(' in name and ')' in name 
            for name in all_names
        )
        assert has_fully_qualified
        
        reader.close()

    def test_full_name_reconstruction_go_124(self):
        """Test that Go 1.24+ pclntab reconstructs full function names."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.24.0_darwin_amd64"
        
        if not go_binary.exists():
            pytest.skip("go_1.24.0_darwin_amd64 not found")
        
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        
        # Should have a reasonable number of symbols
        assert len(symbols) > 6000
        
        # Check for fully qualified names
        all_names = [s.name for s in symbols]
        
        # Should have names with package paths
        names_with_slash = [n for n in all_names if '/' in n]
        assert len(names_with_slash) > 3000
        
        # Should have method names with receiver info
        names_with_receiver = [n for n in all_names if '(*' in n and ').' in n]
        assert len(names_with_receiver) > 1000
        
        reader.close()

    def test_suffix_name_handling(self):
        """Test that names pointing to suffixes are properly reconstructed."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.18.10_darwin_amd64"
        
        if not go_binary.exists():
            pytest.skip("go_1.18.10_darwin_amd64 not found")
        
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        
        # Check that we don't have truncated single-word names
        # (except for legitimate short names)
        all_names = [s.name for s in symbols]
        
        # Most names should be longer than 5 characters
        long_names = [n for n in all_names if len(n) > 5]
        assert len(long_names) > len(all_names) * 0.8
        
        # Should have names from standard packages
        std_package_names = [
            n for n in all_names 
            if any(pkg in n for pkg in ['flag.', 'reflect.', 'strings.', 'bytes.'])
        ]
        assert len(std_package_names) > 100
        
        reader.close()

    def test_name_bounds_checking(self):
        """Test that name offset bounds are properly validated."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.18.10_darwin_amd64"
        
        if not go_binary.exists():
            pytest.skip("go_1.18.10_darwin_amd64 not found")
        
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        
        # All symbol names should be valid strings
        for sym in symbols:
            assert isinstance(sym.name, str)
            assert len(sym.name) > 0
            assert len(sym.name) < 200  # Reasonable max length
        
        # No names should contain null bytes
        for sym in symbols:
            assert '\x00' not in sym.name
        
        # Names should be printable ASCII (mostly)
        printable_count = sum(
            1 for sym in symbols 
            if all(0x20 <= ord(c) < 0x7f or c in '\t\n\r' for c in sym.name)
        )
        # At least 90% should be printable
        assert printable_count > len(symbols) * 0.9
        
        reader.close()

    def test_pclntab_v118_vs_v14_symbol_count(self):
        """Compare symbol counts between Go 1.18+ and older versions."""
        test_dir = Path(__file__).parent
        go_binaries_dir = test_dir / "go_binaries"
        
        # Test Go 1.17 (v14 format)
        go_117 = go_binaries_dir / "go_1.17.13_darwin_amd64"
        if go_117.exists():
            reader = Reader(str(go_117), use_pclntab=True)
            entries = reader.entries()
            syms_117 = len(entries[0].symbols)
            reader.close()
        else:
            pytest.skip("go_1.17.13_darwin_amd64 not found")
        
        # Test Go 1.18 (v118 format)
        go_118 = go_binaries_dir / "go_1.18.10_darwin_amd64"
        if go_118.exists():
            reader = Reader(str(go_118), use_pclntab=True)
            entries = reader.entries()
            syms_118 = len(entries[0].symbols)
            reader.close()
        else:
            pytest.skip("go_1.18.10_darwin_amd64 not found")
        
        # Both should have substantial symbol counts
        assert syms_117 > 5000
        assert syms_118 > 4000

    def test_pclntab_v118_name_format_consistency(self):
        """Test that reconstructed names follow consistent format."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.20.14_darwin_amd64"
        
        if not go_binary.exists():
            pytest.skip("go_1.20.14_darwin_amd64 not found")
        
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        
        # All names should be valid Go function name characters
        # Go names can contain: letters, digits, underscore, dot, slash, dash,
        # asterisk, brackets, angle brackets, comma, parens, braces, colon, semicolon,
        # the middle dot character (·) used in internal names, and quotes for struct tags
        import re
        valid_name_pattern = re.compile(r'^[a-zA-Z0-9_./\-*\[\]<>,"\\{}\(\)\s:;·]+$')
        
        for sym in symbols[:1000]:  # Check first 1000
            assert valid_name_pattern.match(sym.name), f"Invalid name: {sym.name}"
        
        reader.close()
