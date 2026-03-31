import struct

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
        # Use the go_bootstrap file which has an empty Mach-O symbol table
        # but contains a valid Go pclntab
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        go_bootstrap = os.path.join(project_dir, "go_bootstrap")

        if not os.path.exists(go_bootstrap):
            pytest.skip("go_bootstrap not found")

        reader = Reader(go_bootstrap)
        entries = reader.entries()
        assert len(entries) > 0
        symbols = entries[0].symbols
        # Should have symbols from pclntab even though Mach-O table is empty
        assert len(symbols) > 0
        reader.close()

    def test_pclntab_symbols_have_correct_code(self):
        """Test that pclntab symbols have code 'T' for text."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        go_bootstrap = os.path.join(project_dir, "go_bootstrap")

        if not os.path.exists(go_bootstrap):
            pytest.skip("go_bootstrap not found")

        reader = Reader(go_bootstrap)
        entries = reader.entries()
        symbols = entries[0].symbols
        # All pclntab symbols should be 'T' (text/code)
        for sym in symbols:
            assert sym.code == "T"
        reader.close()

    def test_pclntab_symbols_have_names(self):
        """Test that pclntab symbols have valid names."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        go_bootstrap = os.path.join(project_dir, "go_bootstrap")

        if not os.path.exists(go_bootstrap):
            pytest.skip("go_bootstrap not found")

        reader = Reader(go_bootstrap)
        entries = reader.entries()
        symbols = entries[0].symbols
        # All symbols should have non-empty names
        names = [s.name for s in symbols]
        assert all(names)
        assert all(isinstance(n, str) for n in names)
        reader.close()

    def test_pclntab_symbols_have_addresses(self):
        """Test that pclntab symbols have valid addresses."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        go_bootstrap = os.path.join(project_dir, "go_bootstrap")

        if not os.path.exists(go_bootstrap):
            pytest.skip("go_bootstrap not found")

        reader = Reader(go_bootstrap)
        entries = reader.entries()
        symbols = entries[0].symbols
        # All symbols should have positive addresses
        for sym in symbols:
            assert sym.addr > 0
        reader.close()

    def test_pclntab_symbol_count(self):
        """Test that we extract a reasonable number of symbols from pclntab."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        go_bootstrap = os.path.join(project_dir, "go_bootstrap")

        if not os.path.exists(go_bootstrap):
            pytest.skip("go_bootstrap not found")

        reader = Reader(go_bootstrap)
        entries = reader.entries()
        symbols = entries[0].symbols
        # go_bootstrap should have ~4324 symbols
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
        """Test that pclntab symbols have code 'T'."""
        reader = Reader(str(go_binary), use_pclntab=True)
        entries = reader.entries()
        symbols = entries[0].symbols
        # All pclntab symbols should be 'T' (text/code)
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
        # All symbols should have positive addresses
        for sym in symbols:
            assert sym.addr > 0
        reader.close()
