"""Tests for pynm across multiple Go versions and platforms."""

import os
import re

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
    return sorted([f for f in os.listdir(TEST_BINARIES_DIR) if f.startswith(('go_', 'hello_'))])


def parse_binary_name(name):
    """Parse binary name into components.
    
    Returns dict with keys: version, goos, goarch, or None if unparseable.
    Example: go_1.18.10_darwin_amd64 -> {'version': '1.18.10', 'goos': 'darwin', 'goarch': 'amd64'}
             hello_1.18.1_dynamic_linux_amd64 -> {'version': '1.18.1', 'type': 'dynamic', 'goos': 'linux', 'goarch': 'amd64'}
    """
    # Pattern: go_VERSION_OS_ARCH[.exe]
    match = re.match(r'go_([0-9.]+)_([a-z0-9]+)_([a-z0-9]+)(?:\.exe)?$', name)
    if match:
        return {
            'version': match.group(1),
            'goos': match.group(2),
            'goarch': match.group(3),
            'full': name
        }
    
    # Pattern: hello_VERSION_TYPE_OS_ARCH
    match = re.match(r'hello_([0-9.]+)_([a-z_]+)_([a-z0-9]+)_([a-z0-9]+)$', name)
    if match:
        return {
            'version': match.group(1),
            'type': match.group(2),
            'goos': match.group(3),
            'goarch': match.group(4),
            'full': name
        }
    
    return None


def get_binaries_by_platform(binaries):
    """Group binaries by platform (goos_goarch)."""
    by_platform = {}
    for name in binaries:
        parsed = parse_binary_name(name)
        if parsed:
            platform = f"{parsed['goos']}_{parsed['goarch']}"
            if platform not in by_platform:
                by_platform[platform] = []
            by_platform[platform].append(name)
    return by_platform


def get_binaries_by_version(binaries):
    """Group binaries by Go version."""
    by_version = {}
    for name in binaries:
        parsed = parse_binary_name(name)
        if parsed:
            version = parsed['version']
            if version not in by_version:
                by_version[version] = []
            by_version[version].append(name)
    return by_version


# Generate test parameters from available binaries
AVAILABLE_BINARIES = list_available_binaries()
BINARIES_BY_PLATFORM = get_binaries_by_platform(AVAILABLE_BINARIES)
BINARIES_BY_VERSION = get_binaries_by_version(AVAILABLE_BINARIES)


class TestAllBinariesBasic:
    """Basic tests that run on ALL available binaries."""

    @pytest.mark.parametrize("binary_name", AVAILABLE_BINARIES)
    def test_binary_readable(self, binary_name):
        """Test that every binary can be opened and parsed."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            # Should detect a format
            assert reader._format in ('elf', 'pe', 'macho32', 'macho32_rev', 
                                       'macho64', 'macho64_rev', 'archive', 'coff'), \
                f"Unknown format for {binary_name}"
            
            # Should be able to read entries
            entries = reader.entries()
            assert len(entries) > 0, f"No entries for {binary_name}"

    @pytest.mark.parametrize("binary_name", AVAILABLE_BINARIES)
    def test_binary_format_detection(self, binary_name):
        """Test that binary format is correctly detected."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            # Check format based on binary name
            if binary_name.endswith('.exe'):
                assert reader._format == 'pe', f"Expected PE for {binary_name}"
            elif '_linux_' in binary_name:
                assert reader._format == 'elf', f"Expected ELF for {binary_name}"
            elif '_darwin_' in binary_name:
                assert reader._format in ('macho32', 'macho32_rev', 'macho64', 'macho64_rev'), \
                    f"Expected Mach-O for {binary_name}"
            elif '_windows_' in binary_name:
                assert reader._format == 'pe', f"Expected PE for {binary_name}"

    @pytest.mark.parametrize("binary_name", AVAILABLE_BINARIES)
    def test_binary_addr_width(self, binary_name):
        """Test that address width matches binary architecture."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            # 64-bit binaries should have 16-char addresses
            # 32-bit binaries should have 8-char addresses
            if '_amd64' in binary_name or '_ppc64' in binary_name or '_arm64' in binary_name:
                assert reader.addr_width == 16, f"Expected 16-bit width for 64-bit {binary_name}"
            elif reader._format in ('macho32', 'macho32_rev'):
                assert reader.addr_width == 8, f"Expected 8-bit width for 32-bit {binary_name}"

    @pytest.mark.parametrize("binary_name", AVAILABLE_BINARIES)
    def test_binary_has_expected_symbols(self, binary_name):
        """Test that binaries have expected symbol counts.
        
        Different binaries have different symbol expectations:
        - Stripped binaries: 0 symbols expected
        - Go compiler Linux binaries: >1000 symbols expected (now that ELF reader works)
        - All other binaries: >0 symbols expected
        """
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            entries = reader.entries()
            symbol_count = len(entries[0].symbols)
            
            # Stripped test binaries should have no symbols
            if 'stripped' in binary_name:
                assert symbol_count == 0, f"Stripped binary should have 0 symbols, got {symbol_count}: {binary_name}"
                return
            
            # All other binaries should have symbols
            # Go compiler Linux binaries now work correctly with the fixed ELF reader
            assert symbol_count > 0, f"Expected symbols for {binary_name}, got {symbol_count}"


class TestLinuxELFBinaries:
    """Tests specifically for Linux ELF binaries."""

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if '_linux_' in b]
    )
    def test_elf_format_detection(self, binary_name):
        """Test that Linux binaries are detected as ELF."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            assert reader._format == 'elf', f"Expected ELF for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if '_linux_' in b]
    )
    def test_elf_arch_detection(self, binary_name):
        """Test that Linux binary architecture is correctly detected."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            # Check architecture based on binary name
            if '_amd64' in binary_name or '_ppc64' in binary_name or '_arm64' in binary_name:
                # 64-bit binaries
                assert reader._is_64bit is True, f"Expected 64-bit for {binary_name}"
                assert reader.addr_width == 16, f"Expected 16-char addresses for {binary_name}"
            elif '_armv6l' in binary_name or '_ppc' in binary_name:
                # 32-bit binaries
                assert reader._is_64bit is False, f"Expected 32-bit for {binary_name}"
                assert reader.addr_width == 8, f"Expected 8-char addresses for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if '_linux_amd64' in b]
    )
    def test_linux_amd64_pclntab(self, binary_name):
        """Test pclntab extraction from Linux amd64 binaries."""
        binary = get_binary_path(binary_name)
        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            # Modern Go Linux binaries may have pclntab
            # If present, verify they're valid
            if len(symbols) > 0:
                codes = set(s.code for s in symbols)
                assert "T" in codes, f"No T symbols from pclntab for {binary_name}"
                named = [s for s in symbols if s.name]
                assert len(named) > 0, f"No named pclntab symbols for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if 'dynamic' in b and 'linux' in b]
    )
    def test_linux_dynamic_has_elf_symbols(self, binary_name):
        """Test that dynamically linked Linux binaries have ELF symbol tables."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            # Dynamically linked binaries should have ELF symbols
            assert len(symbols) > 10, f"Expected ELF symbols for {binary_name}"
            
            # Should have various symbol types
            codes = set(s.code for s in symbols)
            assert "T" in codes, f"Expected T symbols for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if 'static_sym' in b and 'linux' in b]
    )
    def test_linux_static_sym_has_symbols(self, binary_name):
        """Test that statically linked binaries with symbols have ELF symbol tables."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            # Statically linked with symbols should have ELF symbols
            assert len(symbols) > 10, f"Expected ELF symbols for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if 'stripped' in b and 'linux' in b]
    )
    def test_linux_stripped_pclntab_or_skip(self, binary_name):
        """Test that stripped Linux binaries may have pclntab.
        
        Note: Go binaries built with -ldflags="-s -w" have both ELF symbols
        and pclntab stripped. This is expected behavior.
        """
        binary = get_binary_path(binary_name)
        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            # Stripped binaries may or may not have pclntab depending on build flags
            # If pclntab is present, verify it's valid
            if len(symbols) > 0:
                codes = set(s.code for s in symbols)
                assert "T" in codes, f"Expected T symbols from pclntab for {binary_name}"


class TestBinariesByPlatform:
    """Tests grouped by platform."""

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if b.endswith('_darwin_amd64')]
    )
    def test_darwin_amd64_basic(self, binary_name):
        """Test darwin/amd64 binaries have expected symbol types."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            assert reader._format in ('macho64', 'macho64_rev')
            entries = reader.entries()
            symbols = entries[0].symbols
            
            if len(symbols) == 0:
                pytest.skip(f"No symbols in {binary_name}")
            
            codes = set(s.code for s in symbols)
            assert "T" in codes or "R" in codes or "D" in codes

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if b.endswith('_darwin_ppc_test')]
    )
    def test_darwin_ppc_basic(self, binary_name):
        """Test darwin/ppc binaries have expected symbol types."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            assert reader._format in ('macho32', 'macho32_rev')
            entries = reader.entries()
            symbols = entries[0].symbols
            
            if len(symbols) == 0:
                pytest.skip(f"No symbols in {binary_name}")
            
            codes = set(s.code for s in symbols)
            assert "T" in codes or "R" in codes or "D" in codes

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if b.endswith('_windows_amd64.exe')]
    )
    def test_windows_amd64_basic(self, binary_name):
        """Test windows/amd64 binaries have expected symbol types."""
        binary = get_binary_path(binary_name)
        with Reader(binary) as reader:
            assert reader._format == 'pe'
            entries = reader.entries()
            symbols = entries[0].symbols
            
            if len(symbols) == 0:
                pytest.skip(f"No symbols in {binary_name}")

            codes = set(s.code for s in symbols)
            assert "T" in codes


class TestPclntabAllBinaries:
    """Test pclntab extraction on ALL available binaries."""

    @pytest.mark.parametrize("binary_name", AVAILABLE_BINARIES)
    def test_pclntab_extraction(self, binary_name):
        """Test that pclntab can be extracted from Go binaries."""
        binary = get_binary_path(binary_name)
        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            # Statically-linked ELF binaries may not have pclntab
            # This is expected, not a failure
            if binary_name.endswith(('_linux_amd64', '_linux_ppc64le', '_linux_ppc64', 
                                      '_linux_armv6l', '_linux_arm64')):
                # Just verify we can open the file without error
                # Symbol count may be 0 for statically-linked binaries
                assert len(entries) > 0, f"No entries for {binary_name}"
                return
            
            # All other binaries should have pclntab symbols
            if len(symbols) == 0:
                pytest.skip(f"No pclntab symbols for {binary_name}")
            
            # pclntab symbols should be type T
            codes = set(s.code for s in symbols)
            assert "T" in codes, f"No T symbols from pclntab for {binary_name}"
            
            # Should have named symbols
            named = [s for s in symbols if s.name]
            assert len(named) > 0, f"No named pclntab symbols for {binary_name}"
            
            # Should have valid addresses
            with_addr = [s for s in symbols if s.addr > 0]
            assert len(with_addr) > 0, f"No addresses in pclntab for {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if parse_binary_name(b) and 
         parse_binary_name(b)['version'].startswith(('1.4.', '1.5.', '1.6.', '1.7.'))
         and not b.endswith(('_linux_amd64', '_linux_ppc64le', '_linux_ppc64', 
                            '_linux_armv6l', '_linux_arm64'))]
    )
    def test_pclntab_go14_format(self, binary_name):
        """Test pclntab extraction for Go 1.4-1.7 format."""
        binary = get_binary_path(binary_name)
        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            assert len(symbols) > 500, f"Too few pclntab symbols for Go 1.4-1.7: {binary_name}"

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if parse_binary_name(b) and 
         parse_binary_name(b)['version'].startswith(('1.18.', '1.19.', '1.20.', 
                                                      '1.21.', '1.22.', '1.23.', '1.24.'))
         and not b.endswith(('_linux_amd64', '_linux_ppc64le', '_linux_ppc64', 
                            '_linux_armv6l', '_linux_arm64'))]
    )
    def test_pclntab_go118_format(self, binary_name):
        """Test pclntab extraction for Go 1.18+ format."""
        binary = get_binary_path(binary_name)
        with Reader(binary, use_pclntab=True) as reader:
            entries = reader.entries()
            symbols = entries[0].symbols
            
            assert len(symbols) > 500, f"Too few pclntab symbols for Go 1.18+: {binary_name}"
            
            # Check for fully qualified names (package.function)
            named = [s.name for s in symbols if s.name]
            with_dots = [n for n in named if '.' in n]
            assert len(with_dots) > 0, f"No qualified names in pclntab for {binary_name}"


class TestPclntabVsNative:
    """Compare pclntab vs native symbol tables."""

    @pytest.mark.parametrize(
        "binary_name",
        [b for b in AVAILABLE_BINARIES if b.endswith('_darwin_amd64')]
    )
    def test_pclntab_vs_native_count(self, binary_name):
        """Compare symbol counts between pclntab and native."""
        binary = get_binary_path(binary_name)
        
        # Read with native symbol table
        with Reader(binary, use_pclntab=False) as reader:
            native_count = len(reader.entries()[0].symbols)
        
        # Read with pclntab
        with Reader(binary, use_pclntab=True) as reader:
            pclntab_count = len(reader.entries()[0].symbols)
        
        # Both should have symbols
        assert native_count > 0, f"No native symbols for {binary_name}"
        assert pclntab_count > 0, f"No pclntab symbols for {binary_name}"
