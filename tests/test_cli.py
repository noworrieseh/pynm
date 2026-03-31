import sys
from io import StringIO

import pytest

from pynm.cli import HELP_TEXT, parse_args


class TestCLIAddrWidthOutput:
    """Tests for address width formatting in CLI output."""

    def test_32bit_addr_width_format(self, temp_dir):
        """Test that 32-bit binaries produce 8-character hex addresses."""
        from pynm.reader import Reader

        # Create a minimal 32-bit Mach-O binary
        bin_path = temp_dir / "test32"
        bin_path.write_bytes(b"\xce\xfa\xed\xfe\x01\x00\x00\x00" + b"\x00" * 100)

        reader = Reader(str(bin_path))
        assert reader.addr_width == 8

        # Test address formatting
        test_addr = 0x12345678
        formatted = f"{test_addr:0{reader.addr_width}x}"
        assert len(formatted) == 8
        assert formatted == "12345678"
        reader.close()

    def test_64bit_addr_width_format(self, go_binary):
        """Test that 64-bit binaries produce 16-character hex addresses."""
        from pynm.reader import Reader

        reader = Reader(str(go_binary))
        assert reader.addr_width == 16

        # Test address formatting
        test_addr = 0x1234567890ABCDEF
        formatted = f"{test_addr:0{reader.addr_width}x}"
        assert len(formatted) == 16
        assert formatted == "1234567890abcdef"
        reader.close()


class TestCLIParsing:
    def test_default_args(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "test.o"]
        try:
            args = parse_args()
            assert args.sort == "name"
            assert args.size is False
            assert args.type is False
            assert args.files == ["test.o"]
        finally:
            sys.argv = old_argv

    def test_sort_address(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-n", "test.o"]
        try:
            args = parse_args()
            assert args.sort == "address"
        finally:
            sys.argv = old_argv

    def test_sort_name(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-sort", "name", "test.o"]
        try:
            args = parse_args()
            assert args.sort == "name"
        finally:
            sys.argv = old_argv

    def test_sort_size(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-sort", "size", "test.o"]
        try:
            args = parse_args()
            assert args.sort == "size"
        finally:
            sys.argv = old_argv

    def test_sort_none(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-sort", "none", "test.o"]
        try:
            args = parse_args()
            assert args.sort == "none"
        finally:
            sys.argv = old_argv

    def test_size_flag(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-size", "test.o"]
        try:
            args = parse_args()
            assert args.size is True
        finally:
            sys.argv = old_argv

    def test_type_flag(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "-type", "test.o"]
        try:
            args = parse_args()
            assert args.type is True
        finally:
            sys.argv = old_argv

    def test_multiple_files(self):
        old_argv = sys.argv
        sys.argv = ["pynm", "a.o", "b.o", "c.o"]
        try:
            args = parse_args()
            assert args.files == ["a.o", "b.o", "c.o"]
        finally:
            sys.argv = old_argv

    def test_no_files_exits(self):
        old_argv = sys.argv
        old_stderr = sys.stderr
        sys.argv = ["pynm"]
        sys.stderr = StringIO()
        try:
            with pytest.raises(SystemExit):
                parse_args()
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr

    def test_invalid_sort_exits(self, capsys):
        old_argv = sys.argv
        sys.argv = ["pynm", "-sort", "invalid", "test.o"]
        try:
            with pytest.raises(SystemExit) as exc:
                parse_args()
            assert exc.value.code == 2
        finally:
            sys.argv = old_argv


class TestHelpText:
    def test_help_text_contains_options(self):
        assert "-n" in HELP_TEXT
        assert "-size" in HELP_TEXT
        assert "-sort" in HELP_TEXT
        assert "-type" in HELP_TEXT
        assert "-pclntab" in HELP_TEXT

    def test_help_text_contains_pclntab(self):
        """Test that help text mentions the -pclntab option."""
        assert "pclntab" in HELP_TEXT.lower()


class TestPclntabCLIParsing:
    """Test parsing of -pclntab CLI option."""

    def test_pclntab_flag(self):
        """Test that -pclntab flag is parsed correctly."""
        old_argv = sys.argv
        sys.argv = ["pynm", "-pclntab", "test.o"]
        try:
            args = parse_args()
            assert args.pclntab is True
        finally:
            sys.argv = old_argv

    def test_pclntab_with_other_options(self):
        """Test that -pclntab works with other options."""
        old_argv = sys.argv
        sys.argv = ["pynm", "-pclntab", "-size", "-n", "test.o"]
        try:
            args = parse_args()
            assert args.pclntab is True
            assert args.size is True
            assert args.sort == "address"
        finally:
            sys.argv = old_argv

    def test_no_pclntab_by_default(self):
        """Test that -pclntab is False by default."""
        old_argv = sys.argv
        sys.argv = ["pynm", "test.o"]
        try:
            args = parse_args()
            assert args.pclntab is False
        finally:
            sys.argv = old_argv
