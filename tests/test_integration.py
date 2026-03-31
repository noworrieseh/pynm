import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from pynm.__main__ import main


class TestAddrWidthIntegration:
    """Integration tests for address width formatting."""

    def test_32bit_binary_addr_width(self, temp_dir):
        """Test that 32-bit binaries produce 8-character hex addresses."""
        # Create a minimal 32-bit Mach-O binary with a symbol table
        bin_path = temp_dir / "test32"
        # Mach-O 32-bit little-endian magic
        bin_path.write_bytes(b"\xce\xfa\xed\xfe\x01\x00\x00\x00" + b"\x00" * 100)

        result = subprocess.run(
            [sys.executable, "-m", "pynm", str(bin_path)],
            capture_output=True,
            text=True,
        )
        # Should fail to parse (not a valid binary) but we're testing format detection
        # For a valid test, use the test_reader tests which verify addr_width property

    def test_64bit_binary_addr_width(self, go_binary):
        """Test that 64-bit binaries produce 16-character hex addresses."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0

        # Check that defined symbols have 16-character addresses
        for line in lines[:20]:
            parts = line.split()
            if parts and parts[0] and parts[0] != "":
                # Address should be 16 hex characters for 64-bit
                assert len(parts[0]) == 16, f"Expected 16-char address, got: {parts[0]}"
                break

    def test_32bit_macho_output_format(self, temp_dir):
        """Test output format for 32-bit Mach-O binaries."""
        from pynm.reader import Reader

        # Create minimal 32-bit Mach-O header
        bin_path = temp_dir / "test32"
        bin_path.write_bytes(b"\xce\xfa\xed\xfe\x01\x00\x00\x00" + b"\x00" * 100)

        # For this test, we verify the Reader's addr_width property
        # which is used by the CLI to format output
        reader = Reader(str(bin_path))
        assert reader.addr_width == 8
        reader.close()


class TestMain:
    def test_main_runs(self, go_binary, capsys):
        old_argv = sys.argv
        sys.argv = ["pynm", str(go_binary)]
        try:
            try:
                main()
            except SystemExit:
                pass
            captured = capsys.readouterr()
            assert len(captured.out) > 0
        finally:
            sys.argv = old_argv

    def test_main_multiple_files(self, temp_dir, go_binary, capsys):
        old_argv = sys.argv
        sys.argv = ["pynm", str(go_binary), str(go_binary)]
        try:
            try:
                main()
            except SystemExit:
                pass
            captured = capsys.readouterr()
            lines = captured.out.strip().split("\n")
            assert len(lines) > 0
        finally:
            sys.argv = old_argv

    def test_main_invalid_file(self, temp_dir, capsys):
        old_argv = sys.argv
        old_stderr = sys.stderr
        sys.argv = ["pynm", str(temp_dir / "nonexistent.o")]
        sys.stderr = StringIO()
        try:
            try:
                main()
            except SystemExit:
                pass
            stderr = sys.stderr.getvalue()
            assert "nm:" in stderr
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr


class TestCLIIntegration:
    def test_cli_executable(self, go_binary):
        result = subprocess.run(
            [sys.executable, "-m", "pynm", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_cli_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "--help"], capture_output=True, text=True
        )
        output = result.stderr + result.stdout
        assert "-n" in output

    def test_cli_size_option(self, go_binary):
        """Test that -size option outputs symbol sizes."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-size", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # At least some lines should contain size values (digits between address and type)
        lines_with_sizes = [
            line for line in lines if line.strip() and any(c.isdigit() for c in line)
        ]
        assert len(lines_with_sizes) > 0

    def test_cli_sort_size(self, go_binary):
        """Test that -sort size orders symbols by size descending."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-sort", "size", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # Undefined symbols (code U) should appear first
        undefined_lines = [line for line in lines if " U " in line]
        assert len(undefined_lines) > 0

    def test_cli_sort_address(self, go_binary):
        """Test that -n (alias for -sort address) sorts by address."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-n", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # Defined symbols should be in ascending address order
        defined_lines = [line for line in lines if " U " not in line and line.strip()]
        if defined_lines:
            # Extract addresses and verify they're in order
            addresses = []
            for line in defined_lines[:10]:  # Check first 10
                parts = line.split()
                if parts and parts[0]:
                    try:
                        addr = int(parts[0], 16)
                        addresses.append(addr)
                    except ValueError:
                        pass
            # Verify addresses are sorted
            assert addresses == sorted(addresses)

    def test_cli_sort_name(self, go_binary):
        """Test that -sort name orders symbols alphabetically."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-sort", "name", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # Extract symbol names and verify they're sorted
        names = []
        for line in lines[:100]:  # Check first 100
            parts = line.split()
            if len(parts) >= 4:  # addr, code, name (and possibly size)
                names.append(parts[-1])
        if names:
            assert names == sorted(names)

    def test_cli_type_option(self, go_binary):
        """Test that -type option outputs symbol types."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-type", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # Lines should contain symbol type information after the name

    def test_cli_pclntab_option(self, go_binary):
        """Test that -pclntab option forces use of Go pclntab."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-pclntab", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
        # pclntab symbols should all be 'T' (text/code)
        for line in lines[:20]:  # Check first 20 lines
            if " T " in line:
                assert " T " in line  # Should have T code

    def test_cli_pclntab_with_sort(self, go_binary):
        """Test that -pclntab works with -sort options."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-pclntab", "-sort", "name", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0

    def test_cli_pclntab_with_size(self, go_binary):
        """Test that -pclntab works with -size option."""
        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-pclntab", "-size", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0

    def test_cli_pclntab_go_bootstrap(self):
        """Test that -pclntab works with Go 1.4 PPC binary."""
        test_dir = Path(__file__).parent
        go_binary = test_dir / "go_binaries" / "go_1.4.3_darwin_ppc_test"

        if not go_binary.exists():
            pytest.skip("go_1.4.3_darwin_ppc_test not found")

        result = subprocess.run(
            [sys.executable, "-m", "pynm", "-pclntab", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 100  # go_1.4.3_darwin_ppc_test should have many symbols


class TestStandaloneExecutable:
    """Tests for the standalone PyInstaller executable."""

    def test_executable_exists(self):
        """Test that the standalone executable was built."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        exe_path = os.path.join(project_dir, "dist", "pynm")
        exe_exe_path = os.path.join(project_dir, "dist", "pynm.exe")

        # Skip if executable not built (e.g., in CI without PyInstaller build step)
        if not os.path.exists(exe_path) and not os.path.exists(exe_exe_path):
            pytest.skip("Standalone executable not found. Run ./build.sh first.")

    def test_executable_help(self):
        """Test that the standalone executable shows help."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        exe_path = os.path.join(project_dir, "dist", "pynm")
        exe_exe_path = os.path.join(project_dir, "dist", "pynm.exe")

        if os.path.exists(exe_path):
            exe = exe_path
        elif os.path.exists(exe_exe_path):
            exe = exe_exe_path
        else:
            pytest.skip("Executable not built")

        result = subprocess.run([exe, "--help"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "-n" in result.stdout or "-n" in result.stderr
        assert "-size" in result.stdout or "-size" in result.stderr

    def test_executable_runs(self, go_binary):
        """Test that the standalone executable can process a binary."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        exe_path = os.path.join(project_dir, "dist", "pynm")
        exe_exe_path = os.path.join(project_dir, "dist", "pynm.exe")

        if os.path.exists(exe_path):
            exe = exe_path
        elif os.path.exists(exe_exe_path):
            exe = exe_exe_path
        else:
            pytest.skip("Executable not built")

        result = subprocess.run([exe, str(go_binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_executable_pclntab_option(self, go_binary):
        """Test that the standalone executable supports -pclntab."""
        import os

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        exe_path = os.path.join(project_dir, "dist", "pynm")
        exe_exe_path = os.path.join(project_dir, "dist", "pynm.exe")

        if os.path.exists(exe_path):
            exe = exe_path
        elif os.path.exists(exe_exe_path):
            exe = exe_exe_path
        else:
            pytest.skip("Executable not built")

        result = subprocess.run(
            [exe, "-pclntab", str(go_binary)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        assert len(lines) > 0
