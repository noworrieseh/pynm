import pytest
import subprocess
import tempfile
import os
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def go_binary():
    """Use pre-built Go binary from test resources.
    
    Uses go_1.18.10_darwin_amd64 which has a working pclntab format.
    Older Go versions (1.17 and earlier) have a different pclntab format
    that isn't fully supported.
    """
    test_dir = Path(__file__).parent
    go_binaries_dir = test_dir / "go_binaries"
    
    # Prefer Go 1.18+ which has pclntab support
    for version in ['1.24.0', '1.23.4', '1.22.5', '1.21.13', '1.20.14', '1.19.13', '1.18.10']:
        binary = go_binaries_dir / f"go_{version}_darwin_amd64"
        if binary.exists():
            return binary
    
    # Fallback to any darwin_amd64 binary
    for binary in go_binaries_dir.glob("go_*_darwin_amd64"):
        if binary.exists():
            return binary
    
    # Fallback to any go binary
    for binary in go_binaries_dir.glob("go_*"):
        if binary.exists():
            return binary
    
    pytest.skip("No pre-built Go binaries found in tests/go_binaries/")


@pytest.fixture
def c_binary(temp_dir):
    src = temp_dir / "test.c"
    src.write_text("""
int global_var = 42;
static int static_var = 10;

void func() {}
static void static_func() {}

const int const_var = 100;
""")
    bin_path = temp_dir / "test"
    subprocess.run(["gcc", "-c", str(src), "-o", str(bin_path)], check=True)
    return bin_path


@pytest.fixture
def empty_binary(temp_dir):
    bin_path = temp_dir / "empty.o"
    bin_path.write_bytes(b"")
    return bin_path
