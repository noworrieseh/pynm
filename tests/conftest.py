import pytest
import subprocess
import tempfile
import os
from pathlib import Path


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def go_binary(temp_dir):
    src = temp_dir / "main.go"
    src.write_text("""
package main

import "fmt"

var AppVersion string = "1.0.0"

func main() {
    fmt.Println("Hello, version:", AppVersion)
}
""")
    bin_path = temp_dir / "test"
    subprocess.run(["go", "build", "-o", str(bin_path), str(src)], check=True)
    return bin_path


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
