"""Binary file reader supporting multiple formats (ELF, Mach-O, PE, COFF, Archive)."""

import os
import struct

from .symbols import Entry, Symbol


class Reader:
    """Reads symbol tables from binary files in various formats."""

    def __init__(self, path: str, use_pclntab: bool = False):
        """Initialize a Reader for the given file path.

        Args:
            path: Path to the binary file to read.
            use_pclntab: If True, force use of Go pclntab instead of native symbol table.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        self.path = path
        self.use_pclntab = use_pclntab
        self._file = open(path, "rb")
        self._entries = None
        self._format = self._detect_format()
        self._is_64bit = self._detect_is_64bit()

    def _detect_is_64bit(self) -> bool:
        """Detect if the binary is 64-bit.

        Returns:
            True if 64-bit, False if 32-bit, None if unknown.
        """
        if self._format in ("macho64", "macho64_rev"):
            return True
        elif self._format in ("macho32", "macho32_rev"):
            return False
        elif self._format == "elf":
            self._file.seek(0)
            magic = self._file.read(5)
            if len(magic) >= 5:
                return magic[4] == 2  # EI_CLASS = ELFCLASS64
            return False
        elif self._format == "pe":
            return True  # PE+ is 64-bit, but we'll assume 64 for PE
        return False

    @property
    def addr_width(self) -> int:
        """Return the address display width in hex characters.

        Returns:
            16 for 64-bit binaries, 8 for 32-bit binaries.
        """
        return 16 if self._is_64bit else 8

    def _detect_format(self) -> str:
        """Detect the binary file format based on magic bytes.

        Returns:
            A string identifying the format: 'elf', 'macho32', 'macho64', 'pe', 'coff',
            'archive', or 'unknown'.
        """
        self._file.seek(0)
        magic = self._file.read(16)

        if magic[:4] == b"\x7fELF":
            return "elf"
        elif magic[:2] == b"MZ":
            return "pe"
        elif magic[:4] == b"!<ar":
            return "archive"
        elif magic[:4] == b"\xfe\xed\xfa\xce":
            return "macho32_rev"
        elif magic[:4] == b"\xce\xfa\xed\xfe":
            return "macho32"
        elif magic[:4] == b"\xfe\xed\xfa\xcf":
            return "macho64_rev"
        elif magic[:4] == b"\xcf\xfa\xed\xfe":
            return "macho64"

        if len(magic) >= 2:
            machine = struct.unpack("<H", magic[:2])[0]
            coff_machines = {0x014C, 0x8664, 0x01C0, 0x0200, 0x01C4, 0xAA64, 0x01C2}
            if machine in coff_machines:
                return "coff"

        self._file.seek(0)
        return "unknown"

    def entries(self, use_pclntab: bool = None) -> list[Entry]:
        """Read and parse symbol entries from the binary file.

        Args:
            use_pclntab: If True, force use of Go pclntab. If None, uses instance default.

        Returns:
            A list of Entry objects, each containing symbols from the file.

        Raises:
            ValueError: If the file format is unknown or the file is corrupted.
        """
        if self._entries is not None and use_pclntab is None:
            return self._entries

        self._entries = []

        # Use provided value or instance default
        force_pclntab = use_pclntab if use_pclntab is not None else self.use_pclntab

        if self._format == "archive":
            self._entries = self._read_archive()
        elif self._format == "elf":
            self._entries = self._read_elf()
        elif self._format in ("macho32", "macho32_rev", "macho64", "macho64_rev"):
            self._entries = self._read_macho()
        elif self._format == "pe":
            self._entries = self._read_pe()
        elif self._format == "coff":
            self._entries = self._read_coff()
        else:
            raise ValueError(f"unknown file format: {self.path}")

        return self._entries

    def _extract_string(
        self, data: bytes, str_table_offset: int, str_index: int
    ) -> str:
        """Extract a null-terminated string from a string table.

        Args:
            data: The complete binary data.
            str_table_offset: Offset to the start of the string table.
            str_index: Index/offset within the string table.

        Returns:
            The extracted string, or empty string if not found.
        """
        if str_index <= 0 or str_table_offset <= 0:
            return ""

        name_offset = str_table_offset + str_index
        if name_offset >= len(data):
            return ""

        end = data.find(b"\x00", name_offset)
        if end > name_offset:
            return data[name_offset:end].decode("utf-8", errors="replace")

        return ""

    def _read_archive(self) -> list[Entry]:
        """Read symbols from an archive file (.a format).

        Returns:
            A list of Entry objects, one per archive member that contains symbols.

        Raises:
            ValueError: If the archive header is invalid.
        """
        entries = []
        self._file.seek(0)
        data = self._file.read()

        if len(data) < 8:
            raise ValueError("file too small for archive")

        magic = data[:8]
        if magic != b"!<ar\n":
            raise ValueError("invalid archive header")

        offset = 8
        while offset < len(data):
            # Read archive member header (16 bytes)
            if offset + 16 > len(data):
                break

            member_header = data[offset : offset + 16]
            if member_header[:2] != b"`\n":
                break

            try:
                # Parse member size from header (bytes 3-12, right-padded with spaces)
                size_str = member_header[3:12].decode().rstrip()
                member_size = int(size_str)
            except (ValueError, UnicodeDecodeError):
                break

            # Extract member name (bytes 0-15, right-padded with spaces and /)
            try:
                member_name = member_header[:16].decode().rstrip().rstrip("/").rstrip()
            except UnicodeDecodeError:
                member_name = ""

            # Move to member data
            offset += 16
            member_data = data[offset : offset + member_size]
            offset += member_size

            # Align to 2-byte boundary
            if member_size % 2 == 1:
                offset += 1

            # Try to parse the member as a binary format
            if member_data:
                try:
                    # Detect format of member
                    member_format = self._detect_member_format(member_data)

                    if member_format == "elf":
                        syms = self._read_elf_symbols(member_data, False, True)
                    elif member_format in (
                        "macho32",
                        "macho32_rev",
                        "macho64",
                        "macho64_rev",
                    ):
                        is_64 = member_format in ("macho64", "macho64_rev")
                        is_le = member_format in ("macho32", "macho64")
                        syms = self._read_macho_symbols(member_data, is_64, is_le)
                    elif member_format == "coff":
                        syms = self._read_coff_symbols_from_data(member_data)
                    else:
                        syms = []

                    if syms:
                        entries.append(Entry(name=member_name, symbols=syms))
                except Exception:
                    # If parsing fails, just skip this member
                    pass

        return entries

    def _detect_member_format(self, data: bytes) -> str:
        """Detect the format of an archive member.

        Args:
            data: The member data.

        Returns:
            A format string or empty string if unknown.
        """
        if len(data) < 4:
            return ""

        if data[:4] == b"\x7fELF":
            return "elf"
        elif data[:4] == b"\xfe\xed\xfa\xce":
            return "macho32_rev"
        elif data[:4] == b"\xce\xfa\xed\xfe":
            return "macho32"
        elif data[:4] == b"\xfe\xed\xfa\xcf":
            return "macho64_rev"
        elif data[:4] == b"\xcf\xfa\xed\xfe":
            return "macho64"
        elif len(data) >= 2:
            machine = struct.unpack("<H", data[:2])[0]
            coff_machines = {0x014C, 0x8664, 0x01C0, 0x0200, 0x01C4, 0xAA64, 0x01C2}
            if machine in coff_machines:
                return "coff"

        return ""

    def _read_elf(self) -> list[Entry]:
        """Read symbols from an ELF binary file.

        Returns:
            A list containing one Entry with ELF symbols.

        Raises:
            ValueError: If the file is not a valid ELF file.
        """
        entries = []
        self._file.seek(0)
        data = self._file.read()

        if len(data) < 64:
            raise ValueError("file too small for ELF")

        ei_class = data[4]
        if ei_class == 1:
            is_64 = False
        elif ei_class == 2:
            is_64 = True
        else:
            raise ValueError("invalid ELF class")

        endian = data[5]
        if endian == 1:
            is_le = True
        elif endian == 2:
            is_le = False
        else:
            raise ValueError("invalid ELF endianness")

        syms = self._read_elf_symbols(data, is_64, is_le)
        entries.append(Entry(name="", symbols=syms))

        return entries

    def _read_elf_symbols(self, data: bytes, is_64: bool, is_le: bool) -> list[Symbol]:
        """Extract symbols from ELF binary data.

        Args:
            data: The ELF file data.
            is_64: True if this is a 64-bit ELF file.
            is_le: True if the file uses little-endian byte order.

        Returns:
            A list of Symbol objects extracted from the ELF file.
        """
        syms = []

        if is_64:
            if is_le:
                fmt = "<HHIQQ"
                sym_size = 24
            else:
                fmt = ">HHIQQ"
                sym_size = 24
        else:
            if is_le:
                fmt = "<IIIBBH"
                sym_size = 16
            else:
                fmt = ">IIIBBH"
                sym_size = 16

        # ELF header offsets differ between 32-bit and 64-bit
        # 32-bit ELF: e_shoff at 32, e_shentsize at 46, e_shnum at 48
        # 64-bit ELF: e_shoff at 24, e_shentsize at 46, e_shnum at 48
        if is_64:
            e_shoff = self._unpack(data[24:32], "Q", is_le)
            e_shentsize = self._unpack(data[46:48], "H", is_le)
            e_shnum = self._unpack(data[48:50], "H", is_le)
        else:
            e_shoff = self._unpack(data[32:36], "I", is_le)
            e_shentsize = self._unpack(data[46:48], "H", is_le)
            e_shnum = self._unpack(data[48:50], "H", is_le)

        if e_shoff == 0 or e_shnum == 0:
            return syms

        str_section = None
        for i in range(e_shnum):
            offset = e_shoff + i * e_shentsize
            if offset + (64 if is_64 else 40) > len(data):
                continue

            sh_type = self._unpack(data[offset + 4 : offset + 8], "I", is_le)
            if sh_type == 2:
                str_section = offset
                break

        symtab_offset = 0
        symtab_size = 0
        symtab_entsize = 0
        symtab_str_offset = 0

        for i in range(e_shnum):
            offset = e_shoff + i * e_shentsize
            if offset + e_shentsize > len(data):
                continue

            sh_type = self._unpack(data[offset + 4 : offset + 8], "I", is_le)
            # 32-bit: sh_link at 24, 64-bit: sh_link at 40
            sh_link_offset = 24 if is_64 else 24
            sh_link = self._unpack(
                data[offset + sh_link_offset : offset + sh_link_offset + 4], "I", is_le
            )

            if sh_type == 2:
                # 32-bit: sh_offset at 16, sh_size at 20
                # 64-bit: sh_offset at 24, sh_size at 32
                if is_64:
                    symtab_offset = self._unpack(
                        data[offset + 24 : offset + 32], "Q", is_le
                    )
                    symtab_size = self._unpack(
                        data[offset + 32 : offset + 40], "Q", is_le
                    )
                    symtab_entsize = self._unpack(
                        data[offset + 56 : offset + 58], "H", is_le
                    )

                    if sh_link < e_shnum:
                        str_offset = e_shoff + sh_link * e_shentsize
                        if str_offset + 64 <= len(data):
                            symtab_str_offset = self._unpack(
                                data[str_offset + 24 : str_offset + 32], "Q", is_le
                            )
                else:
                    symtab_offset = self._unpack(
                        data[offset + 16 : offset + 20], "I", is_le
                    )
                    symtab_size = self._unpack(
                        data[offset + 20 : offset + 24], "I", is_le
                    )
                    symtab_entsize = self._unpack(
                        data[offset + 36 : offset + 38], "H", is_le
                    )

                    if sh_link < e_shnum:
                        str_offset = e_shoff + sh_link * e_shentsize
                        if str_offset + 40 <= len(data):
                            symtab_str_offset = self._unpack(
                                data[str_offset + 16 : str_offset + 20], "I", is_le
                            )
                break

        if symtab_offset == 0:
            return syms

        num_syms = symtab_size // symtab_entsize if symtab_entsize else 0

        for i in range(num_syms):
            offset = symtab_offset + i * symtab_entsize
            if offset + symtab_entsize > len(data):
                continue

            if is_64:
                st_name = self._unpack(data[offset : offset + 4], "I", is_le)
                st_info = data[offset + 4]
                st_shndx = self._unpack(data[offset + 6 : offset + 8], "H", is_le)
                st_value = self._unpack(data[offset + 8 : offset + 16], "Q", is_le)
                st_size = self._unpack(data[offset + 16 : offset + 24], "Q", is_le)
            else:
                st_name = self._unpack(data[offset : offset + 4], "I", is_le)
                st_value = self._unpack(data[offset + 4 : offset + 8], "I", is_le)
                st_size = self._unpack(data[offset + 8 : offset + 12], "I", is_le)
                st_info = data[offset + 12]
                st_shndx = self._unpack(data[offset + 14 : offset + 16], "H", is_le)

            if st_shndx == 0:
                code = "U"
            elif st_shndx == 0xFFF1:
                code = "A"
            else:
                if st_info & 0xF == 0:
                    code = "t"
                elif st_info & 0xF == 1:
                    code = "T"
                elif st_info & 0xF == 2:
                    code = "r"
                elif st_info & 0xF == 3:
                    code = "R"
                elif st_info & 0xF == 4:
                    code = "b"
                elif st_info & 0xF == 5:
                    code = "B"
                elif st_info & 0xF == 8:
                    code = "C"
                elif st_info & 0xF == 10:
                    code = "v"
                elif st_info & 0xF == 11:
                    code = "V"
                else:
                    code = "?"

            name = self._extract_string(data, symtab_str_offset, st_name)

            syms.append(
                Symbol(
                    name=name,
                    addr=st_value,
                    size=st_size,
                    code=code,
                )
            )

        return syms

    def _unpack(self, data: bytes, fmt: str, le: bool) -> int:
        """Unpack a binary value with the specified endianness.

        Args:
            data: The bytes to unpack.
            fmt: The struct format character (e.g., 'I', 'Q', 'H').
            le: True for little-endian, False for big-endian.

        Returns:
            The unpacked integer value.
        """
        if le:
            return struct.unpack("<" + fmt, data)[0]
        else:
            return struct.unpack(">" + fmt, data)[0]

    def _read_macho(self) -> list[Entry]:
        """Read symbols from a Mach-O binary file.

        Returns:
            A list containing one Entry with Mach-O symbols.
        """
        entries = []
        self._file.seek(0)
        data = self._file.read()

        is_64 = self._format in ("macho64", "macho64_rev")
        is_le = self._format in ("macho32", "macho64")

        syms = self._read_macho_symbols(data, is_64, is_le)

        # If pclntab is forced, always use it for Go binaries
        # Otherwise, use as fallback when Mach-O symbol table is empty
        if self.use_pclntab or not syms:
            pclntab_syms = self._read_go_pclntab(data)
            if pclntab_syms:
                syms = pclntab_syms

        entries.append(Entry(name="", symbols=syms))

        return entries

    def _build_macho_section_map(
        self, data: bytes, is_64: bool, is_le: bool, hdr_size: int
    ) -> dict[int, tuple[str, str]]:
        """Build a map of section numbers to (segment_name, section_name) tuples.

        Args:
            data: The Mach-O file data.
            is_64: True if this is a 64-bit Mach-O file.
            is_le: True if the file uses little-endian byte order.
            hdr_size: Size of the Mach-O header.

        Returns:
            Dictionary mapping section number (1-based) to (segment, section) names.
        """
        section_map = {}
        fmt4 = "<I" if is_le else ">I"
        ncmds = struct.unpack(fmt4, data[16:20])[0]

        offset = hdr_size
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break

            cmd = struct.unpack(fmt4, data[offset : offset + 4])[0]
            cmdsize = struct.unpack(fmt4, data[offset + 4 : offset + 8])[0]

            # LC_SEGMENT_64 = 0x19, LC_SEGMENT = 0x01
            if cmd in (0x19, 0x01):
                seg_name = (
                    data[offset + 8 : offset + 24]
                    .rstrip(b"\x00")
                    .decode("utf-8", errors="replace")
                )
                # For LC_SEGMENT_64: nsects is at offset 64, sections start at 72
                # For LC_SEGMENT: nsects is at offset 32, sections start at 48
                if cmd == 0x19:  # LC_SEGMENT_64
                    num_sects = struct.unpack(fmt4, data[offset + 64 : offset + 68])[0]
                    sect_offset = offset + 72
                    sect_size = 80
                else:  # LC_SEGMENT
                    num_sects = struct.unpack(fmt4, data[offset + 48 : offset + 52])[0]
                    sect_offset = offset + 56
                    sect_size = 68

                for s in range(num_sects):
                    if sect_offset + sect_size > len(data):
                        break

                    sect_name = (
                        data[sect_offset : sect_offset + 16]
                        .rstrip(b"\x00")
                        .decode("utf-8", errors="replace")
                    )
                    section_num = len(section_map) + 1
                    section_map[section_num] = (seg_name, sect_name)
                    sect_offset += sect_size

            offset += cmdsize

        return section_map

    def _get_macho_symbol_code(
        self, section_map: dict[int, tuple[str, str]], n_sect: int, n_type: int
    ) -> str:
        """Determine the nm symbol code for a Mach-O symbol.

        Args:
            section_map: Map of section numbers to (segment, section) names.
            n_sect: The symbol's section number.
            n_type: The symbol's type byte.

        Returns:
            A single character representing the symbol type.
        """
        if n_sect == 0:
            return "U"  # Undefined

        if n_sect not in section_map:
            return "?"  # Unknown section

        seg_name, sect_name = section_map[n_sect]

        # For defined symbols (those in a section), Go nm always uses uppercase
        # Map based on segment and section names
        if seg_name == "__TEXT":
            # Code sections
            if sect_name in ("__text", "__stubs", "__stub_helper"):
                return "T"
            # Read-only data sections
            elif sect_name in (
                "__cstring",
                "__const",
                "__rodata",
                "__objc_classlist",
                "__objc_methlist",
            ):
                return "R"
            # Other text sections default to text
            else:
                return "T"

        elif seg_name == "__DATA":
            # BSS sections (uninitialized data)
            # Both __bss and __noptrbss are uninitialized
            if sect_name in ("__bss", "__common", "__noptrbss"):
                return "B"
            # Initialized data sections
            elif sect_name in (
                "__data",
                "__go_buildinfo",
                "__go_fipsinfo",
                "__noptrdata",
            ):
                return "D"
            # Read-only data sections (const)
            elif sect_name in ("__const", "__objc_const"):
                return "R"
            # Default to data
            else:
                return "D"

        elif seg_name == "__DATA_CONST":
            # Data constant sections are read-only
            return "R"

        elif seg_name == "__LINKEDIT":
            # Linkedit is typically read-only
            return "R"

        elif seg_name == "__PAGEZERO":
            # Page zero is typically BSS
            return "B"

        elif seg_name == "__DWARF":
            # Debug sections are read-only
            return "R"

        # Default fallback
        return "S"

    def _read_macho_symbols(
        self, data: bytes, is_64: bool, is_le: bool
    ) -> list[Symbol]:
        """Extract symbols from Mach-O binary data.

        Args:
            data: The Mach-O file data.
            is_64: True if this is a 64-bit Mach-O file.
            is_le: True if the file uses little-endian byte order.

        Returns:
            A list of Symbol objects extracted from the Mach-O file.
        """
        syms = []

        if len(data) < 32:
            return syms

        fmt4 = "<I" if is_le else ">I"
        fmt8 = "<II" if is_le else ">II"
        hdr_size = 32 if is_64 else 28

        ncmds = struct.unpack(fmt8, data[16:24])[0]

        symtab_offset = 0
        symtab_count = 0
        stroff = 0

        offset = hdr_size
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break

            cmd = struct.unpack(fmt4, data[offset : offset + 4])[0]
            cmdsize = struct.unpack(fmt4, data[offset + 4 : offset + 8])[0]

            if cmd == 2:  # LC_SYMTAB
                symtab_offset = struct.unpack(fmt4, data[offset + 8 : offset + 12])[0]
                symtab_count = struct.unpack(fmt4, data[offset + 12 : offset + 16])[0]
                stroff = struct.unpack(fmt4, data[offset + 16 : offset + 20])[0]
                break

            offset += cmdsize

        if symtab_offset == 0 or symtab_count == 0:
            return syms

        # Build section map for proper symbol code determination
        section_map = self._build_macho_section_map(data, is_64, is_le, hdr_size)

        sym_size = 16 if is_64 else 12

        # First pass: collect all symbols with their addresses and sections
        parsed_syms = []
        for i in range(symtab_count):
            sym_offset = symtab_offset + i * sym_size
            if sym_offset + sym_size > len(data):
                continue

            if is_64:
                n_strx = struct.unpack(fmt4, data[sym_offset : sym_offset + 4])[0]
                n_type = data[sym_offset + 4]
                n_sect = data[sym_offset + 5]
                n_value = struct.unpack("<Q", data[sym_offset + 8 : sym_offset + 16])[0]
            else:
                n_strx = struct.unpack(fmt4, data[sym_offset : sym_offset + 4])[0]
                n_type = data[sym_offset + 4]
                n_sect = data[sym_offset + 5]
                n_value = struct.unpack(fmt4, data[sym_offset + 8 : sym_offset + 12])[0]

            code = "?"
            n_type_masked = n_type & 0x0E

            if n_type & 0xE0:
                code = "N"
            elif n_type_masked == 0x00:
                code = "U"
            elif n_type_masked == 0x02:
                code = "A" if (n_type & 0x01) else "a"
            elif n_type_masked == 0x0E:
                # N_SECT - defined symbol in a section
                code = self._get_macho_symbol_code(section_map, n_sect, n_type)
            elif n_type_masked == 0x0C:
                code = "U"
            elif n_type_masked == 0x0A:
                code = "I" if (n_type & 0x01) else "i"

            name = self._extract_string(data, stroff, n_strx)

            parsed_syms.append(
                {
                    "name": name,
                    "addr": n_value,
                    "size": 0,
                    "code": code,
                    "n_sect": n_sect,
                }
            )

        # Second pass: calculate sizes by finding distance to next symbol in same section
        # Group symbols by section
        section_syms = {}
        for i, sym in enumerate(parsed_syms):
            sect = sym["n_sect"]
            if sect not in section_syms:
                section_syms[sect] = []
            section_syms[sect].append((sym["addr"], i))

        # Sort each section's symbols by address
        for sect in section_syms:
            section_syms[sect].sort(key=lambda x: x[0])

        # Calculate sizes
        for sect, sorted_syms in section_syms.items():
            for j, (addr, idx) in enumerate(sorted_syms):
                if j < len(sorted_syms) - 1:
                    # Size is distance to next symbol in same section
                    next_addr = sorted_syms[j + 1][0]
                    parsed_syms[idx]["size"] = next_addr - addr
                else:
                    # Last symbol in section: size is 0 (unknown)
                    parsed_syms[idx]["size"] = 0

        # Convert back to Symbol objects
        for sym in parsed_syms:
            syms.append(
                Symbol(
                    name=sym["name"],
                    addr=sym["addr"],
                    size=sym["size"],
                    code=sym["code"],
                )
            )

        return syms

    def _read_go_pclntab(self, data: bytes) -> list[Symbol]:
        """Extract symbols from Go's pclntab (program counter line table).

        Go binaries embed a symbol table in the pclntab format, which can be
        read even when the OS symbol table is stripped. Supports Go 1.4 and
        Go 1.18+ formats.

        Args:
            data: The binary file data.

        Returns:
            A list of Symbol objects extracted from Go's pclntab.
        """
        # Go 1.4 pclntab magic bytes
        MAGIC_BE = b"\xff\xff\xff\xfb"
        MAGIC_LE = b"\xfb\xff\xff\xff"
        # Go 1.18+ pclntab magic (0xFFFFFFF0 or 0xFFFFFFF1)
        MAGIC_118 = b"\xf0\xff\xff\xff"
        MAGIC_122 = b"\xf1\xff\xff\xff"

        # Try Go 1.4 format first
        pclntab_offset = self._find_pclntab(data, MAGIC_BE, MAGIC_LE)
        if pclntab_offset > 0:
            return self._parse_pclntab_v14(data, pclntab_offset)

        # Try Go 1.18+ format
        pclntab_offset = self._find_pclntab_v118(data, MAGIC_118, MAGIC_122)
        if pclntab_offset > 0:
            return self._parse_pclntab_v118(data, pclntab_offset)

        return []

    def _find_pclntab(self, data: bytes, magic_be: bytes, magic_le: bytes) -> int:
        """Find the offset of Go's pclntab in the binary data.

        Args:
            data: The binary file data.
            magic_be: Big-endian magic bytes.
            magic_le: Little-endian magic bytes.

        Returns:
            The offset of the pclntab, or 0 if not found.
        """
        # Try big-endian first
        start = 0
        while True:
            pos = data.find(magic_be, start)
            if pos == -1:
                break

            # Check if this looks like a valid pclntab (Go 1.4: quantum=4, ptr_size=4 or 8)
            if len(data) > pos + 8:
                quantum = data[pos + 6]
                ptr_size = data[pos + 7]
                if quantum == 4 and ptr_size in (4, 8):
                    return pos

            start = pos + 4

        # Try little-endian
        start = 0
        while True:
            pos = data.find(magic_le, start)
            if pos == -1:
                break

            # Check if this looks like a valid pclntab
            if len(data) > pos + 8:
                quantum = data[pos + 6]
                ptr_size = data[pos + 7]
                if quantum == 4 and ptr_size in (4, 8):
                    return pos

            start = pos + 4

        return 0

    def _parse_pclntab(self, data: bytes, pclntab_offset: int) -> list[Symbol]:
        """Parse Go's pclntab format and extract symbols.

        Go 1.4 pclntab format:
        - Header: [4B Magic][2B Padding][1B Quantum][1B PtrSize][4B nfuncs]
        - Function entries: [PC][func_offset] pairs (size depends on ptr_size)
        - _func struct: [PC][name_offset][entry_offset][... ]

        Args:
            data: The binary file data.
            pclntab_offset: Offset to the start of the pclntab.

        Returns:
            A list of Symbol objects.
        """
        symbols = []

        # Detect endianness based on magic bytes
        magic = data[pclntab_offset : pclntab_offset + 4]
        if magic == b"\xff\xff\xff\xfb":
            is_be = True  # Big-endian
        else:
            is_be = False  # Little-endian

        fmt_ptr = ">I" if is_be else "<I"
        ptr_size = data[pclntab_offset + 7]

        # Parse number of functions from header
        n_funcs = struct.unpack_from(fmt_ptr, data, pclntab_offset + 8)[0]

        # Table of [PC, func_offset] pairs starts after header
        table_start = pclntab_offset + 8 + ptr_size

        for i in range(n_funcs):
            entry_pos = table_start + (i * 2 * ptr_size)
            if entry_pos + 2 * ptr_size > len(data):
                break

            # Get the function's entry address (PC)
            pc = struct.unpack_from(fmt_ptr, data, entry_pos)[0]

            # Get the offset to the _func struct (relative to pclntab start)
            func_struct_offset = struct.unpack_from(
                fmt_ptr, data, entry_pos + ptr_size
            )[0]

            # Resolve name: In _func struct, name_offset is ptr_size bytes after PC
            name_offset_pos = pclntab_offset + func_struct_offset + ptr_size
            if name_offset_pos + ptr_size > len(data):
                continue

            name_offset = struct.unpack_from(fmt_ptr, data, name_offset_pos)[0]

            # Read the symbol name from the string table
            name_start = pclntab_offset + name_offset
            if name_start >= len(data):
                continue

            name_end = data.find(b"\x00", name_start)
            if name_end <= name_start:
                continue

            try:
                name = data[name_start:name_end].decode("utf-8", errors="replace")
            except Exception:
                continue

            # Go functions are 'T' (text/code) symbols
            symbols.append(
                Symbol(
                    name=name,
                    addr=pc,
                    size=0,  # Size not available in pclntab
                    code="T",
                )
            )

        return symbols

    def _find_pclntab_v118(
        self, data: bytes, magic_118: bytes, magic_122: bytes
    ) -> int:
        """Find the offset of Go 1.18+ pclntab in the binary data.

        Args:
            data: The binary file data.
            magic_118: Go 1.18-1.21 magic bytes (0xFFFFFFF0).
            magic_122: Go 1.22+ magic bytes (0xFFFFFFF1).

        Returns:
            The offset of the pclntab, or 0 if not found.
        """
        for magic in [magic_122, magic_118]:
            start = 0
            while True:
                pos = data.find(magic, start)
                if pos == -1:
                    break

                # Validate: check quantum and ptrSize
                if len(data) > pos + 8:
                    quantum = data[pos + 6]
                    ptr_size = data[pos + 7]
                    # quantum is typically 1 or 4, ptr_size is 4 or 8
                    if quantum in (1, 4) and ptr_size in (4, 8):
                        return pos

                start = pos + 4

        return 0

    def _parse_pclntab_v14(self, data: bytes, pclntab_offset: int) -> list[Symbol]:
        """Parse Go 1.4 pclntab format and extract symbols.

        Go 1.4 pclntab format:
        - Header: [4B Magic][2B Padding][1B Quantum][1B PtrSize][4B nfuncs]
        - Function entries: [PC][func_offset] pairs (size depends on ptr_size)
        - _func struct: [PC][name_offset][entry_offset][...]

        Args:
            data: The binary file data.
            pclntab_offset: Offset to the start of the pclntab.

        Returns:
            A list of Symbol objects.
        """
        symbols = []

        # Detect endianness based on magic bytes
        magic = data[pclntab_offset : pclntab_offset + 4]
        if magic == b"\xff\xff\xff\xfb":
            is_be = True  # Big-endian
        else:
            is_be = False  # Little-endian

        fmt_ptr = ">I" if is_be else "<I"
        ptr_size = data[pclntab_offset + 7]

        # Parse number of functions from header
        n_funcs = struct.unpack_from(fmt_ptr, data, pclntab_offset + 8)[0]

        # Table of [PC, func_offset] pairs starts after header
        table_start = pclntab_offset + 8 + ptr_size

        for i in range(n_funcs):
            entry_pos = table_start + (i * 2 * ptr_size)
            if entry_pos + 2 * ptr_size > len(data):
                break

            # Get the function's entry address (PC)
            pc = struct.unpack_from(fmt_ptr, data, entry_pos)[0]

            # Get the offset to the _func struct (relative to pclntab start)
            func_struct_offset = struct.unpack_from(
                fmt_ptr, data, entry_pos + ptr_size
            )[0]

            # Resolve name: In _func struct, name_offset is ptr_size bytes after PC
            name_offset_pos = pclntab_offset + func_struct_offset + ptr_size
            if name_offset_pos + ptr_size > len(data):
                continue

            name_offset = struct.unpack_from(fmt_ptr, data, name_offset_pos)[0]

            # Read the symbol name from the string table
            name_start = pclntab_offset + name_offset
            if name_start >= len(data):
                continue

            name_end = data.find(b"\x00", name_start)
            if name_end <= name_start:
                continue

            try:
                name = data[name_start:name_end].decode("utf-8", errors="replace")
            except Exception:
                continue

            # Go functions are 'T' (text/code) symbols
            symbols.append(
                Symbol(
                    name=name,
                    addr=pc,
                    size=0,  # Size not available in pclntab
                    code="T",
                )
            )

        return symbols

    def _parse_pclntab_v118(self, data: bytes, pclntab_offset: int) -> list[Symbol]:
        """Parse Go 1.18+ pclntab format and extract symbols.

        Port of Go's runtime/symtab.go pclntab parser for Go 1.18-1.24.

        pcHeader structure (Go 1.22+, 72 bytes):
          0-3:   magic (uint32) - 0xFFFFFFF1
          4-5:   pad1, pad2 (uint8) - 0, 0
          6:     minLC (uint8) - min instruction size
          7:     ptrSize (uint8) - pointer size (4 or 8)
          8-15:  nfunc (int64) - number of functions
          16-23: nfiles (uint64) - number of files
          24-31: textStart (uintptr) - base for function entry PC offsets
          32-39: funcnameOffset (uintptr) - offset to funcnametab
          40-47: cuOffset (uintptr) - offset to cutab
          48-55: filetabOffset (uintptr) - offset to filetab
          56-63: pctabOffset (uintptr) - offset to pctab
          64-71: pclnOffset (uintptr) - offset to pclntable

        _func structure (24 bytes for Go 1.18+):
          0-3:   entryOff (uint32) - entry PC offset from textStart
          4-7:   nameOff (int32) - function name offset in funcnametab
          8-11:  startLine (int32) - source line number
          12-15: funcID (uint32) - function type ID
          16-19: npcdata (uint32) - number of PC data tables
          20-23: nfuncdata (uint32) - number of function data items

        Args:
            data: The binary file data.
            pclntab_offset: Offset to the start of the pclntab.

        Returns:
            A list of Symbol objects.
        """
        symbols = []
        pclntab = data[pclntab_offset:]
        pclntab_size = len(pclntab)

        if pclntab_size < 72:  # Need at least full header
            return symbols

        # Parse pcHeader (72 bytes for Go 1.22+)
        magic = struct.unpack("<I", pclntab[0:4])[0]

        # Validate magic (Go 1.18-1.21: 0xFFFFFFF0, Go 1.22+: 0xFFFFFFF1)
        if magic not in (0xFFFFFFF0, 0xFFFFFFF1):
            return symbols

        n_funcs = struct.unpack("<Q", pclntab[8:16])[0]
        text_start = struct.unpack("<Q", pclntab[24:32])[0]
        funcname_offset = struct.unpack("<Q", pclntab[32:40])[0]
        pcln_offset = struct.unpack("<Q", pclntab[64:72])[0]

        # Validate offsets
        if funcname_offset == 0 or funcname_offset >= pclntab_size:
            return symbols
        if pcln_offset == 0 or pcln_offset >= pclntab_size:
            return symbols

        # _func structure is 24 bytes for Go 1.18+
        func_size = 24

        # Read function names from funcnametab
        # Names are null-terminated strings, stored consecutively
        names = {}  # offset -> name
        pos = funcname_offset
        while pos < pclntab_size - 1:
            end = pclntab.find(b"\x00", pos)
            if end <= pos or end > pos + 500:
                break
            name_len = end - pos
            if name_len >= 3:
                try:
                    name = pclntab[pos:end].decode("utf-8", errors="replace")
                    # Validate: Go function names contain specific characters
                    if any(c in name for c in "./()*[]<>"):
                        names[pos] = name
                except Exception:
                    pass
            pos = end + 1

        # Read functions from pclntable
        for i in range(n_funcs):
            func_off = pcln_offset + i * func_size
            if func_off + 8 > pclntab_size:
                break

            # Parse _func structure
            entry_off = struct.unpack("<I", pclntab[func_off : func_off + 4])[0]
            name_off = struct.unpack("<i", pclntab[func_off + 4 : func_off + 8])[0]

            # Validate entry_off (PC offset from textStart)
            if entry_off > 0x10000000:  # > 256MB is invalid
                continue

            # Resolve name from funcnametab
            if name_off < 0 or name_off >= pclntab_size:
                continue

            name = names.get(name_off)
            if not name or len(name) < 2:
                continue

            # Calculate absolute PC
            # entry_off is relative to textStart
            pc = text_start + entry_off

            symbols.append(Symbol(name=name, addr=pc, size=0, code="T"))

        return symbols

    def _read_pe(self) -> list[Entry]:
        """Read symbols from a PE (Windows) binary file."""
        entries = []
        self._file.seek(0)
        data = self._file.read()

        if len(data) < 64:
            raise ValueError("file too small for PE")

        e_lfanew = struct.unpack("<I", data[60:64])[0]

        if e_lfanew + 24 > len(data):
            raise ValueError("invalid PE header offset")

        machine = struct.unpack("<H", data[e_lfanew + 4 : e_lfanew + 6])[0]
        num_sections = struct.unpack("<H", data[e_lfanew + 6 : e_lfanew + 8])[0]
        opt_header_size = struct.unpack("<H", data[e_lfanew + 20 : e_lfanew + 22])[0]

        sections_offset = e_lfanew + 24 + opt_header_size

        syms = self._read_pe_symbols(data, sections_offset, num_sections)
        entries.append(Entry(name="", symbols=syms))

        return entries

    def _read_pe_symbols(
        self, data: bytes, sections_offset: int, num_sections: int
    ) -> list[Symbol]:
        """Extract symbols from PE binary data."""
        syms = []

        e_lfanew = struct.unpack("<I", data[60:64])[0]
        coff_start = e_lfanew + 4
        pointer_to_symbol_table = struct.unpack(
            "<I", data[coff_start + 8 : coff_start + 12]
        )[0]
        number_of_symbols = struct.unpack(
            "<I", data[coff_start + 12 : coff_start + 16]
        )[0]

        if pointer_to_symbol_table == 0 or number_of_symbols == 0:
            return syms

        if pointer_to_symbol_table + number_of_symbols * 18 > len(data):
            return syms

        string_table_offset = pointer_to_symbol_table + number_of_symbols * 18
        string_table_size = 0
        if string_table_offset + 4 <= len(data):
            string_table_size = struct.unpack(
                "<I", data[string_table_offset : string_table_offset + 4]
            )[0]

        i = 0
        while i < number_of_symbols:
            sym_offset = pointer_to_symbol_table + i * 18
            if sym_offset + 18 > len(data):
                break

            name_bytes = data[sym_offset : sym_offset + 8]
            value = struct.unpack("<I", data[sym_offset + 8 : sym_offset + 12])[0]
            section_number = struct.unpack(
                "<H", data[sym_offset + 12 : sym_offset + 14]
            )[0]
            storage_class = data[sym_offset + 16]
            aux_count = data[sym_offset + 17]

            i += 1
            i += aux_count

            if section_number == 0:
                code = "U"
            elif section_number == 0xFFF0:
                code = "A"
            elif storage_class == 2:
                code = "T"
            elif storage_class == 3:
                code = "d"
            elif storage_class == 5:
                code = "b"
            elif storage_class == 6:
                code = "C"
            elif storage_class == 8:
                code = "r"
            elif storage_class == 103:
                code = "-"
            else:
                code = "?"

            name = ""
            if name_bytes[:4] == b"\x00\x00\x00\x00":
                name_offset = struct.unpack("<I", name_bytes[4:8])[0]
                offset = string_table_offset + 4 + name_offset
                if offset < len(data):
                    end = data.find(b"\x00", offset)
                    if end > offset:
                        name = data[offset:end].decode("utf-8", errors="replace")
            else:
                name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            syms.append(Symbol(name=name, addr=value, size=0, code=code))

        return syms

    def _read_coff(self) -> list[Entry]:
        """Read symbols from a COFF object file."""
        entries = []
        self._file.seek(0)
        data = self._file.read()

        if len(data) < 20:
            raise ValueError("file too small for COFF")

        pointer_to_symbol_table = struct.unpack("<I", data[8:12])[0]
        number_of_symbols = struct.unpack("<I", data[12:16])[0]

        if pointer_to_symbol_table == 0 or number_of_symbols == 0:
            entries.append(Entry(name="", symbols=[]))
            return entries

        syms = self._read_coff_symbols(data, pointer_to_symbol_table, number_of_symbols)
        entries.append(Entry(name="", symbols=syms))

        return entries

    def _read_coff_symbols(
        self, data: bytes, symtab_offset: int, num_syms: int
    ) -> list[Symbol]:
        """Extract symbols from COFF binary data."""
        syms = []

        if symtab_offset + num_syms * 18 > len(data):
            return syms

        string_table_offset = symtab_offset + num_syms * 18
        if string_table_offset + 4 > len(data):
            return syms

        i = 0
        while i < num_syms:
            sym_offset = symtab_offset + i * 18
            if sym_offset + 18 > len(data):
                break

            name_bytes = data[sym_offset : sym_offset + 8]
            value = struct.unpack("<I", data[sym_offset + 8 : sym_offset + 12])[0]
            section_number = struct.unpack(
                "<H", data[sym_offset + 12 : sym_offset + 14]
            )[0]
            storage_class = data[sym_offset + 16]
            aux_count = data[sym_offset + 17]

            i += 1
            i += aux_count

            if section_number == 0:
                code = "U"
            elif section_number == 0xFFF0:
                code = "A"
            elif storage_class == 2:
                code = "T"
            elif storage_class == 3:
                code = "d"
            elif storage_class == 5:
                code = "b"
            elif storage_class == 6:
                code = "C"
            elif storage_class == 8:
                code = "r"
            elif storage_class == 103:
                code = "-"
            else:
                code = "?"

            name = ""
            if name_bytes[:4] == b"\x00\x00\x00\x00":
                name_offset = struct.unpack("<I", name_bytes[4:8])[0]
                offset = string_table_offset + 4 + name_offset
                if offset < len(data):
                    end = data.find(b"\x00", offset)
                    if end > offset:
                        name = data[offset:end].decode("utf-8", errors="replace")
            else:
                name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            syms.append(Symbol(name=name, addr=value, size=0, code=code))

        return syms

    def _read_coff_symbols_from_data(self, data: bytes) -> list[Symbol]:
        """Extract symbols from COFF data (used for archive members)."""
        if len(data) < 20:
            return []

        pointer_to_symbol_table = struct.unpack("<I", data[8:12])[0]
        number_of_symbols = struct.unpack("<I", data[12:16])[0]

        if pointer_to_symbol_table == 0 or number_of_symbols == 0:
            return []

        return self._read_coff_symbols(data, pointer_to_symbol_table, number_of_symbols)

    def close(self):
        """Close the underlying file handle."""
        self._file.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit; closes the file handle."""
        self.close()
