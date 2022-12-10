# coding=utf-8
# ELF.h

# p_type
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_NUM = 8
PT_LOOS = 0x60000000
PT_GNU_EH_FRAME = 0x6474e550
PT_HIOS = 0x6fffffff
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff

# sh_type
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP = 17
SHT_SYMTAB_SHNDX = 18
SHT_NUM = 19
SHT_LOOS = 0x60000000
SHT_GNU_LIBLIST = 0x6ffffff7
SHT_CHECKSUM = 0x6ffffff8
SHT_LOSUNW = 0x6ffffffa
SHT_SUNW_move = 0x6ffffffa
SHT_SUNW_COMDAT = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff
SHT_HISUNW = 0x6fffffff
SHT_HIOS = 0x6fffffff
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0x8fffffff

# sh_flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MASKPROC = 0xf0000000
SHF_MIPS_GPREL = 0x10000000

# d_tag
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH = 29
DT_FLAGS = 30
DT_ENCODING = 32
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_NUM = 34
DT_LOOS = 0x60000000
DT_HIOS = 0x6fffffff
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7fffffff
DT_PROCNUM = 0x32


class EI_NIDENT:
    def __init__(self):
        self.file_identification = None
        self.ei_class = None
        self.ei_data = None
        self.ei_version = None
        self.ei_osabi = None
        self.ei_abiversion = None
        self.ei_pad = None
        self.ei_nident = None

    def dump(self):
        buffer = b""
        buffer += self.file_identification
        buffer += int.to_bytes(self.ei_class, 1, "little")
        buffer += int.to_bytes(self.ei_data, 1, "little")
        buffer += int.to_bytes(self.ei_version, 1, "little")
        buffer += int.to_bytes(self.ei_osabi, 1, "little")
        buffer += int.to_bytes(self.ei_abiversion, 1, "little")
        buffer += self.ei_pad
        buffer += int.to_bytes(self.ei_nident, 1, "little")
        return buffer


class Elf32_Ehdr:
    def __init__(self):
        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None     # uint32_t
        self.e_phoff = None     # uint32_t
        self.e_shoff = None     # uint32_t
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None

    def dump(self):
        buffer = b""
        buffer += self.e_ident.dump()
        buffer += int.to_bytes(self.e_type, 2, "little")
        buffer += int.to_bytes(self.e_machine, 2, "little")
        buffer += int.to_bytes(self.e_version, 4, "little")
        buffer += int.to_bytes(self.e_entry, 4, "little")
        buffer += int.to_bytes(self.e_phoff, 4, "little")
        buffer += int.to_bytes(self.e_shoff, 4, "little")
        buffer += int.to_bytes(self.e_flags, 4, "little")
        buffer += int.to_bytes(self.e_ehsize, 2, "little")
        buffer += int.to_bytes(self.e_phentsize, 2, "little")
        buffer += int.to_bytes(self.e_phnum, 2, "little")
        buffer += int.to_bytes(self.e_shentsize, 2, "little")
        buffer += int.to_bytes(self.e_shnum, 2, "little")
        buffer += int.to_bytes(self.e_shstrndx, 2, "little")
        return buffer


class Elf64_Ehdr:
    def __init__(self):
        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None     # uint64_t
        self.e_phoff = None     # uint64_t
        self.e_shoff = None     # uint64_t
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None

    def dump(self):
        buffer = b""
        buffer += self.e_ident.dump()
        buffer += int.to_bytes(self.e_type, 2, "little")
        buffer += int.to_bytes(self.e_machine, 2, "little")
        buffer += int.to_bytes(self.e_version, 4, "little")
        buffer += int.to_bytes(self.e_entry, 8, "little")
        buffer += int.to_bytes(self.e_phoff, 8, "little")
        buffer += int.to_bytes(self.e_shoff, 8, "little")
        buffer += int.to_bytes(self.e_flags, 4, "little")
        buffer += int.to_bytes(self.e_ehsize, 2, "little")
        buffer += int.to_bytes(self.e_phentsize, 2, "little")
        buffer += int.to_bytes(self.e_phnum, 2, "little")
        buffer += int.to_bytes(self.e_shentsize, 2, "little")
        buffer += int.to_bytes(self.e_shnum, 2, "little")
        buffer += int.to_bytes(self.e_shstrndx, 2, "little")
        return buffer


class Elf32_Shdr:
    def __init__(self):
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

    def dump(self):
        buffer = b""
        buffer += int.to_bytes(self.sh_name, 4, "little")
        buffer += int.to_bytes(self.sh_type, 4, "little")
        buffer += int.to_bytes(self.sh_flags, 4, "little")
        buffer += int.to_bytes(self.sh_addr, 4, "little")
        buffer += int.to_bytes(self.sh_offset, 4, "little")
        buffer += int.to_bytes(self.sh_size, 4, "little")
        buffer += int.to_bytes(self.sh_link, 4, "little")
        buffer += int.to_bytes(self.sh_info, 4, "little")
        buffer += int.to_bytes(self.sh_addralign, 4, "little")
        buffer += int.to_bytes(self.sh_entsize, 4, "little")
        return buffer


class Elf64_Shdr:
    def __init__(self):
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

    def dump(self):
        buffer = b""
        buffer += int.to_bytes(self.sh_name, 4, "little")
        buffer += int.to_bytes(self.sh_type, 4, "little")
        buffer += int.to_bytes(self.sh_flags, 8, "little")
        buffer += int.to_bytes(self.sh_addr, 8, "little")
        buffer += int.to_bytes(self.sh_offset, 8, "little")
        buffer += int.to_bytes(self.sh_size, 8, "little")
        buffer += int.to_bytes(self.sh_link, 4, "little")
        buffer += int.to_bytes(self.sh_info, 4, "little")
        buffer += int.to_bytes(self.sh_addralign, 8, "little")
        buffer += int.to_bytes(self.sh_entsize, 8, "little")
        return buffer


class Elf32_Sym:
    def __init__(self):
        self.st_name = None
        self.st_value = None
        self.st_size = None
        self.st_info = None
        self.st_other = None
        self.st_shndx = None


class Elf64_Sym:
    def __init__(self):
        self.st_name = None
        self.st_info = None
        self.st_other = None
        self.st_shndx = None
        self.st_value = None
        self.st_size = None


class Elf32_Syminfo:
    def __init__(self):
        self.si_boundto = None
        self.si_flags = None


class Elf64_Syminfo:
    def __init__(self):
        self.si_boundto = None
        self.si_flags = None


class Elf32_Rel:
    def __init__(self):
        self.r_offset = None
        self.r_info = None


class Elf64_Rel:
    def __init__(self):
        self.r_offset = None
        self.r_info = None


class Elf32_Rela:
    def __init__(self):
        self.r_offset = None
        self.r_info = None
        self.r_addend = None


class Elf64_Rela:
    def __init__(self):
        self.r_offset = None
        self.r_info = None
        self.r_addend = None


class Elf32_Phdr:
    def __init__(self):
        self.p_type = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_flags = None
        self.p_align = None

    def dump(self):
        buffer = b""
        buffer += int.to_bytes(self.p_type, 4, "little")
        buffer += int.to_bytes(self.p_offset, 4, "little")
        buffer += int.to_bytes(self.p_vaddr, 4, "little")
        buffer += int.to_bytes(self.p_paddr, 4, "little")
        buffer += int.to_bytes(self.p_filesz, 4, "little")
        buffer += int.to_bytes(self.p_memsz, 4, "little")
        buffer += int.to_bytes(self.p_flags, 4, "little")
        buffer += int.to_bytes(self.p_align, 4, "little")
        return buffer


class Elf64_Phdr:
    def __init__(self):
        self.p_type = None
        self.p_flags = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_align = None

    def dump(self):
        buffer = b""
        buffer += int.to_bytes(self.p_type, 4, "little")
        buffer += int.to_bytes(self.p_flags, 4, "little")
        buffer += int.to_bytes(self.p_offset, 8, "little")
        buffer += int.to_bytes(self.p_vaddr, 8, "little")
        buffer += int.to_bytes(self.p_paddr, 8, "little")
        buffer += int.to_bytes(self.p_filesz, 8, "little")
        buffer += int.to_bytes(self.p_memsz, 8, "little")
        buffer += int.to_bytes(self.p_align, 8, "little")
        return buffer


class Elf32_Dyn:
    def __init__(self):
        self.d_tag = None
        self.d_un = None


class Elf64_Dyn:
    def __init__(self):
        self.d_tag = None
        self.d_un = None

