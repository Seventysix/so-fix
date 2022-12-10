# coding=utf-8

import optparse
import elf


class SoInfo:
    def __init__(self):
        self.nbucket = -1
        self.nchain = -1

        self.hash = -1
        self.strtab = -1
        self.symtab = -1
        self.plt_rel = -1       # 32位用rel
        self.plt_rel_size = -1
        self.plt_rela = -1      # 64位用rela
        self.plt_rela_size = -1
        self.rel = -1           # 32位用rel
        self.rel_size = -1
        self.rela = -1          # 64位用rela
        self.rela_size = -1
        self.plt_got = -1
        self.init_func = -1
        self.fini_func = -1
        self.init_array = -1
        self.init_array_size = -1
        self.fini_array = -1
        self.fini_array_size = -1
        self.preinit_array = -1
        self.preinit_array_size  = -1
        self.strtabsize = -1

        self.ARM_exidx = -1
        self.ARM_exidx_size = -1

        self.has_text_relocations = False


class ELF:
    def __init__(self):
        self.elfHeader = None
        self.sectionHeaderTable = []
        self.programHeaderTable = []
        self.pt_dynamic = None
        self.last_PT_load = None
        self.shstr = b""
        self.bias = 0

        # soinfo
        self.soinfo = SoInfo()

        self.raw_buf = None

    def _load_elf_header(self):
        if self.raw_buf is None:
            raise Exception("Try load elf header, but file buffer is None.")

        self.raw_buf.seek(0, 0)

        # parse EI_NIDENT
        e_ident = elf.EI_NIDENT()
        e_ident.file_identification = self.raw_buf.read(4)
        e_ident.ei_class = int.from_bytes(self.raw_buf.read(1), "little")
        e_ident.ei_data = int.from_bytes(self.raw_buf.read(1), "little")
        e_ident.ei_version = int.from_bytes(self.raw_buf.read(1), "little")
        e_ident.ei_osabi = int.from_bytes(self.raw_buf.read(1), "little")
        e_ident.ei_abiversion = int.from_bytes(self.raw_buf.read(1), "little")
        e_ident.ei_pad = self.raw_buf.read(6)
        e_ident.ei_nident = int.from_bytes(self.raw_buf.read(1), "little")

        # parse Elfxx_Ehdr
        if e_ident.ei_class == 0x1:
            # arm32
            elf_header = elf.Elf32_Ehdr()
            elf_header.e_ident = e_ident
            elf_header.e_type = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_machine = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_version = int.from_bytes(self.raw_buf.read(4), "little")
            elf_header.e_entry = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            elf_header.e_phoff = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            elf_header.e_shoff = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            elf_header.e_flags = int.from_bytes(self.raw_buf.read(4), "little")
            elf_header.e_ehsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_phentsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_phnum = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shentsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shnum = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shstrndx = int.from_bytes(self.raw_buf.read(2), "little")
        else:
            # arm64
            elf_header = elf.Elf64_Ehdr()
            elf_header.e_ident = e_ident
            elf_header.e_type = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_machine = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_version = int.from_bytes(self.raw_buf.read(4), "little")
            elf_header.e_entry = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            elf_header.e_phoff = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            elf_header.e_shoff = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            elf_header.e_flags = int.from_bytes(self.raw_buf.read(4), "little")
            elf_header.e_ehsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_phentsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_phnum = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shentsize = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shnum = int.from_bytes(self.raw_buf.read(2), "little")
            elf_header.e_shstrndx = int.from_bytes(self.raw_buf.read(2), "little")
        self.elfHeader = elf_header

        print("[Info] Load ELF header finish.")

    def _fix_elf_header(self, sh_offset):
        self.elfHeader.e_shoff = sh_offset
        self.elfHeader.e_shnum = len(self.sectionHeaderTable)
        self.elfHeader.e_shstrndx = len(self.sectionHeaderTable) - 1
        if self.elfHeader.e_ident.ei_class == 0x1:
            self.elfHeader.e_shentsize = 40
        else:
            self.elfHeader.e_shentsize = 64

    def _load_program_header(self, offset):
        self.raw_buf.seek(offset)

        if self.elfHeader.e_ident.ei_class == 0x1:
            program_header = elf.Elf32_Phdr()
            program_header.p_type = int.from_bytes(self.raw_buf.read(4), "little")
            program_header.p_offset = int.from_bytes(self.raw_buf.read(4), "little")    # uint32_t
            program_header.p_vaddr = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            program_header.p_paddr = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            program_header.p_filesz = int.from_bytes(self.raw_buf.read(4), "little")    # uint32_t
            program_header.p_memsz = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
            program_header.p_flags = int.from_bytes(self.raw_buf.read(4), "little")
            program_header.p_align = int.from_bytes(self.raw_buf.read(4), "little")     # uint32_t
        else:
            program_header = elf.Elf64_Phdr()
            program_header.p_type = int.from_bytes(self.raw_buf.read(4), "little")
            program_header.p_flags = int.from_bytes(self.raw_buf.read(4), "little")
            program_header.p_offset = int.from_bytes(self.raw_buf.read(8), "little")    # uint64_t
            program_header.p_vaddr = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            program_header.p_paddr = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            program_header.p_filesz = int.from_bytes(self.raw_buf.read(8), "little")    # uint64_t
            program_header.p_memsz = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t
            program_header.p_align = int.from_bytes(self.raw_buf.read(8), "little")     # uint64_t

        return program_header

    def _load_program_header_table(self):
        if self.raw_buf is None:
            raise Exception("Try load program header table, but file buffer is None.")
        if self.elfHeader is None:
            raise Exception("Try load program header table, but ELF Header is None.")

        ph_number = self.elfHeader.e_phnum
        if ph_number < 0 or ph_number > 1024:
            raise Exception("Try load program header table, invalid e_phnum.")

        self.programHeaderTable.clear()

        for i in range(ph_number):
            if self.elfHeader.e_ident.ei_class == 0x1:
                cur_offset = self.elfHeader.e_phoff + i * 32
            else:
                cur_offset = self.elfHeader.e_phoff + i * 56
            cur_ph = self._load_program_header(cur_offset)
            self.programHeaderTable.append(cur_ph)

            if cur_ph.p_type == elf.PT_DYNAMIC:
                self.pt_dynamic = cur_ph
            if cur_ph.p_type == elf.PT_LOPROC or cur_ph.p_type == (elf.PT_LOPROC + 1):
                self.soinfo.ARM_exidx = cur_ph.p_vaddr
                self.soinfo.ARM_exidx_size = cur_ph.p_memsz

        print("[Info] Load program header table finish, count: {0}.".format(len(self.programHeaderTable)))

    def _fix_program_header_table(self):
        if len(self.programHeaderTable) == 0:
            return

        # 之后在修复有bias情况
        # for ph in self.programHeaderTable:
        #     if ph.p_type == elf.PT_LOAD:
        #         self.bias = ph.p_vaddr
        #         break

        max_load_end = 0
        for ph in self.programHeaderTable:
            if ph.p_type == elf.PT_LOAD:
                # ph.p_vaddr -= self.bias
                ph.p_paddr = ph.p_vaddr
                ph.p_offset = ph.p_vaddr
                ph.p_filesz = ph.p_memsz

                cur_load_end = ph.p_paddr + ph.p_memsz
                if cur_load_end > max_load_end:
                    max_load_end = cur_load_end
                    self.last_PT_load = ph
        print("[Info] Fix program header table finish.")

    def _get_shstrtab_offset(self, sh_name: bytes):
        cur_offset = len(self.shstr)
        self.shstr += sh_name
        return cur_offset

    def _read_soinfo(self):
        if self.raw_buf is None:
            raise Exception("Try read soinfo, but file buffer is None.")
        if self.elfHeader is None:
            raise Exception("Try read soinfo, but ELF Header is None.")
        if self.pt_dynamic is None:
            raise Exception("Try read soinfo, but PT_DYNAMIC is None.")

        if self.elfHeader.e_ident.ei_class == 0x1:
            Elf_Dyn_sz = 8  # sizeof(Elf32_Dyn) = 8
            int_sz = 4      # sizeof(int32_t) = 4
        else:
            Elf_Dyn_sz = 16 # sizeof(Elf64_Dyn) = 16
            int_sz = 8      # sizeof(int64_t) = 8

        dt_dynamic_count = int(self.pt_dynamic.p_memsz / Elf_Dyn_sz)
        for i in range(dt_dynamic_count):
            cur_offset = self.pt_dynamic.p_vaddr + Elf_Dyn_sz * i
            self.raw_buf.seek(cur_offset)
            dyn = elf.Elf32_Dyn()
            dyn.d_tag = int.from_bytes(self.raw_buf.read(int_sz), "little")
            dyn.d_un = int.from_bytes(self.raw_buf.read(int_sz), "little")

            if dyn.d_tag == elf.DT_HASH:
                self.soinfo.hash = dyn.d_un
                self.raw_buf.seek(self.soinfo.hash)
                self.soinfo.nbucket = int.from_bytes(self.raw_buf.read(int_sz), "little")
                self.soinfo.nchain = int.from_bytes(self.raw_buf.read(int_sz), "little")
            elif dyn.d_tag == elf.DT_STRTAB:
                self.soinfo.strtab = dyn.d_un
            elif dyn.d_tag == elf.DT_SYMTAB:
                self.soinfo.symtab = dyn.d_un
            elif dyn.d_tag == elf.DT_PLTREL:
                pass
            elif dyn.d_tag == elf.DT_JMPREL:
                if self.elfHeader.e_ident.ei_class == 0x1:
                    self.soinfo.plt_rel = dyn.d_un
                else:
                    self.soinfo.plt_rela = dyn.d_un
            elif dyn.d_tag == elf.DT_PLTRELSZ:
                if self.elfHeader.e_ident.ei_class == 0x1:
                    self.soinfo.plt_rel_size = dyn.d_un
                else:
                    self.soinfo.plt_rela_size = dyn.d_un
            elif dyn.d_tag == elf.DT_REL:
                self.soinfo.rel = dyn.d_un
            elif dyn.d_tag == elf.DT_RELSZ:
                self.soinfo.rel_size = dyn.d_un
            elif dyn.d_tag == elf.DT_RELA:
                self.soinfo.rela = dyn.d_un
            elif dyn.d_tag == elf.DT_RELASZ:
                self.soinfo.rela_size = dyn.d_un
            elif dyn.d_tag == elf.DT_PLTGOT:
                self.soinfo.plt_got = dyn.d_un
            elif dyn.d_tag == elf.DT_DEBUG:
                pass
            elif dyn.d_tag == elf.DT_INIT:
                self.soinfo.init_func = dyn.d_un
            elif dyn.d_tag == elf.DT_FINI:
                self.soinfo.fini_func = dyn.d_un
            elif dyn.d_tag == elf.DT_INIT_ARRAY:
                self.soinfo.init_array = dyn.d_un
            elif dyn.d_tag == elf.DT_INIT_ARRAYSZ:
                self.soinfo.init_array_size = dyn.d_un
            elif dyn.d_tag == elf.DT_FINI_ARRAY:
                self.soinfo.fini_array = dyn.d_un
            elif dyn.d_tag == elf.DT_FINI_ARRAYSZ:
                self.soinfo.fini_array_size = dyn.d_un
            elif dyn.d_tag == elf.DT_PREINIT_ARRAY:
                self.soinfo.preinit_array = dyn.d_un
            elif dyn.d_tag == elf.DT_PREINIT_ARRAYSZ:
                self.soinfo.preinit_array_size = dyn.d_un
            elif dyn.d_tag == elf.DT_TEXTREL:
                self.soinfo.has_text_relocations = True
            elif dyn.d_tag == elf.DT_STRSZ:
                self.soinfo.strtabsize = dyn.d_un
        print("[Info] Read soinfo finish.")

    def _rebuild_section_header_table(self):
        # 由prelink_image函数，可知通过PT_DYNAMIC可以获得部分关键section信息
        if self.raw_buf is None:
            raise Exception("Try rebuild section header table, but file buffer is None.")
        if self.pt_dynamic is None:
            raise Exception("Try rebuild section header table, but PT_DYNAMIC is None.")

        self.sectionHeaderTable.clear()

        if self.elfHeader.e_ident.ei_class == 0x1:
            # 32位
            # .dynsym
            if self.soinfo.symtab > -1:
                dt_dynsym = elf.Elf32_Shdr()
                dt_dynsym.sh_name = self._get_shstrtab_offset(b'.dynsym\0')
                dt_dynsym.sh_type = elf.SHT_SYMTAB
                dt_dynsym.sh_flags = elf.SHF_ALLOC
                dt_dynsym.sh_addr = self.soinfo.symtab
                dt_dynsym.sh_offset = dt_dynsym.sh_addr
                dt_dynsym.sh_size = self.soinfo.nchain * 16
                dt_dynsym.sh_link = None  # idx_dynstr
                dt_dynsym.sh_info = 1
                dt_dynsym.sh_addralign = 4
                dt_dynsym.sh_entsize = 16
                self.sectionHeaderTable.append(dt_dynsym)
            # .dynstr
            if self.soinfo.strtab > -1:
                dt_dynstr = elf.Elf32_Shdr()
                dt_dynstr.sh_name = self._get_shstrtab_offset(b'.dynstr\0')
                dt_dynstr.sh_type = elf.SHT_STRTAB
                dt_dynstr.sh_flags = elf.SHF_ALLOC
                dt_dynstr.sh_addr = self.soinfo.strtab
                dt_dynstr.sh_offset = dt_dynstr.sh_addr
                dt_dynstr.sh_size = self.soinfo.strtabsize
                dt_dynstr.sh_link = 0
                dt_dynstr.sh_info = 0
                dt_dynstr.sh_addralign = 1
                dt_dynstr.sh_entsize = 0
                self.sectionHeaderTable.append(dt_dynstr)
            # .hash
            if self.soinfo.hash > -1:
                dt_hash = elf.Elf32_Shdr()
                dt_hash.sh_name = self._get_shstrtab_offset(b'.hash\0')
                dt_hash.sh_type = elf.SHT_HASH
                dt_hash.sh_flags = elf.SHF_ALLOC
                dt_hash.sh_addr = self.soinfo.hash
                dt_hash.sh_offset = dt_hash.sh_addr
                dt_hash.sh_size = (self.soinfo.nbucket + self.soinfo.nchain + 2) * 4
                dt_hash.sh_link = None   # idx_dynsym
                dt_hash.sh_info = 0
                dt_hash.sh_addralign = 4
                dt_hash.sh_entsize = 4
                self.sectionHeaderTable.append(dt_hash)
            # .rel.dyn
            if self.soinfo.rel > -1:
                dt_rel = elf.Elf32_Shdr()
                dt_rel.sh_name = self._get_shstrtab_offset(b'.rel.dyn\0')
                dt_rel.sh_type = elf.SHT_REL
                dt_rel.sh_flags = elf.SHF_ALLOC
                dt_rel.sh_addr = self.soinfo.rel
                dt_rel.sh_offset = dt_rel.sh_addr
                dt_rel.sh_size = self.soinfo.rel_size
                dt_rel.sh_link = None  # idx_dynsym
                dt_rel.sh_info = 0
                dt_rel.sh_addralign = 4
                dt_rel.sh_entsize = 8
                self.sectionHeaderTable.append(dt_rel)
            # .rel.plt and .plt and .text
            if self.soinfo.plt_rel > -1:
                # .rel.plt
                dt_plt_rel = elf.Elf32_Shdr()
                dt_plt_rel.sh_name = self._get_shstrtab_offset(b'.rel.plt\0')
                dt_plt_rel.sh_type = elf.SHT_REL
                dt_plt_rel.sh_flags = elf.SHF_ALLOC
                dt_plt_rel.sh_addr = self.soinfo.plt_rel
                dt_plt_rel.sh_offset = dt_plt_rel.sh_addr
                dt_plt_rel.sh_size = self.soinfo.plt_rel_size
                dt_plt_rel.sh_link = None  # idx_dynsym
                dt_plt_rel.sh_info = 0
                dt_plt_rel.sh_addralign = 4
                dt_plt_rel.sh_entsize = 8
                self.sectionHeaderTable.append(dt_plt_rel)
                # .plt
                dt_plt = elf.Elf32_Shdr()
                dt_plt.sh_name = self._get_shstrtab_offset(b'.plt\0')
                dt_plt.sh_type = elf.SHT_PROGBITS
                dt_plt.sh_flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR
                dt_plt.sh_addr = dt_plt_rel.sh_addr + dt_plt_rel.sh_size
                dt_plt.sh_offset = dt_plt.sh_addr
                dt_plt.sh_size = 0x14 + 12 * (self.soinfo.plt_rel_size / dt_plt_rel.sh_entsize)
                dt_plt.sh_link = 0
                dt_plt.sh_info = 0
                dt_plt.sh_addralign = 4
                dt_plt.sh_entsize = 0
                self.sectionHeaderTable.append(dt_plt)
                # .text
                dt_text = elf.Elf32_Shdr()
                # dt_text.sh_name = self._get_shstrtab_offset(b'.text\0')     # 实际上是把.text和.ARM.extab合并到一起了
                dt_text.sh_name = '.text'
                dt_text.sh_type = elf.SHT_PROGBITS
                dt_text.sh_flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR
                dt_text.sh_addr = dt_plt.sh_addr + dt_plt.sh_size
                dt_text.sh_offset = dt_text.sh_addr
                dt_text.sh_size = 0     # 先空着，最后排序一下，通过前后地址减出来吧
                dt_text.sh_link = 0
                dt_text.sh_info = 0
                dt_text.sh_addralign = 4
                dt_text.sh_entsize = 0
                self.sectionHeaderTable.append(dt_text)
            # .ARM.exidx
            if self.soinfo.ARM_exidx > -1:
                dt_ARM_exidx = elf.Elf32_Shdr()
                dt_ARM_exidx.sh_name = self._get_shstrtab_offset(b'.ARM.exidx\0')
                dt_ARM_exidx.sh_type = elf.SHT_LOPROC + 1
                dt_ARM_exidx.sh_flags = elf.SHF_ALLOC | elf.SHF_MIPS_GPREL
                dt_ARM_exidx.sh_addr = self.soinfo.ARM_exidx
                dt_ARM_exidx.sh_offset = dt_ARM_exidx.sh_addr
                dt_ARM_exidx.sh_size = self.soinfo.ARM_exidx_size
                dt_ARM_exidx.sh_link = 0  # idx_text
                dt_ARM_exidx.sh_info = 0
                dt_ARM_exidx.sh_addralign = 4
                dt_ARM_exidx.sh_entsize = 8
                self.sectionHeaderTable.append(dt_ARM_exidx)
            # .fini_array
            if self.soinfo.fini_array > -1:
                dt_fini_array = elf.Elf32_Shdr()
                dt_fini_array.sh_name = self._get_shstrtab_offset(b'.fini_array\0')
                dt_fini_array.sh_type = elf.SHT_FINI_ARRAY
                dt_fini_array.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_fini_array.sh_addr = self.soinfo.fini_array
                dt_fini_array.sh_offset = dt_fini_array.sh_addr
                dt_fini_array.sh_size = self.soinfo.fini_array_size
                dt_fini_array.sh_link = 0
                dt_fini_array.sh_info = 0
                dt_fini_array.sh_addralign = 4
                dt_fini_array.sh_entsize = 0
                self.sectionHeaderTable.append(dt_fini_array)
            # .init_array
            if self.soinfo.init_array > -1:
                dt_init_array = elf.Elf32_Shdr()
                dt_init_array.sh_name = self._get_shstrtab_offset(b'.init_array\0')
                dt_init_array.sh_type = elf.SHT_INIT_ARRAY
                dt_init_array.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_init_array.sh_addr = self.soinfo.init_array
                dt_init_array.sh_offset = dt_init_array.sh_addr
                dt_init_array.sh_size = self.soinfo.init_array_size
                dt_init_array.sh_link = 0
                dt_init_array.sh_info = 0
                dt_init_array.sh_addralign = 4
                dt_init_array.sh_entsize = 0
                self.sectionHeaderTable.append(dt_init_array)
            # .dynamic
            if self.pt_dynamic is not None:
                dt_dynamic = elf.Elf32_Shdr()
                dt_dynamic.sh_name = self._get_shstrtab_offset(b".dynamic\0")
                dt_dynamic.sh_type = elf.SHT_DYNAMIC
                dt_dynamic.sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC
                dt_dynamic.sh_addr = self.pt_dynamic.p_vaddr
                dt_dynamic.sh_offset = self.pt_dynamic.p_vaddr
                dt_dynamic.sh_size = self.pt_dynamic.p_memsz
                dt_dynamic.sh_link = None  # idx_dynstr
                dt_dynamic.sh_info = 0
                dt_dynamic.sh_addralign = 4
                dt_dynamic.sh_entsize = 8
                self.sectionHeaderTable.append(dt_dynamic)
            # .got
            if self.soinfo.plt_got > -1:
                # 此处got修复还是有待商榷的
                dt_got = elf.Elf32_Shdr()
                dt_got.sh_name = self._get_shstrtab_offset(b'.got\0')
                dt_got.sh_type = elf.SHT_PROGBITS
                dt_got.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_got.sh_addr = self.soinfo.plt_got
                dt_got.sh_offset = dt_got.sh_addr
                dt_got.sh_size = self.soinfo.plt_got + 4 * (self.soinfo.plt_rel_size / 8 + 3) - dt_got.sh_addr
                dt_got.sh_link = 0
                dt_got.sh_info = 0
                dt_got.sh_addralign = 4
                dt_got.sh_entsize = 0
                self.sectionHeaderTable.append(dt_got)
        else:
            # 64位
            # .dynsym
            if self.soinfo.symtab > -1:
                dt_dynsym = elf.Elf64_Shdr()
                dt_dynsym.sh_name = self._get_shstrtab_offset(b'.dynsym\0')
                dt_dynsym.sh_type = elf.SHT_SYMTAB
                dt_dynsym.sh_flags = elf.SHF_ALLOC
                dt_dynsym.sh_addr = self.soinfo.symtab
                dt_dynsym.sh_offset = dt_dynsym.sh_addr
                dt_dynsym.sh_size = self.soinfo.nchain * 16
                dt_dynsym.sh_link = None  # idx_dynstr
                dt_dynsym.sh_info = 1
                dt_dynsym.sh_addralign = 8
                dt_dynsym.sh_entsize = 24
                self.sectionHeaderTable.append(dt_dynsym)
            # .dynstr
            if self.soinfo.strtab > -1:
                dt_dynstr = elf.Elf64_Shdr()
                dt_dynstr.sh_name = self._get_shstrtab_offset(b'.dynstr\0')
                dt_dynstr.sh_type = elf.SHT_STRTAB
                dt_dynstr.sh_flags = elf.SHF_ALLOC
                dt_dynstr.sh_addr = self.soinfo.strtab
                dt_dynstr.sh_offset = dt_dynstr.sh_addr
                dt_dynstr.sh_size = self.soinfo.strtabsize
                dt_dynstr.sh_link = 0
                dt_dynstr.sh_info = 0
                dt_dynstr.sh_addralign = 1
                dt_dynstr.sh_entsize = 0
                self.sectionHeaderTable.append(dt_dynstr)
            # .hash
            if self.soinfo.hash > -1:
                dt_hash = elf.Elf64_Shdr()
                dt_hash.sh_name = self._get_shstrtab_offset(b'.hash\0')
                dt_hash.sh_type = elf.SHT_HASH
                dt_hash.sh_flags = elf.SHF_ALLOC
                dt_hash.sh_addr = self.soinfo.hash
                dt_hash.sh_offset = dt_hash.sh_addr
                dt_hash.sh_size = (self.soinfo.nbucket + self.soinfo.nchain + 2) * 8
                dt_hash.sh_link = None  # idx_dynsym
                dt_hash.sh_info = 0
                dt_hash.sh_addralign = 4
                dt_hash.sh_entsize = 4
                self.sectionHeaderTable.append(dt_hash)
            # .rela.dyn
            if self.soinfo.rela > -1:
                dt_rela = elf.Elf64_Shdr()
                dt_rela.sh_name = self._get_shstrtab_offset(b'.rela.dyn\0')
                dt_rela.sh_type = elf.SHT_RELA
                dt_rela.sh_flags = elf.SHF_ALLOC
                dt_rela.sh_addr = self.soinfo.rela
                dt_rela.sh_offset = dt_rela.sh_addr
                dt_rela.sh_size = self.soinfo.rela_size
                dt_rela.sh_link = None  # idx_dynsym
                dt_rela.sh_info = 0
                dt_rela.sh_addralign = 8
                dt_rela.sh_entsize = 24
                self.sectionHeaderTable.append(dt_rela)
            # .rela.plt and .plt and .text
            if self.soinfo.plt_rela > -1:
                # .rela.plt
                dt_plt_rela = elf.Elf64_Shdr()
                dt_plt_rela.sh_name = self._get_shstrtab_offset(b'.rela.plt\0')
                dt_plt_rela.sh_type = elf.SHT_RELA
                dt_plt_rela.sh_flags = elf.SHF_ALLOC
                dt_plt_rela.sh_addr = self.soinfo.plt_rela
                dt_plt_rela.sh_offset = dt_plt_rela.sh_addr
                dt_plt_rela.sh_size = self.soinfo.plt_rela_size
                dt_plt_rela.sh_link = None  # idx_dynsym
                dt_plt_rela.sh_info = 0
                dt_plt_rela.sh_addralign = 8
                dt_plt_rela.sh_entsize = 24
                self.sectionHeaderTable.append(dt_plt_rela)
                # .plt
                dt_plt = elf.Elf64_Shdr()
                dt_plt.sh_name = self._get_shstrtab_offset(b'.plt\0')
                dt_plt.sh_type = elf.SHT_PROGBITS
                dt_plt.sh_flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR
                dt_plt.sh_addr = dt_plt_rela.sh_addr + dt_plt_rela.sh_size
                dt_plt.sh_offset = dt_plt.sh_addr
                dt_plt.sh_size = 0x14 + 16 * (self.soinfo.plt_rela_size / dt_plt_rela.sh_entsize)
                dt_plt.sh_link = 0
                dt_plt.sh_info = 0
                dt_plt.sh_addralign = 4
                dt_plt.sh_entsize = 0
                self.sectionHeaderTable.append(dt_plt)
                # .text
                dt_text = elf.Elf64_Shdr()
                # dt_text.sh_name = self._get_shstrtab_offset(b'.text\0')  # 实际上是把.text和.ARM.extab合并到一起了
                dt_text.sh_name = '.text'
                dt_text.sh_type = elf.SHT_PROGBITS
                dt_text.sh_flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR
                dt_text.sh_addr = dt_plt.sh_addr + dt_plt.sh_size
                dt_text.sh_offset = dt_text.sh_addr
                dt_text.sh_size = 0  # 先空着，最后排序一下，通过前后地址减出来吧
                dt_text.sh_link = 0
                dt_text.sh_info = 0
                dt_text.sh_addralign = 4
                dt_text.sh_entsize = 0
                self.sectionHeaderTable.append(dt_text)
            # .ARM.exidx
            if self.soinfo.ARM_exidx > -1:
                dt_ARM_exidx = elf.Elf64_Shdr()
                dt_ARM_exidx.sh_name = self._get_shstrtab_offset(b'.ARM.exidx\0')
                dt_ARM_exidx.sh_type = elf.SHT_LOPROC + 1
                dt_ARM_exidx.sh_flags = elf.SHF_ALLOC | elf.SHF_MIPS_GPREL
                dt_ARM_exidx.sh_addr = self.soinfo.ARM_exidx
                dt_ARM_exidx.sh_offset = dt_ARM_exidx.sh_addr
                dt_ARM_exidx.sh_size = self.soinfo.ARM_exidx_size
                dt_ARM_exidx.sh_link = 0  # idx_text
                dt_ARM_exidx.sh_info = 0
                dt_ARM_exidx.sh_addralign = 4
                dt_ARM_exidx.sh_entsize = 8
                self.sectionHeaderTable.append(dt_ARM_exidx)
            # .fini_array
            if self.soinfo.fini_array > -1:
                dt_fini_array = elf.Elf64_Shdr()
                dt_fini_array.sh_name = self._get_shstrtab_offset(b'.fini_array\0')
                dt_fini_array.sh_type = elf.SHT_FINI_ARRAY
                dt_fini_array.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_fini_array.sh_addr = self.soinfo.fini_array
                dt_fini_array.sh_offset = dt_fini_array.sh_addr
                dt_fini_array.sh_size = self.soinfo.fini_array_size
                dt_fini_array.sh_link = 0
                dt_fini_array.sh_info = 0
                dt_fini_array.sh_addralign = 8
                dt_fini_array.sh_entsize = 0
                self.sectionHeaderTable.append(dt_fini_array)
            # .init_array
            if self.soinfo.init_array > -1:
                dt_init_array = elf.Elf64_Shdr()
                dt_init_array.sh_name = self._get_shstrtab_offset(b'.init_array\0')
                dt_init_array.sh_type = elf.SHT_INIT_ARRAY
                dt_init_array.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_init_array.sh_addr = self.soinfo.init_array
                dt_init_array.sh_offset = dt_init_array.sh_addr
                dt_init_array.sh_size = self.soinfo.init_array_size
                dt_init_array.sh_link = 0
                dt_init_array.sh_info = 0
                dt_init_array.sh_addralign = 8
                dt_init_array.sh_entsize = 0
                self.sectionHeaderTable.append(dt_init_array)
            # .dynamic
            if self.pt_dynamic is not None:
                dt_dynamic = elf.Elf64_Shdr()
                dt_dynamic.sh_name = self._get_shstrtab_offset(b".dynamic\0")
                dt_dynamic.sh_type = elf.SHT_DYNAMIC
                dt_dynamic.sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC
                dt_dynamic.sh_addr = self.pt_dynamic.p_vaddr
                dt_dynamic.sh_offset = self.pt_dynamic.p_vaddr
                dt_dynamic.sh_size = self.pt_dynamic.p_memsz
                dt_dynamic.sh_link = None  # idx_dynstr
                dt_dynamic.sh_info = 0
                dt_dynamic.sh_addralign = 8
                dt_dynamic.sh_entsize = 16
                self.sectionHeaderTable.append(dt_dynamic)
            # .got
            if self.soinfo.plt_got > -1:
                # 此处got修复还是有待商榷的
                dt_got = elf.Elf64_Shdr()
                dt_got.sh_name = self._get_shstrtab_offset(b'.got\0')
                dt_got.sh_type = elf.SHT_PROGBITS
                dt_got.sh_flags = elf.SHF_ALLOC | elf.SHF_WRITE
                dt_got.sh_addr = self.soinfo.plt_got
                dt_got.sh_offset = dt_got.sh_addr
                dt_got.sh_size = self.soinfo.plt_got + 8 * (self.soinfo.plt_rel_size / 24 + 3) - dt_got.sh_addr
                dt_got.sh_link = 0
                dt_got.sh_info = 0
                dt_got.sh_addralign = 4
                dt_got.sh_entsize = 0
                self.sectionHeaderTable.append(dt_got)
        print("[Info] Rebuild section header table finish, count {0}.".format(len(self.sectionHeaderTable)))

    def _fix_section_header_table(self):
        if len(self.sectionHeaderTable) > 1:
            self.sectionHeaderTable = sorted(self.sectionHeaderTable, key=lambda sh: sh.sh_addr)
        idx_dynsym, idx_dynstr, idx_text = 0, 0, 0
        for i in range(len(self.sectionHeaderTable)):
            cur_section = self.sectionHeaderTable[i]
            if cur_section.sh_type == elf.SHT_SYMTAB:
                idx_dynsym = i
            elif cur_section.sh_type == elf.SHT_STRTAB:
                idx_dynstr = i
            elif cur_section.sh_name == '.text':
                idx_text = i
                cur_section.sh_name = self._get_shstrtab_offset(b'.text\0')     # 这里sh_name换回来
                next_section = self.sectionHeaderTable[i+1]
                cur_section.sh_size = next_section.sh_addr - cur_section.sh_addr
        # fix sh_link
        for i in range(len(self.sectionHeaderTable)):
            cur_section = self.sectionHeaderTable[i]
            if cur_section.sh_type == elf.SHT_SYMTAB:
                cur_section.sh_link = idx_dynstr
            elif cur_section.sh_type == elf.SHT_HASH:
                cur_section.sh_link = idx_dynsym
            elif cur_section.sh_type == elf.SHT_REL:
                cur_section.sh_link = idx_dynsym
            elif cur_section.sh_type == elf.SHT_LOPROC + 1:
                cur_section.sh_link = idx_text
            elif cur_section.sh_type == elf.SHT_DYNAMIC:
                cur_section.sh_link = idx_dynstr
        # .data
        if self.last_PT_load is not None:
            if self.elfHeader.e_ident.ei_class == 0x1:
                dt_data = elf.Elf32_Shdr()
                dt_data.sh_addralign = 4
            else:
                dt_data = elf.Elf64_Shdr()
                dt_data.sh_addralign = 8
            dt_data.sh_name = self._get_shstrtab_offset(b".data\0")
            dt_data.sh_type = elf.SHT_PROGBITS
            dt_data.sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC
            last_section = self.sectionHeaderTable[-1]
            dt_data.sh_addr = last_section.sh_addr + last_section.sh_size
            dt_data.sh_offset = dt_data.sh_addr
            dt_data.sh_size = self.last_PT_load.p_vaddr + self.last_PT_load.p_memsz - dt_data.sh_addr
            dt_data.sh_link = 0
            dt_data.sh_info = 0
            dt_data.sh_entsize = 0
            self.sectionHeaderTable.append(dt_data)
        # .shstrtab
        if self.elfHeader.e_ident.ei_class == 0x1:
            dt_shstrtab = elf.Elf32_Shdr()
        else:
            dt_shstrtab = elf.Elf64_Shdr()
        dt_shstrtab.sh_name = self._get_shstrtab_offset(b".data\0")
        dt_shstrtab.sh_type = elf.SHT_STRTAB
        dt_shstrtab.sh_flags = elf.SHT_NULL
        dt_shstrtab.sh_addr = self.last_PT_load.p_vaddr + self.last_PT_load.p_memsz
        dt_shstrtab.sh_offset = dt_shstrtab.sh_addr
        dt_shstrtab.sh_size = len(self.shstr)
        dt_shstrtab.sh_link = 0
        dt_shstrtab.sh_info = 0
        dt_shstrtab.sh_addralign = 1
        dt_shstrtab.sh_entsize = 0
        self.sectionHeaderTable.append(dt_shstrtab)

        print("[Info] Fix section header table finish.")

    def _fix_reloc(self):
        if self.elfHeader.e_ident.ei_class == 0x1:
            rel_addr = self.soinfo.rel
            rel_count = int(self.soinfo.rel_size / 8)
            plt_rel_addr = self.soinfo.plt_rel
            plt_rel_count = self.soinfo.plt_rel_size / 8
        else:
            rel_addr = self.soinfo.rela
            rel_count = self.soinfo.rel_size / 16
            plt_rel_addr = self.soinfo.plt_rela
            plt_rel_count = self.soinfo.plt_rel_size / 16

        self.raw_buf.seek(rel_addr)
        for i in range(rel_count):
            if self.elfHeader.e_ident.ei_class == 0x1:
                cur_rel = elf.Elf32_Rel()
                cur_rel.r_offset = int.from_bytes(self.raw_buf.read(4), "little")
                cur_rel.r_info = int.from_bytes(self.raw_buf.read(4), "little")

        print("[Info] Fix relocation finish.")

    def load(self, path):
        self.raw_buf = open(path, 'rb')
        self._load_elf_header()
        self._load_program_header_table()
        self._fix_program_header_table()
        self._read_soinfo()
        self._rebuild_section_header_table()
        self._fix_section_header_table()
        # self._fix_reloc()

    def dump(self):
        load_size = self.last_PT_load.p_vaddr + self.last_PT_load.p_memsz
        self.raw_buf.seek(0)
        out_buffer = self.raw_buf.read()
        out_buffer = list(out_buffer)[0: load_size]

        out_buffer += list(self.shstr)

        sh_offset = len(out_buffer)
        sh_buf = b""
        for sh in self.sectionHeaderTable:
            sh_buf += sh.dump()
        out_buffer += list(sh_buf)
        self._fix_elf_header(sh_offset)  # 修复ELF Header
        elf_header_buf = self.elfHeader.dump()
        elf_header_sz = len(elf_header_buf)
        out_buffer[0: elf_header_sz] = list(elf_header_buf)

        ph_buf = b""
        for pb in self.programHeaderTable:
            ph_buf += pb.dump()
        ph_buf_sz = len(ph_buf)
        out_buffer[elf_header_sz: ph_buf_sz] = list(ph_buf)

        print("[Info] Generate new so buffer finish.")
        return bytes(out_buffer)


def fix_so(so_path, output_path):
    elf_fixer = ELF()
    elf_fixer.load(so_path)
    fix_data = elf_fixer.dump()
    with open(output_path, "wb") as f:
        f.write(fix_data)
    print("[Info] Fix finish.")


if __name__ == '__main__':
    parser = optparse.OptionParser(usage="usage: %prog -i input.so -o output_path")
    parser.add_option("-i", "--inputfile", help="input so file")
    parser.add_option("-o", "--outputfile", help="output so file")

    args = parser.parse_args()[0]
    fix_so(args.inputfile, args.outputfile)
