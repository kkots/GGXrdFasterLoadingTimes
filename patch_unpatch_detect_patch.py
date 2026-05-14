import os
import struct

class Section:
    def __init__(self, name, start_rva, start_raw, raw_size):
        self.name = name
        self.start_rva = start_rva
        self.start_raw = start_raw
        self.raw_size = raw_size
    
    def __repr__(self):
        return f"({self.name.decode('utf-8')}; RVA: {self.start_rva:#x}; RAW: {self.start_raw:#x}; SIZE: {self.raw_size:#x})"

class RelocWrite:
    def __init__(self, pos, size):  # data supposed to be in reloc_table.reloc_table
        self.pos = pos  # raw file position
        self.size = size  # amount of written data
    def __repr__(self):
        return f"(POS: {self.pos:#x}; SIZE: {self.size:#x})"

class FoundReloc:
    def __init__(self, reloc_type, region_va, reloc_va):
        self.reloc_type = reloc_type  # see IMAGE_REL_BASED_
        self.region_va = region_va  # position of the place that the reloc is patching
        self.reloc_va = reloc_va  # position of the reloc entry itself
    def __repr__(self):
        return f"(TYPE: {self.reloc_type}; REGION_VA: {self.region_va:#x}; RELOC_VA: {self.reloc_va:#x})"

class FoundRelocBlock:
    def __init__(self, reloc_block_file_pos, page_base_va, reloc_block_va, size):
        self.reloc_block_file_pos = reloc_block_file_pos  # points to the page base member of the block
        self.page_base_va = page_base_va  # page base of all patches that the reloc is responsible for
        self.reloc_block_va = reloc_block_va  # position of the reloc block itself. Points to the page base member of the block
        self.size = size  # size of the entire block, including the page base and block size and all entries
    def __repr__(self):
        return f"(BLOCK_FILE_POS: {self.reloc_block_file_pos:#x}; PAGE_BASE_VA: {self.page_base_va:#x}; RELOC_BLOCK_VA: {self.reloc_block_va:#x}; SIZE: {self.size:#x})"

# returns list[Section]
def read_sections(f):
    sections = []
    if not isinstance(f, bytes) and not isinstance(f, bytearray):
        f.seek(0)
        if f.read(2) != b'MZ':
            raise Exception("Not a valid EXE.")
        f.seek(0x3c)
        nt_header_off = struct.unpack("<I", f.read(4))[0]
        f.seek(nt_header_off)
        if f.read(4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
        
        f.seek(nt_header_off + 6)
        num_sections = struct.unpack("<H", f.read(2))[0]
        f.seek(nt_header_off + 0x14)
        size_of_optional_header = struct.unpack("<H", f.read(2))[0]
        section_header_off = nt_header_off + 0x18 + size_of_optional_header
        for section_ind in range(0, num_sections):
            f.seek(section_header_off)
            section_name = f.read(8)
            section_name_length = 0
            for i in range(0, len(section_name)):
                byte_value = section_name[i]
                if byte_value == 0:
                    break
                section_name_length += 1
            section_name_truncated = section_name[0:section_name_length]
            f.seek(section_header_off + 0xc)
            section_rva = struct.unpack("<I", f.read(4))[0]
            f.seek(section_header_off + 0x10)
            section_raw_size = struct.unpack("<I", f.read(4))[0]
            f.seek(section_header_off + 0x14)
            section_raw = struct.unpack("<I", f.read(4))[0]
            new_section = Section(section_name_truncated, section_rva, section_raw, section_raw_size)
            sections.append(new_section)
            section_header_off += 0x28
    else:
        def vread(pos, size):
            return f[pos:pos + size]
            
        if vread(0,2) != b'MZ':
            raise Exception("Not a valid EXE.")
        nt_header_off = struct.unpack("<I", vread(0x3c, 4))[0]
        if vread(nt_header_off, 4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
        
        num_sections = struct.unpack("<H", vread(nt_header_off + 6, 2))[0]
        size_of_optional_header = struct.unpack("<H", vread(nt_header_off + 0x14, 2))[0]
        section_header_off = nt_header_off + 0x18 + size_of_optional_header
        for section_ind in range(0, num_sections):
            section_name_length = 0
            for i in range(0, 8):
                byte_value = f[section_header_off + i]
                if byte_value == 0:
                    break
                section_name_length += 1
            section_name_truncated = vread(section_header_off, section_name_length)
            section_rva = struct.unpack("<I", vread(section_header_off + 0xc, 4))[0]
            section_raw_size = struct.unpack("<I", vread(section_header_off + 0x10, 4))[0]
            section_raw = struct.unpack("<I", vread(section_header_off + 0x14, 4))[0]
            new_section = Section(section_name_truncated, section_rva, section_raw, section_raw_size)
            sections.append(new_section)
            section_header_off += 0x28
    return sections

def find_section(sections, name):
    for section in sections:
        if section.name == name:
            return section
    return None

class RelocTable:
    
    IMAGE_REL_BASED_ABSOLUTE = 0
    IMAGE_REL_BASED_HIGH = 1
    IMAGE_REL_BASED_LOW = 2
    IMAGE_REL_BASED_HIGHLOW = 3
    IMAGE_REL_BASED_HIGHADJ = 4
    IMAGE_REL_BASED_DIR64 = 10
    
    def populate_from_file(self, f):
        f.seek(0)
        if f.read(2) != b'MZ':
            raise Exception("Not a valid EXE.")
        f.seek(0x3c)
        nt_header_off = struct.unpack("<I", f.read(4))[0]
        f.seek(nt_header_off)
        if f.read(4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
            
        f.seek(nt_header_off + 0x34)
        self.image_base = struct.unpack("<I", f.read(4))[0]
        
        reloc_section = find_section(read_sections(f), b".reloc")
        if reloc_section is None:
            raise Exception(".reloc section not found.")
        
        reloc_section_header = nt_header_off + 0xa0
        f.seek(reloc_section_header)
        reloc_rva = struct.unpack("<I", f.read(4))[0]
        self.where_size = reloc_section_header + 4
        self.size = struct.unpack("<I", f.read(4))[0]
        self.va = reloc_rva + self.image_base
        self.raw = reloc_section.start_raw
        self.reloc_table = bytearray(reloc_section.raw_size)
        f.seek(self.raw)
        f.readinto(self.reloc_table)
        self.reloc_writes = []  # list[RelocWrite]
        
    def populate_from_buffer(self, buffer):
        def vread(pos, size):
            return buffer[pos:pos + size]
            
        if vread(0, 2) != b'MZ':
            raise Exception("Not a valid EXE.")
        nt_header_off = struct.unpack("<I", vread(0x3c, 4))[0]
        if vread(nt_header_off, 4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
            
        reloc_section = find_section(read_sections(buffer), b".reloc")
        if reloc_section is None:
            raise Exception(".reloc section not found.")
            
        self.image_base = struct.unpack("<I", vread(nt_header_off + 0x34, 4))[0]
        reloc_section_header = nt_header_off + 0xa0
        reloc_rva = struct.unpack("<I", vread(reloc_section_header, 4))[0]
        self.where_size = reloc_section_header + 4
        self.size = struct.unpack("<I", vread(reloc_section_header + 4, 4))[0]
        self.va = reloc_rva + self.image_base
        self.raw = reloc_section.start_raw
        self.reloc_table = bytearray(vread(self.raw, reloc_section.raw_size))
        self.reloc_writes = []  # list[RelocWrite]
        
    # start_file_raw_pos is absolute raw file pos.
    def write(self, start_file_raw_pos, bytes_to_write):
        self.reloc_table[start_file_raw_pos - self.raw : start_file_raw_pos - self.raw + len(bytes_to_write)] = bytes_to_write
        self.reloc_writes.append(
            RelocWrite(start_file_raw_pos, len(bytes_to_write))
        )
        
    # region specified in Virtual Address space
    def find_relocs_in_region(self, region_start, region_end):
        result = []  # list[FoundReloc]
        reloc_table_size_remaining = self.size
        reloc_table_pos = 0
        region_start_rva = region_start - self.image_base
        region_end_rva = region_end - self.image_base
        while reloc_table_size_remaining > 0:
            page_base_rva = struct.unpack("<I", self.reloc_table[reloc_table_pos : reloc_table_pos + 4])[0]
            block_size = struct.unpack("<I", self.reloc_table[reloc_table_pos + 4 : reloc_table_pos + 8])[0]
            if block_size == 0:
                block_size = 8
            reloc_table_size_remaining -= block_size
            reloc_table_pos += block_size
            
            if (page_base_rva | 0xFFF) + 8 >= region_start_rva and page_base_rva < region_end_rva:
                entry_pos = reloc_table_pos - block_size + 8
                block_size_remaining = block_size - 8
                while block_size_remaining > 0:
                    entry = struct.unpack("<H", self.reloc_table[entry_pos : entry_pos + 2])[0]
                    reloc_type = entry >> 12
                    entry_size = 4 if reloc_type == RelocTable.IMAGE_REL_BASED_HIGHADJ else 2
                    entry_pos += entry_size
                    block_size_remaining -= entry_size
                    if reloc_type == RelocTable.IMAGE_REL_BASED_ABSOLUTE:
                        continue
                    patch_va = (page_base_rva | (entry & 0xFFF)) + self.image_base
                    patch_size = 4
                    if reloc_type == RelocTable.IMAGE_REL_BASED_HIGH:
                        patch_va += 2
                        patch_size = 2
                    elif reloc_type in (RelocTable.IMAGE_REL_BASED_LOW, RelocTable.IMAGE_REL_BASED_HIGHADJ):
                        patch_size = 2
                    elif reloc_type == RelocTable.IMAGE_REL_BASED_DIR64:
                        patch_size = 8
                    if patch_va >= region_end or patch_va + patch_size < region_start:
                        continue
                    result.append(FoundReloc(reloc_type, patch_va, entry_pos + self.va - entry_size))
        return result
    
    # Returns list[FoundReloc]
    # If the returned list would be empty, returns a FoundRelocBlock instead with information about the last block.
    def find_reusable_reloc_entries(self, va_to_patch):
        result = []  # list[FoundReloc]
        rva_to_patch = va_to_patch - self.image_base
        reloc_table_size_remaining = self.size
        reloc_table_pos_next = 0
        while reloc_table_size_remaining > 0:
            reloc_table_pos = reloc_table_pos_next
            block_size = struct.unpack("<I", self.reloc_table[reloc_table_pos + 4 : reloc_table_pos + 8])[0]
            if block_size == 0:
                block_size = 8
            reloc_table_pos_next += block_size
            reloc_table_size_remaining -= block_size
            page_base_rva = struct.unpack("<I", self.reloc_table[reloc_table_pos : reloc_table_pos + 4])[0]
            if rva_to_patch >= page_base_rva and rva_to_patch <= (page_base_rva | 0xFFF):
                entry_pos = reloc_table_pos + 8
                block_size_remaining = block_size - 8
                while block_size_remaining > 0:
                    entry = struct.unpack("<H", self.reloc_table[entry_pos : entry_pos + 2])[0]
                    reloc_type = entry >> 12
                    if reloc_type == RelocTable.IMAGE_REL_BASED_ABSOLUTE:
                        result.append(FoundReloc(
                            RelocTable.IMAGE_REL_BASED_ABSOLUTE,
                            (page_base_rva | (entry & 0xFFF)) + self.image_base,
                            entry_pos + self.va
                        ))
                    entry_size = 4 if reloc_type == RelocTable.IMAGE_REL_BASED_HIGHADJ else 2
                    entry_pos += entry_size
                    block_size_remaining -= entry_size
        if not result:
            if reloc_table_pos_next == 0:
                return None
            return FoundRelocBlock(
                reloc_table_pos + self.raw,
                struct.unpack("<I", self.reloc_table[reloc_table_pos : reloc_table_pos + 4])[0] + self.image_base,
                reloc_table_pos + self.va,
                struct.unpack("<I", self.reloc_table[reloc_table_pos + 4 : reloc_table_pos + 8])[0]
            )
        return result
        
    def increase_size_by(self, n):
        if n == 0:
            return
        self.size = (self.size + 3) & ~3
        self.size += n
        self.size = (self.size + 3) & ~3
        
    def commit_all_writes(self, f):
        if RelocTable.debug:
            print(f"Committing {self.size:#x} reloc table size and {len(self.reloc_writes)} writes.")
        f.seek(self.where_size)
        f.write(struct.pack("<I", self.size))
        for write_elem in self.reloc_writes:
            f.seek(write_elem.pos)
            f.write(self.reloc_table[write_elem.pos - self.raw : write_elem.pos - self.raw + write_elem.size])
        self.reloc_writes.clear()
        
    # Try to:
    # 1) Reuse an existing 0000 entry that has a page base from which we can reach the target;
    # 2) Try to expand the last block if the target is reachable from its page base;
    # 3) Add a new block to the end of the table with that one entry.
    def add_entry(self, va_to_patch):
        rva_to_patch = va_to_patch - self.image_base
        new_entry_short = (RelocTable.IMAGE_REL_BASED_HIGHLOW << 12) | (rva_to_patch & 0xFFF)
        reusable_entries = self.find_reusable_reloc_entries(va_to_patch)
        if isinstance(reusable_entries, list):
            first_reloc = reusable_entries[0]
            if RelocTable.debug:
                print(f"Reusing entry {first_reloc} for VA {va_to_patch:#x}")
            self.write(first_reloc.reloc_va - self.va + self.raw, struct.pack("<H", new_entry_short))
            return
        
        # try to expand the last block if it has appropriate page base
        last_block = reusable_entries
        if last_block is not None and va_to_patch >= last_block.page_base_va and va_to_patch <= (last_block.page_base_va | 0xFFF):
            new_size = last_block.size + 2
            new_size = (new_size + 3) & ~3
            
            size_increase = new_size - last_block.size
            
            if RelocTable.debug:
                print(f"Expanding last reloc block for VA {va_to_patch:#x} by {size_increase}.")
            
            self.size = (self.size + 3) & ~3
            whole_reloc_table_size_diff = (last_block.reloc_block_file_pos - self.raw + new_size) - self.size
            if whole_reloc_table_size_diff > 0:
                if RelocTable.debug:
                    print(f"Expanding whole reloc table size by {whole_reloc_table_size_diff}")
                self.increase_size_by(whole_reloc_table_size_diff)
            
            self.write(last_block.reloc_block_file_pos + 4, struct.pack("<I", new_size))
            self.write(last_block.reloc_block_file_pos + last_block.size, struct.pack("<H", new_entry_short))
            
            if size_increase > 2:
                self.write(last_block.reloc_block_file_pos + last_block.size + 2, b"\x00\x00")
            return
            
        # add a new block with one entry to the end of the reloc table
        if RelocTable.debug:
            print(f"Adding a new reloc block with one entry for VA: {va_to_patch:#x}")
        self.size = (self.size + 3) & ~3
        old_table_size = self.size
        self.increase_size_by(12)
        
        new_reloc_page_base = rva_to_patch & 0xFFFFF000
        
        new_bytes = bytearray(12)
        new_bytes[0:4] = struct.pack("<I", new_reloc_page_base)
        new_bytes[4:8] = struct.pack("<I", 12)
        new_bytes[8:10] = struct.pack("<H", new_entry_short)
        # 10:12 already zeros
        
        self.write(self.raw + old_table_size, new_bytes)
        
    def remove_entry(self, reloc: FoundReloc):
        if RelocTable.debug:
            print("Removing entry", str(reloc))
        self.write(reloc.reloc_va - self.va + self.raw, b"\x00\x00")
        
    def remove_entries(self, relocs: list[FoundReloc]):
        for reloc in relocs:
            self.remove_entry(reloc)

# There're a bunch of versions of the patcher.
# First version only made loading synchronous.
# Second version added automash through the loading screen.
# Third version sped up the bootup time and added an option to skip intro cutscenes and included a patch for daylight saving INI reset.
# This will detect if the latest version was applied, as it has some non-optional (mandatory) patches that get applied that are not present in the earlier versions.
def detect_patched(guilty_gear_xrd_exe_path):
    with open(guilty_gear_xrd_exe_path, "rb") as f:
        f.seek(0xaff080)  # position of REDGfxMoviePlayer_MenuInterlude::execIsAsyncLoading in Guilty Gear Xrd Rev 2 version 2211
        func_start = f.read(5)
        if (func_start != b"\x8B\x44\x24\x04\x56"   # the no mash version
                and func_start != b"\x56\x57\x8B\x7C\x24"):  # the mash version
            return False
        f.seek(0x15e00ec)  # position of amountOfTimeToWasteOnInitialMenus variable in Guilty Gear Xrd Rev 2 version 2211
        current_val = struct.unpack("<i", f.read(4))[0]
        if current_val == 90:
            return False  # not the latest version. Latest version would've set it to 0
        return True
        
# Raises exception if the file is invalid.
# Returns a 'str' object if patching failed, the 'str' will contain the reason why.
# Returns True if patching succeeded.
# Does not create a backup copy, modifies the file right away.
# intro_movies_skip_mode possible values:
#    "skippable_by_pressing_enter"
#    "skip_automatically"
#    "dont_change_anything"
# fix_bug_that_causes_ini_file_to_reset_twice_a_year_in_countries_with_daylight_saving: True/False, suggested if intro_movies_skip_mode is "skippable_by_pressing_enter", because that approach requires editing an INI, and if you don't fix the bug the INI will reset when daylight saving changes to regular time or vice versa.
def patch(guilty_gear_xrd_exe_path, automash, intro_movies_skip_mode, fix_bug_that_causes_ini_file_to_reset_twice_a_year_in_countries_with_daylight_saving):
    debug = False
    RelocTable.debug = debug
    
    if intro_movies_skip_mode not in (
            "skippable_by_pressing_enter",
            "skip_automatically",
            "dont_change_anything"):
        raise Exception(f"Invalid value for intro_movies_skip_mode: {intro_movies_skip_mode}")
        
    with open(guilty_gear_xrd_exe_path, "r+b") as f:
        if f.read(2) != b'MZ':
            raise Exception("Not a valid EXE.")
        f.seek(0x3c)
        nt_header_off = struct.unpack("<I", f.read(4))[0]
        f.seek(nt_header_off)
        if f.read(4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
        
        f.seek(nt_header_off + 0x34)
        image_base = struct.unpack("<I", f.read(4))[0]
        if debug:
            print(f"Image Base {image_base:#x}")
        
        sections = read_sections(f)
        
        def raw_to_rva(raw_addr):
            for section in reversed(sections):
                if raw_addr >= section.start_raw:
                    return raw_addr - section.start_raw + section.start_rva
            return 0
        
        def rva_to_raw(rva_addr):
            for section in reversed(sections):
                if rva_addr >= section.start_rva:
                    return rva_addr - section.start_rva + section.start_raw
            return 0
        
        def raw_to_va(raw_addr):
            return raw_to_rva(raw_addr) + image_base
        
        def va_to_raw(va_addr):
            return rva_to_raw(va_addr - image_base)
        
        text_section = None
        rdata_section = None
        data_section = None
        reloc_section = None
        
        for section in sections:
            if section.name == b".text":
                text_section = section
            elif section.name == b".rdata":
                rdata_section = section
            elif section.name == b".data":
                data_section = section
            elif section.name == b".reloc":
                reloc_section = section
        
        if debug:
            print("Sections:")
            for section in sections:
                print(section.__str__())
            print("")
        
        if text_section is None:
            raise Exception(".text section not found.")
        if rdata_section is None:
            raise Exception(".rdata section not found.")
        if data_section is None:
            raise Exception(".data section not found.")
        if reloc_section is None:
            raise Exception(".reloc section not found.")
        
        f.seek(0)
        whole_file = f.read()  # for faster sigscanning
        
        def pattern_to_sigmask(pattern):
            sig = bytearray()
            mask = bytearray()
            wildcard = False
            accum = 0
            accum_count = 0
            
            def on_end():
                accum_local = accum
                accum_count_local = accum_count
                if accum_count_local == 0:
                    return
                    
                if wildcard:
                    accum_count_rounded_up = (accum_count_local + 1) & ~1
                    accum_count_half = accum_count_rounded_up >> 1
                    for accum_count_index in range(0, accum_count_half):
                        sig.append(0)
                        mask.append(ord('?'))
                    return
                    
                while accum_count_local > 0:
                    next_byte = accum_local & 0xFF
                    accum_local = (accum_local >> 8) & 0x00FFFFFF
                    accum_count_local -= 2
                    sig.append(next_byte)
                    mask.append(ord('x'))
                    
            for c in pattern:
                if c == '?':
                    wildcard = True
                    accum_count += 1
                    if accum_count > 8:
                        raise Exception("Wrong pattern: " + pattern)
                elif c == ' ':
                    on_end()
                    wildcard = False
                    accum_count = 0
                    accum = 0
                elif wildcard:
                    raise Exception("Wrong pattern: " + pattern)
                else:
                    if c >= '0' and c <= '9':
                        val = ord(c) - ord('0')
                    elif c >= 'a' and c <= 'f':
                        val = ord(c) - ord('a') + 10
                    elif c >= 'A' and c <= 'F':
                        val = ord(c) - ord('A') + 10
                    else:
                        raise Exception("Wrong pattern: " + pattern)
                    accum = (accum << 4) | val
                    accum_count += 1
                    if accum > 0xFFFFFFFF or accum < -0x80000000 or accum_count > 8:
                        raise Exception("Wrong pattern: " + pattern)
            on_end()
            return (sig, mask)
        
        def sigmask_to_pattern(sig, mask):
            str_array = []
            for i in range(0, len(sig)):
                if mask[i] == ord('?'):
                    str_array.append("??")
                else:
                    hex_str = hex(sig[i])[2:]
                    if len(hex_str) == 1:
                        hex_str = "0" + hex_str
                    str_array.append(hex_str)
            return " ".join(str_array)
            
        
        def sigscan_backwards(sig, mask, start_low_pos, end_high_pos_inclusive, *, every_0x10 = False):
            if mask is None:
                mask = b'x' * len(sig)
            if isinstance(sig, str):
                sig = bytes(ord(x) for x in sig)
            if isinstance(mask, str):
                mask = bytes(ord(x) for x in mask)
            if every_0x10:
                start_low_pos = (start_low_pos + 0xf) & ~0xf
                end_high_pos_inclusive = end_high_pos_inclusive & ~0xf
                rg = range(start_low_pos, end_high_pos_inclusive + 0x10, 0x10)
            else:
                rg = range(start_low_pos, end_high_pos_inclusive + 1)
            sig_rg = range(0, len(sig))
            for file_pos in reversed(rg):
                failed = False
                for char_index in sig_rg:
                    sig_char = sig[char_index]
                    mask_char = mask[char_index]
                    byte_value = whole_file[file_pos + char_index]
                    if mask_char != ord('?') and byte_value != sig_char:
                        failed = True
                        break
                if not failed:
                    return file_pos
            return -1
            
        def sigscan_backwardsp(pattern, start_low_pos, end_high_pos_inclusive, *, every_0x10 = False):
            sig, mask = pattern_to_sigmask(pattern)
            return sigscan_backwards(sig, mask, start_low_pos, end_high_pos_inclusive, every_0x10 = every_0x10)
        
        # mask is a string of 'x' and '?' characters, 'x' meaning the corresponding character from the sig must match
        # a character in whole_file, '?' meaning any character is ok and that corresponding character is skipped.
        # mask and sig must be of equal lengths.
        # If mask is None, that implies it is same length as sig and is all 'x'.
        # start_pos is from where to begin search, as a raw file pos.
        # end_pos is up to what point, non-inclusive, to continue searching; do not subtract sig length from end_pos,
        # the sigscan function will do that for you.
        # If start_pos is a Section, searching will occur in that section.
        # every_4 means the sig must start on a 4-byte boundary.
        # Returns -1 if not found.
        # Returns file (raw) position if found.
        def sigscan(sig, mask, start_pos, end_pos = None, *, every_4 = False):
            if isinstance(start_pos, Section):
                end_pos = start_pos.start_raw + start_pos.raw_size
                start_pos = start_pos.start_raw
                
            if isinstance(sig, str):
                sig = bytes(ord(x) for x in sig)
            if isinstance(mask, str):
                mask = bytes(ord(x) for x in mask)
                
            if not isinstance(sig, bytearray) and not isinstance(sig, bytes):
                raise Exception("sig isn't a bytearray or bytes: " + str(type(sig)))
            if not isinstance(mask, bytearray) and not isinstance(mask, bytes) and mask is not None:
                raise Exception("mask isn't a bytearray or bytes: " + str(type(mask)))
                
            if end_pos is None:
                raise Exception("end_pos is None")
                
            if mask is not None and len(sig) != len(mask):
                raise Exception("sig length mismatches mask length: sig: " + str(sig) + ", mask: " + str(mask))
                
            if every_4:
                start_pos = (start_pos + 3) & ~3
                end_pos = end_pos & ~3
                
            sig_len = len(sig)
            
            if mask is None or ord('?') not in mask:
                end_pos -= sig_len
                if every_4:
                    end_pos = end_pos & ~3
                    
                file_pos = start_pos
                
                while file_pos <= end_pos:
                    file_pos = whole_file.find(sig, file_pos, end_pos + 1)
                    if file_pos == -1:
                        return -1
                    if not every_4 or every_4 and (file_pos & 3) == 0:
                        return file_pos
                    file_pos += 1
                return -1
                
            # normal sigscan
            if every_4:
                rg = range(start_pos, end_pos - sig_len + 1, 4)
            else:
                rg = range(start_pos, end_pos - sig_len + 1)
                
            sig_start = 0
            for mask_char in mask:
                if mask != ord('?'):
                    break
                sig_start += 1
            
            sig_end = len(sig)
            for mask_char_index in range(sig_start, len(sig)):
                if mask[mask_char_index] == ord('?'):
                    sig_end = mask_char_index
                    break
            sig_piece = sig[sig_start : sig_end]
            
            sig_rg = range(0, len(sig))
            file_pos = start_pos
            search_end = end_pos - sig_len + 1
            while file_pos < search_end:
                file_pos = whole_file.find(sig_piece, file_pos, search_end)
                if file_pos == -1:
                    return -1
                file_pos -= sig_start
                if not every_4 or every_4 and (file_pos & 3) == 0:
                    failed = False
                    for char_index in sig_rg:
                        sig_char = sig[char_index]
                        mask_char = mask[char_index]
                        byte_value = whole_file[file_pos + char_index]
                        if mask_char != ord('?') and byte_value != sig_char:
                            failed = True
                            break
                    if not failed:
                        return file_pos
                file_pos += sig_start + 1
            return -1
        
        # Example pattern: "ff 15 ?? ?? ?? ??" (string)
        # Each ?? byte gets converted to a '?' mask char and a '\x00' sig byte.
        # Each non-?? byte gets converted to a 'x' mask char and that byte in sig.
        # See sigscan for the rest of the information.
        def sigscanp(pattern, start_pos, end_pos = None, *, every_4 = False):
            sig, mask = pattern_to_sigmask(pattern)
            return sigscan(sig, mask, start_pos, end_pos, every_4 = every_4)
            
        # returns VA of the start of the function
        def find_exec(name):
            pos = sigscan(name + "\x00", None, rdata_section)
            if pos == -1:
                return -1
            pos_va = raw_to_va(pos)
            string_mention = sigscan(struct.pack("<I", pos_va), None, data_section, every_4 = True)
            if string_mention == -1:
                return -1
            return struct.unpack("<I", whole_file[string_mention + 4 : string_mention + 8])[0]
            
        execIsAsyncLoading_va = find_exec("UREDGfxMoviePlayer_MenuInterludeexecIsAsyncLoading")
        if execIsAsyncLoading_va == -1:
            return "UREDGfxMoviePlayer_MenuInterludeexecIsAsyncLoading not found."
        execIsAsyncLoading_raw = va_to_raw(execIsAsyncLoading_va)
        if debug:
            print(f"execIsAsyncLoading_raw: {execIsAsyncLoading_raw:#x}")
        
        GNatives_EX_DebugInfo_pos = sigscan(b"\xff\x15", None, execIsAsyncLoading_raw, execIsAsyncLoading_raw + 0x40)
        if GNatives_EX_DebugInfo_pos != -1:
            GNatives_EX_DebugInfo_pos += 2
        else:
            another_GNatives_EX_DebugInfo_sig = b"\x8b\x46\x18\x80\x38\x41\x75\x10\x8b\x4e\x14\x6a\x00\x40\x56\x89\x46\x18\xff\x15"
            GNatives_EX_DebugInfo_pos = sigscan(another_GNatives_EX_DebugInfo_sig, None, text_section)
            if GNatives_EX_DebugInfo_pos == -1:
                return "Failed to find GNatives[EX_DebugInfo]."
            GNatives_EX_DebugInfo_pos += len(another_GNatives_EX_DebugInfo_sig)
        
        GNatives_EX_DebugInfo_va = struct.unpack("<I", whole_file[GNatives_EX_DebugInfo_pos : GNatives_EX_DebugInfo_pos + 4])[0]
        if debug:
            print(f"GNatives_EX_DebugInfo_va: {GNatives_EX_DebugInfo_va:#x}")
        
        execLoadAssets_va = find_exec("UREDCharaAssetLoaderexecLoadAssets")
        if execLoadAssets_va == -1:
            return "UREDCharaAssetLoaderexecLoadAssets not found."
        if debug:
            print(f"execLoadAssets_va: {execLoadAssets_va:#x}")
        execLoadAssets_raw = va_to_raw(execLoadAssets_va)
        LoadAssets_call_place_raw = sigscan(b"\x8b\xcb\xe8", None, execLoadAssets_raw, execLoadAssets_raw + 0x130)
        if LoadAssets_call_place_raw == -1:
            return "Couldn't find LoadAssets calling place."
        LoadAssets_call_place_raw += 2
        LoadAssets_va = raw_to_va(LoadAssets_call_place_raw) + 5 + struct.unpack("<i", whole_file[
            LoadAssets_call_place_raw + 1 :
            LoadAssets_call_place_raw + 5])[0]
        if debug:
            print(f"LoadAssets_va: {LoadAssets_va:#x}")
        LoadAssets_raw = va_to_raw(LoadAssets_va)
        jmp_already_noped_out = False
        jmp_pos = sigscan(b"\x39\x5c\x24\x48\x74\x16", None, LoadAssets_raw, LoadAssets_raw + 0x1b0)
        if jmp_pos == -1:
            jmp_pos = sigscan(b"\x39\x5c\x24\x48\x90\x90", None, LoadAssets_raw, LoadAssets_raw + 0x1b0)
            if jmp_pos == -1:
                return "Couldn't find 'if (bBlocking != 0) {' instruction in LoadAssets."
            jmp_already_noped_out = True
            if debug:
                print("Jump already noped out.")
        jmp_pos += 4
        if debug:
            print(f"jmp_pos (raw): {jmp_pos:#x}")
        
        if automash:
            FName_Init_middle_pos = sigscanp("8b 46 08 d1 f8 83 7c 24 ?? 02 89 07 0f 85 ?? ?? ?? ?? f6 46 08 01",
                text_section)
            if FName_Init_middle_pos == -1:
                return "Couldn't find FName::Init(const ANSICHAR* InName, INT InNumber, EFindName FindType)"
            FName_Init_start_pos = sigscan_backwards("\x51\x55\x57\x8b\xf9", None,
                FName_Init_middle_pos - 0x230, FName_Init_middle_pos, every_0x10 = True)
            if FName_Init_start_pos == -1:
                return "Couldn't find the start of FName::Init(const ANSICHAR* InName, INT InNumber, EFindName FindType)"
            FName_Init_va = raw_to_va(FName_Init_start_pos)
            if debug:
                print(f"FName_Init_va: {FName_Init_va:#x}")
            
            FName_Compare_middle_pos = sigscan("\x8b\x34\x82\x8b\x04\x8a\x8b\x48\x08\x8b\x56\x08\x83\xe1\x01\x83\xe2\x01\x3b\xd1", None,
                text_section)
            if FName_Compare_middle_pos == -1:
                return "Couldn't find FName::Compare"
            FName_Compare_start_pos = sigscan_backwardsp("6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 81 ec ?? ?? ?? ??",
                FName_Compare_middle_pos - 0x193, FName_Compare_middle_pos, every_0x10 = True)
            if FName_Compare_start_pos == -1:
                return "Couldn't find the start of FName::Compare"
            FName_Compare_va = raw_to_va(FName_Compare_start_pos)
            if debug:
                print(f"FName_Compare_va: {FName_Compare_va:#x}")
            
        write_buf_no_mash = bytearray(
            b"\x8B\x44\x24\x04"         # MOV EAX,dword [ESP+0x4]  ; this argument is an FFrame* and is called Stack in UE3 source code
            b"\x56"                     # PUSH ESI
            b"\x89\xCE"                 # MOV ESI,ECX
            b"\xFF\x40\x18"             # INC dword [EAX+0x18]  ; increment stack->Code
            b"\x8b\x48\x18"             # MOV ECX,dword ptr [EAX + 0x18]  ; read stack->Code
            b"\x80\x39\x41"             # CMP byte ptr [ECX],0x41  ; compare *stack->Code to EX_DebugInfo
            b"\x75\x14"                 # JNZ not_EX_DebugInfo
            b"\x41"                     # INC ECX
            b"\x6a\x00"                 # PUSH 0
            b"\x89\x48\x18"             # MOV dword ptr [EAX + 0x18],ECX
            b"\x8b\x48\x14"             # MOV ECX,dword ptr [EAX + 0x14]  # stack->Object
            b"\x50"                     # PUSH EAX
            b"\xff\x15\x00\x00\x00\x00" # CALL dword ptr [GNatives[0x41]]  ; call GNatives[EX_DebugInfo]. We'll write the address soon
            b"\x8B\x44\x24\x08"         # MOV EAX,dword [ESP+0x8]
            # not_EX_DebugInfo
            b"\x8B\x48\x1C"             # MOV ECX,dword [EAX+0x1c]  ; this is stack->Locals, it stores function arguments and local variables of the unrealscript
            b"\x31\xD2"                 # XOR EDX,EDX
            b"\x42"                     # INC EDX
            b"\x8B\x41\x04"             # MOV EAX,dword [ECX+0x4]  ; The first value is always bTrigger, a function argument. The second could either be a TArray (local array<SpawnPlayerInfo> Info) or a BOOL (local bool press1P). TArray's first element is a pointer but the array starts empty and so everything should be null in it
            b"\x39\xD0"                 # CMP EAX,EDX
            b"\x77\x04"                 # JA returnZero  ; > 1? Probably it's a TArray. In this part of unrealscript (UpdateWaitCharaLoad unrealscript function) we want to report that we're not async loading
            b"\x74\x06"                 # JZ doProperCheck  ; if it's 1, that means it's the local bool press1P variable and it is TRUE. In this part of the script, we want to check if loading is actually finished
            b"\xEB\x14"                 # JMP second  ; check the other variable, press2P
            # returnZero:
            b"\x31\xC0"                 # XOR EAX,EAX
            b"\xEB\x19"                 # JMP return
            # doProperCheck:
            b"\x8B\x86\xD0\x01\x00\x00" # MOV EAX,dword [ESI+0x1d0]  ; this object is a REDGfxMoviePlayer_MenuInterlude and 0x1d0 is an int VSLoadPercent, from 0 to 100
            b"\x83\xF8\x64"             # CMP EAX,0x64  ; compare to 100
            b"\x74\xF1"                 # JZ returnZero  ; if it's fully loaded, we want to report that we're not async loading, which will let the user's mash skip the loading screen
            b"\x31\xC0"                 # XOR EAX,EAX  ; report that we're async loading (EAX 1). This means that the user cannot skip the loading screen despite them mashing
            b"\x40"                     # INC EAX
            b"\xEB\x09"                 # JMP return
            # second:
            b"\x8B\x41\x08"             # MOV EAX,dword [ECX+0x8]  ; check local bool press2P. In UpdateWaitCharaLoad this would be ArrayNum of the array. That array is empty at the time of this call, so it should be 0
            b"\x39\xD0"                 # CMP EAX,EDX
            b"\x74\xE9"                 # JZ doProperCheck
            b"\x31\xC0"                 # XOR EAX,EAX
            # return:
            b"\x8B\x4C\x24\x0C"         # MOV ECX,dword [ESP+0xc]  ; this function argument is called void* Result and we cast it to BOOL* to return a BOOL
            b"\x89\x01"                 # MOV dword [ECX],EAX
            b"\x5E"                     # POP ESI
            b"\xC2\x08\x00"            # RET 0x8
        )
        
        # The function we're overwriting, execIsAsyncLoading, is called IsAsyncLoading in unrealscript and is a member of REDGfxMoviePlayer_MenuInterlude.
        # It is called from two places: UpdateWaitCharaLoad and UpdateExec.
        # In UpdateWaitCharaLoad we just want to return false and not modify its local variables, because they start with local array<SpawnPlayerInfo> Info.
        # In UpdateExec we want to write TRUE into press1P and return false if we've finished loading,
        # while returning true (yes we're async loading) whenever the user mashes before we've finished loading.
        # dword ptr[dword ptr[ESP+0x4]+0x10] + 0x50 is PropertiesSize. It has been observed to be 0x4C for UpdateWaitCharaLoad and 0x30 for UpdateExec.
        # But we are not going to hardcode these values. We will instead do a proper string check for the name.
        
        write_buf_mash = bytearray(
            b"\x56"                     # PUSH ESI
            b"\x57"                     # PUSH EDI
            b"\x8B\x7C\x24\x0C"         # MOV EDI,dword [ESP+0xc]  ; this argument is an FFrame* and is called Stack in UE3 source code
            b"\x89\xCE"                 # MOV ESI,ECX
            b"\xFF\x47\x18"             # INC dword [EDI+0x18]  ; increment stack->Code
            b"\x8B\x4F\x18"             # MOV ECX,dword [EDI+0x18]  ; read stack->Code
            b"\x80\x39\x41"             # CMP byte [ECX],0x41  ; compare *stack->Code to EX_DebugInfo
            b"\x75\x1D"                 # JNZ string_literal_end
            b"\x41"                     # INC ECX
            b"\x6a\x00"                 # PUSH 0
            b"\x89\x4F\x18"             # MOV dword [EDI+0x18],ECX
            b"\x8b\x4F\x14"             # MOV ECX,dword [EDI+0x14]  # stack->Object
            b"\x57"                     # PUSH EDI
            b"\xff\x15\x00\x00\x00\x00" # CALL dword [GNatives[0x41]]  ; call GNatives[EX_DebugInfo]. We'll write the address soon
            b"\xEB\x0B"                 # JMP string_literal_end
            b"UpdateExec\x00"
            # string_literal_end
            b"\x83\xEC\x08"             # SUB ESP,0x8  ; allocate stack space for an FName
            b"\x8d\x0c\x24"             # LEA ECX,[ESP]
            b"\x6A\x00"                 # PUSH 0  ; this is the EFindName FindType argument of the FName::Init function. Value 0 means FNAME_Find
            b"\x6A\x00"                 # PUSH 0  ; this will be the number part of the new FName. 0 means there is no number
            b"\x68\x00\x00\x00\x00"     # PUSH UpdateExec  ; we'll write the address of the string later. This needs a relocation entry too
            b"\xE8\x00\x00\x00\x00"     # CALL FName::Init. We'll write the call offset later. This cleans the stack for us
            b"\x8D\x0C\x24"             # LEA ECX,[ESP]  ; ECX will be the FName we just initted
            b"\x8B\x47\x10"             # MOV EAX,dword [EDI+0x10]  ; 0x10 is UStruct* Node member of FFrame
            b"\x8D\x40\x2C"             # LEA EAX,dword [EAX+0x2c]  ; 0x2c is FName Name member of UObject (UStruct extends UObject)
            b"\x50"                     # PUSH EAX
            b"\xE8\x00\x00\x00\x00"     # CALL FName::Compare  ; Cleans up the one stack argument. We'll write the call offset later.
            b"\x83\xC4\x08"             # ADD ESP,0x8  ; clean up our stack allocated FName
            b"\x31\xD2"                 # XOR EDX,EDX
            b"\x39\xD0"                 # CMP EAX,EDX
            b"\x75\x2C"                 # JNZ returnZero  ; for UpdateWaitCharaLoad we always want to return false, that we're not async oading
            b"\x8B\x47\x10"             # MOV EAX,dword [EDI+0x10]  ; 0x10 is UStruct* Node member of FFrame
            b"\x8B\x40\x54"             # MOV EAX,dword [EAX+0x54]  ; 0x54 is TArray<BYTE> Script member of UStruct, and the first member of this TArray is BYTE* Data
            b"\x8B\x57\x18"             # MOV EDX,dword [EDI+0x18]  ; 0x18 is the EExprToken* Code member of FFrame. It should be somewhere inside Script
            b"\x29\xC2"                 # SUB EDX,EAX
            b"\x81\xFA\x93\x01\x00\x00" # CMP EDX,0x193  ; past 0x193 the script obtains press1P and press2P and it actually becomes dangerous to return true
            b"\x7c\x19"                 # JB returnZero  ; before 0x193 it's OK to just always return false
            b"\x8B\x86\xD0\x01\x00\x00" # MOV EAX,dword [ESI+0x1d0]  ; this object is a REDGfxMoviePlayer_MenuInterlude and 0x1d0 is an int VSLoadPercent, from 0 to 100
            b"\x83\xF8\x64"             # CMP EAX,0x64  ; compare to 100
            b"\x7D\x05"                 # JGE forceWayThrough
            b"\x31\xC0"                 # XOR EAX,EAX
            b"\x40"                     # INC EAX
            b"\xEB\x0B"                 # JMP return
            # forceWayThrough:
            b"\x8B\x4F\x1C"             # MOV ECX,dword [EDI+0x1c]  ; this is stack->Locals, it stores function arguments and local variables of the unrealscript
            b"\x31\xC0"                 # XOR EAX,EAX
            b"\x40"                     # INC EAX
            b"\x89\x41\x04"             # MOV dword [ECX+0x4],EAX  ; The first value (ECX+0x0) is always bTrigger, a function argument. The second is local bool press1P
            # returnZero:
            b"\x31\xC0"                 # XOR EAX,EAX
            # return:
            b"\x8B\x4C\x24\x10"         # MOV ECX,dword [ESP+0x10]  ; this function argument is called void* Result and we cast it to BOOL* to return a BOOL
            b"\x89\x01"                 # MOV dword [ECX],EAX
            b"\x5F"                     # POP EDI
            b"\x5E"                     # POP ESI
            b"\xC2\x08\x00"             # RET 0x8
        )
        
        if automash:
            write_buf = write_buf_mash
        else:
            write_buf = write_buf_no_mash
        GNatives_EX_DebugInfo_mention_in_write_buf = write_buf.find(b"\xff\x15\x00\x00\x00\x00")
        GNatives_EX_DebugInfo_mention_in_write_buf += 2
        write_buf[
            GNatives_EX_DebugInfo_mention_in_write_buf :
            GNatives_EX_DebugInfo_mention_in_write_buf + 4
        ] = struct.pack("<I", GNatives_EX_DebugInfo_va)
        
        IMAGE_REL_BASED_ABSOLUTE = 0
        IMAGE_REL_BASED_HIGH = 1
        IMAGE_REL_BASED_LOW = 2
        IMAGE_REL_BASED_HIGHLOW = 3
        IMAGE_REL_BASED_HIGHADJ = 4
        IMAGE_REL_BASED_DIR64 = 10
        
        reloc_table = RelocTable()
        reloc_table.populate_from_buffer(whole_file)
        relocs = reloc_table.find_relocs_in_region(execIsAsyncLoading_va, execIsAsyncLoading_va + len(write_buf))
        if debug:
            print(f"Removing entries from between VA {execIsAsyncLoading_va:#x} and VA {execIsAsyncLoading_va + len(write_buf):#x}")
        reloc_table.remove_entries(relocs)
        
        if automash:
            UpdateExec_str_pos = write_buf.find(b"UpdateExec")
            UpdateExec_str_va = execIsAsyncLoading_va + UpdateExec_str_pos
            UpdateExec_str_usage_pos = write_buf.find(b"\x68\x00\x00\x00\x00")
            write_buf[UpdateExec_str_usage_pos + 1 :
                      UpdateExec_str_usage_pos + 5] = struct.pack("<I", UpdateExec_str_va)
            if debug:
                print("Adding reloc entry for execIsAsyncLoading_va + UpdateExec_str_usage_pos + 1.")
            reloc_table.add_entry(execIsAsyncLoading_va + UpdateExec_str_usage_pos + 1)
            
            FName_Init_call_pos = write_buf.find(b"\xE8\x00\x00\x00\x00")
            call_offset = FName_Init_va - (execIsAsyncLoading_va + FName_Init_call_pos + 5)
            write_buf[FName_Init_call_pos + 1:
                      FName_Init_call_pos + 5] = struct.pack("<i", call_offset)
            
            FName_Compare_call_pos = write_buf.find(b"\xE8\x00\x00\x00\x00")
            call_offset = FName_Compare_va - (execIsAsyncLoading_va + FName_Compare_call_pos + 5)
            write_buf[FName_Compare_call_pos + 1:
                      FName_Compare_call_pos + 5] = struct.pack("<i", call_offset)
            
            
        class FileWrite:
            def __init__(self, pos, data):
                self.pos = pos
                self.data =data
        file_writes: list[FileWrite] = []
        file_writes.append(FileWrite(execIsAsyncLoading_raw, write_buf))
        
        if debug:
            print("Adding reloc entry for execIsAsyncLoading_va + GNatives_EX_DebugInfo_mention_in_write_buf.")
        reloc_table.add_entry(execIsAsyncLoading_va + GNatives_EX_DebugInfo_mention_in_write_buf)
        
        if not jmp_already_noped_out:
            file_writes.append(FileWrite(jmp_pos, b"\x90\x90"))
            
        menu_timewaste_counter_usage_raw = sigscanp("75 20 6a 64 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 12 8b 0d ?? ?? ?? ?? 51 8b ce e8 ?? ?? ?? ?? 85 c0 74 38",
            text_section)
        if menu_timewaste_counter_usage_raw == -1:
            if debug:
                print("Couldn't find the usage of the variable that holds the amount of time needed to waste for you on each initial game loading message.")
        else:
            if debug:
                print(f"menu_timewaste_counter_usage_raw: {menu_timewaste_counter_usage_raw:#x}")
            menu_timewaste_counter_va = struct.unpack("<I", whole_file[
                menu_timewaste_counter_usage_raw + 18 :
                menu_timewaste_counter_usage_raw + 22])[0]
            if debug:
                print(f"menu_timewaste_counter_va: {menu_timewaste_counter_va:#x}")
            menu_timewaste_counter_raw = va_to_raw(menu_timewaste_counter_va)
            current_val = struct.unpack("<i", whole_file[
                menu_timewaste_counter_raw :
                menu_timewaste_counter_raw + 4])[0]
            if debug:
                print(f"menu timewaste current val: {current_val}")
            if current_val == 90:
                file_writes.append(FileWrite(menu_timewaste_counter_raw, b"\x00\x00\x00\x00"))
            elif debug:
                print("Someone else has already changed menu timewaste value.")
            
        dlc_timewaste_usage_raw = sigscanp("6a 00 6a 00 68 f7 00 00 00 6a 03 68 ?? ?? ?? ?? 6a 00 6a 61 e8 ?? ?? ?? ?? 83 c4 1c c7 05 ?? ?? ?? ?? 3c 00 00 00",
            text_section)
        if dlc_timewaste_usage_raw == -1:
            if debug:
                print("Couldn't find the usage of a variable that just wastes your time on the 'Verifying downloadable content.' message.")
        else:
            if debug:
                print(f"dlc_timewaste_usage_raw: {dlc_timewaste_usage_raw:#x}")
            dlc_timewaste_va = struct.unpack("<I", whole_file[
                dlc_timewaste_usage_raw + 30 :
                dlc_timewaste_usage_raw + 34])[0]
            search_needle = bytearray(b"\xc7\x05\x10\x05\xe4\x01\x3c\x00\x00\x00")
            search_needle[2:6] = struct.pack("<I", dlc_timewaste_va)
            found_at_least_one = False
            search_start = text_section.start_raw
            text_end = text_section.start_raw + text_section.raw_size
            while text_end - search_start >= 10:
                next_find = sigscan(search_needle, None, search_start, text_end)
                if next_find == -1:
                    break
                found_at_least_one = True
                file_writes.append(FileWrite(next_find + 6, b"\x00\x00\x00\x00"))
                found_at_leasts_one = True
                search_start = next_find + 10
            if not found_at_least_one:
                if debug:
                    print("Couldn't find any uses of the variable that just wastes your time on the 'Verifying downloadable content.' message.")
        
        # dll_name case-insensitive, must contain ".dll" at the end.
        # func_name case-sensitive.
        # returns raw file address, or -1, if not found.
        def find_imported_function(dll_name, func_name):
            if isinstance(func_name, str):
                func_name = func_name.encode("utf-8")
                
            dll_name_upper = dll_name.upper()
            import_directory_entry_off = nt_header_off + 0x80
            imports_size = struct.unpack("<I", whole_file[import_directory_entry_off + 4 : import_directory_entry_off + 8])[0]
            import_ptr_next_raw = rva_to_raw(struct.unpack("<I", whole_file[import_directory_entry_off : import_directory_entry_off + 4])[0])
            while imports_size > 0:
                imports_size -= 0x14
                import_ptr_raw = import_ptr_next_raw
                import_ptr_next_raw += 0x14
                import_lookup_table_rva = struct.unpack("<I", whole_file[import_ptr_raw : import_ptr_raw + 4])[0]
                if import_lookup_table_rva == 0:
                    break
                import_lookup_table_raw = rva_to_raw(import_lookup_table_rva)
                
                dll_name_raw = rva_to_raw(struct.unpack("<I", whole_file[import_ptr_raw + 0xc : import_ptr_raw + 0x10])[0])
                dll_name_end = dll_name_raw
                while whole_file[dll_name_end] != 0:
                    dll_name_end += 1
                dll_name_current = whole_file[dll_name_raw : dll_name_end].decode("utf-8")
                if dll_name_upper != dll_name_current.upper():
                    continue
                    
                func_ptr_raw = rva_to_raw(struct.unpack("<I", whole_file[import_ptr_raw + 0x10 : import_ptr_raw + 0x14])[0])
                image_import_by_name_ptr_raw = import_lookup_table_raw
                while True:
                    image_import_by_name_rva = struct.unpack("<I", whole_file[
                        image_import_by_name_ptr_raw :
                        image_import_by_name_ptr_raw + 4])[0]
                    if image_import_by_name_rva == 0:
                        break
                    image_import_by_name_raw = rva_to_raw(image_import_by_name_rva)
                    
                    func_name_start = image_import_by_name_raw + 2
                    func_name_end = func_name_start
                    while whole_file[func_name_end] != 0:
                        func_name_end += 1
                    func_name_current = whole_file[func_name_start : func_name_end]
                    if func_name_current == func_name:
                        return func_ptr_raw
                    func_ptr_raw += 4
                    image_import_by_name_ptr_raw += 4
            return -1
        
        # For INI files.
        class DesiredEdit:
            def __init__(self, char_offset_start, char_offset_end, new_txt):
                self.char_offset_start = char_offset_start
                self.char_offset_end = char_offset_end
                self.new_txt = new_txt  # str
        
        # For INI files.
        def get_timestamp(path):
            if not os.path.isfile(path):
                return None
            return float(int(os.stat(path).st_mtime))
            
        def strip_bytestring(bytestring):
            start_off = 0
            len_bytestring = len(bytestring)
            while start_off < len_bytestring and bytestring[start_off] <= 32:
                start_off += 1
            if start_off == len_bytestring:
                return b""
            end_off = len_bytestring
            while end_off > start_off and bytestring[end_off - 1] <= 32:
                end_off -= 1
            if end_off == start_off:
                return b""
            return bytestring[start_off : end_off]
        
        # For INI files.
        class SectionTracker:
            def __init__(self):
                self.reset()
                self.is_in_section_of_interest = False
                self.redgame_folder = ""  # UE3 adds one more .. at the start of BasedOn values
                self.BasedOn_timestamp = None
                self.new_timestamps = []  # list[float]
                self.desired_edits = []  # list[DesiredEdit]
                self.last_SkippableMovies_end = -1
                self.FullScreenMovie_section_line_end = -1  # end of the line on which [FullScreenMovie] section is declared
                self.FullScreenMovie_section_last_non_empty_line_end = -1
                self.already_ignores_intro = False  # already has SkippableMovies=Splash_Steam
                self.on_line_end = None  # function. Must be member of SectionTracker. Returns nothing. Accepts self, char_offset: int. Gets called after every line break. reset() gets called immediately after.
                
            def enter_interest(self, interesting_name):
                if not self.dont_like_line and self.section_name and not self.in_section_name:
                    self.is_in_section_of_interest = (self.section_name == interesting_name)
                    return True
                return False
                
            def on_line_end_BasedOn(self, char_offset):
                if self.enter_interest(b"Configuration"):
                    return
                if self.is_in_section_of_interest and self.key_name and self.value:
                    self.value = strip_bytestring(self.value)
                    if self.key_name == b"BasedOn":
                        current_path = self.redgame_folder
                        current_piece = bytearray()
                        
                        def piece_on_end():
                            current_path_local = current_path
                            if current_piece == b"..":
                                while current_path_local and current_path_local[-1] == "\\":
                                    current_path_local = current_path_local[0:-1]
                                return os.path.dirname(current_path_local)
                            elif current_piece:
                                return os.path.join(current_path_local, current_piece.decode("utf-8"))
                            else:
                                return current_path_local
                                
                        for c in self.value:
                            if c == ord('\\'):
                                current_path = piece_on_end()
                                current_piece = bytearray()
                            else:
                                current_piece.append(c)
                        current_path = piece_on_end()
                        self.BasedOn_timestamp = get_timestamp(current_path)
                        
            def on_line_end_IniVersion(self, char_offset):
                if self.enter_interest(b"IniVersion"):
                    return
                if self.is_in_section_of_interest and self.key_name and self.value and self.line_start_offset != -1:
                    parsed_index = int(self.key_name.decode("utf-8"))
                    if parsed_index in (0,1) and parsed_index < len(self.new_timestamps):
                        formatted_float = str(self.new_timestamps[parsed_index])
                        if formatted_float.endswith(".0"):
                            formatted_float += "00000"
                        formatted_str = f"{str(parsed_index)}={formatted_float}"
                        self.desired_edits.append(DesiredEdit(self.line_start_offset, char_offset, formatted_str))
                        
            def on_line_end_ignore_intro(self, char_offset):
                if self.enter_interest(b"FullScreenMovie"):
                    if self.is_in_section_of_interest:
                        self.FullScreenMovie_section_line_end = char_offset
                    return
                
                if self.is_in_section_of_interest and self.key_name and self.value and self.line_start_offset != -1:
                    if self.key_name == b"SkippableMovies":
                        self.last_SkippableMovies_end = char_offset
                        self.value = strip_bytestring(self.value)
                        if self.value == b"Splash_Steam":
                            self.already_ignores_intro = True
                elif self.is_in_section_of_interest and self.line_start_offset != -1 and self.line_non_empty:
                    FullScreenMovie_section_last_non_empty_line_end = char_offset
                
            # Called after every line break.
            def reset(self):
                self.line_start_offset = -1  # set by the lower-level parser to the file offset on which the current line starts
                self.line_non_empty = False  # comments are considered non-empty
                self.key_name = bytearray()
                self.value = bytearray()
                self.fresh_line = True  # used only by the lower-level parser to indicate the first character on a line
                self.dont_like_line = False  # used for parsing [section]s
                self.section_name = bytearray()
                self.in_section_name = False
                self.encountered_equal_sign = False
                self.is_comment = False
                
            def parse_char(self, c, char_offset):
                if c in (ord('\r'), ord('\n')):
                    self.on_line_end(char_offset)
                    self.reset()
                elif self.fresh_line and c == ord('['):
                    self.in_section_name = True
                    self.line_start_offset = char_offset
                    self.fresh_line = False
                    self.line_non_empty = True
                elif self.in_section_name:
                    if c == ord(']'):
                        self.in_section_name = False
                    else:
                        self.section_name.append(c)
                elif not self.fresh_line and c in (ord('\t'), ord(' ')) and self.section_name:
                    # ok, allowed to have whitespace after a section ]
                    # UE3 only considers '\t' and ' ' to be whitespace
                    pass
                else:
                    if self.fresh_line:
                        if c == ord(';'):
                            self.is_comment = True
                        self.line_start_offset = char_offset
                        self.fresh_line = False
                    self.line_non_empty = (self.line_non_empty or c > 32)
                    self.dont_like_line = True
                    if self.is_in_section_of_interest and not self.is_comment:
                        if c == ord('=') and not self.encountered_equal_sign:
                            self.encountered_equal_sign = True
                            
                            self.key_name = strip_bytestring(self.key_name)
                        elif not self.encountered_equal_sign:
                            self.key_name.append(c)
                        else:
                            self.value.append(c)
                    
            def run_loop(self, data, on_line_end_param):
                self.on_line_end = on_line_end_param
                c_offset = 0
                for c in data:
                    self.parse_char(c, c_offset)
                    c_offset += 1
                self.on_line_end(c_offset)
                
            def apply_edits(self, data):
                for desired_edit in self.desired_edits:
                    new_data = desired_edit.new_txt.encode("utf-8")
                    data[desired_edit.char_offset_start : desired_edit.char_offset_end] = new_data
                    shift = len(new_data) - (desired_edit.char_offset_end - desired_edit.char_offset_start)
                    for desired_edit_modif in self.desired_edits:
                        if desired_edit_modif.char_offset_start > desired_edit.char_offset_start:
                            desired_edit_modif.char_offset_start += shift
                            desired_edit_modif.char_offset_end += shift
        
        binaries_win32_folder = os.path.dirname(guilty_gear_xrd_exe_path)
        binaries_folder = os.path.dirname(binaries_win32_folder)
        root_folder = os.path.dirname(binaries_folder)
        
        if fix_bug_that_causes_ini_file_to_reset_twice_a_year_in_countries_with_daylight_saving:
            
            class StuffForDaylightSaving:
                pass
                
            stuff_for_daylight_saving = StuffForDaylightSaving()
            
            def find_stuff_for_daylight_saving():
                stuff = stuff_for_daylight_saving
                FFileManagerWindows_GetFileTimestamp_part1_sig, \
                FFileManagerWindows_GetFileTimestamp_part1_mask = pattern_to_sigmask(
                    "6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 83 ec 60 a1 ?? ?? ?? ?? 33 c4 89 44 24 5c 53 55 56 57"
                    " a1 ?? ?? ?? ?? 33 c4 50 8d 44 24 74 64 a3 00 00 00 00 8b bc 24 84 00 00 00 8b f1 8b 06 8b 50 54 57 8d 4c 24 2c 51 8b ce"
                    " ff d2 33 db 89 5c 24 7c 39 58 04 74 04 8b 00 eb 05"
                )
                total_len = len(FFileManagerWindows_GetFileTimestamp_part1_sig)
                stuff.MOV_EAX_EMPTYSTRING = total_len  # MOV EAX,""
                FFileManagerWindows_GetFileTimestamp_part2_sig, \
                FFileManagerWindows_GetFileTimestamp_part2_mask = pattern_to_sigmask(
                    "b8 ?? ?? ?? ??"
                    " 8b 16 8b 52 58 50 8d 44 24 20 50 8b ce ff d2 39 58 04 74 04 8b 00 eb 05"
                    " b8 ?? ?? ?? ?? 8b 2d 44 d5 48 01 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e"
                )
                total_len += len(FFileManagerWindows_GetFileTimestamp_part2_sig)
                stuff.NEGATIVE_1 = total_len  # MOVSD XMM0,qword ptr [DOUBLE_014a0db0], DOUBLE_014a0db0 says 00 00 00 00 00 00 f0 bf, which means -1.0
                FFileManagerWindows_GetFileTimestamp_part3_sig, \
                FFileManagerWindows_GetFileTimestamp_part3_mask = pattern_to_sigmask(
                    "f2 0f 10 05 ?? ?? ?? ??"
                    " f2 0f 11 44 24 14 8b 44 24 1c 89 5c 24 24 89 5c 24 20 3b c3 74 0d 50"
                )
                total_len += len(FFileManagerWindows_GetFileTimestamp_part3_sig)
                stuff.APP_FREE = total_len  # CALL appFree
                FFileManagerWindows_GetFileTimestamp_part4_sig, \
                FFileManagerWindows_GetFileTimestamp_part4_mask = pattern_to_sigmask(
                    "e8 ?? ?? ?? ??"
                    " 83 c4 04 89 5c 24 1c 8b 44 24 28 c7 44 24 7c ff ff ff ff 89 5c 24 30 89 5c 24 2c 3b c3 74 09 50 e8 ?? ?? ?? ??"
                    " 83 c4 04 f2 0f 10 44 24 14 66 0f 2e 05 ?? ?? ?? ?? 9f f6 c4 44 7a 5d 8b 16 8b 52 54 57 8d 44 24 38 50 8b ce"
                    " ff d2 39 58 04 74 04 8b 00 eb 05 b8 ?? ?? ?? ?? 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e"
                    " f2 0f 10 05 ?? ?? ?? ?? f2 0f 11 44 24 14 8b 44 24 34 89 5c 24 3c 89 5c 24 38 3b c3 74 09 50 e8 ?? ?? ?? ??"
                    " 83 c4 04 dd 44 24 14 8b 4c 24 74 64 89 0d 00 00 00 00 59 5f 5e 5d 5b 8b 4c 24 5c 33 cc e8 ?? ?? ?? ?? 83 c4 6c c2 04 00"
                )
                FFileManagerWindows_GetFileTimestamp_sig = \
                    FFileManagerWindows_GetFileTimestamp_part1_sig \
                    + FFileManagerWindows_GetFileTimestamp_part2_sig \
                    + FFileManagerWindows_GetFileTimestamp_part3_sig \
                    + FFileManagerWindows_GetFileTimestamp_part4_sig
                    
                FFileManagerWindows_GetFileTimestamp_mask = \
                    FFileManagerWindows_GetFileTimestamp_part1_mask \
                    + FFileManagerWindows_GetFileTimestamp_part2_mask \
                    + FFileManagerWindows_GetFileTimestamp_part3_mask \
                    + FFileManagerWindows_GetFileTimestamp_part4_mask
                
                # ConvertToAbsolutePath is 0x54. Takes FString* out and wchar_t* Filename. Returns out
                # ConvertAbsolutePathToUserPath is 0x58. Takes FString* out and wchar_t* AbsolutePath. Returns out
                
                stuff.FFileManagerWindows_GetFileTimestamp = sigscan(
                    FFileManagerWindows_GetFileTimestamp_sig,
                    FFileManagerWindows_GetFileTimestamp_mask,
                    text_section)
                
                if stuff.FFileManagerWindows_GetFileTimestamp == -1:
                    if debug:
                        print("Couldn't find FFileManagerWindows::GetFileTimestamp.")
                    return False
                
                if debug:
                    print(f"FFileManagerWindows_GetFileTimestamp (raw): {stuff.FFileManagerWindows_GetFileTimestamp:#x}")
                stuff.FFileManagerWindows_GetFileTimestamp_size = len(FFileManagerWindows_GetFileTimestamp_sig)
                
                stuff.CreateFileW_offset = find_imported_function("kernel32.dll", b"CreateFileW")
                if stuff.CreateFileW_offset == -1:
                    if debug:
                        print("CreateFileW not found.")
                    return False
                if debug:
                    print(f"CreateFileW_offset (raw): {stuff.CreateFileW_offset:#x}")
                stuff.GetFileTime_offset = find_imported_function("kernel32.dll", b"GetFileTime");
                if stuff.GetFileTime_offset == -1:
                    if debug:
                        print("GetFileTime not found.")
                    return False
                if debug:
                    print(f"GetFileTime_offset (raw): {stuff.GetFileTime_offset:#x}")
                stuff.CloseHandle_offset = find_imported_function("kernel32.dll", b"CloseHandle");
                if stuff.CloseHandle_offset == -1:
                    if debug:
                        print("CloseHandle not found.")
                    return False
                if debug:
                    print(f"CloseHandle_offset (raw): {stuff.CloseHandle_offset:#x}")
                stuff.GetFileAttributesW_offset = find_imported_function("kernel32.dll", b"GetFileAttributesW");
                if stuff.GetFileAttributesW_offset == -1:
                    if debug:
                        print("GetFileAttributesW not found.")
                    return False
                if debug:
                    print(f"GetFileAttributesW_offset (raw): {stuff.GetFileAttributesW_offset:#x}")
                    
                return True
                
            if find_stuff_for_daylight_saving():
                def patch_daylight_saving():
                    class NewCode:
                        def __init__(self):
                            self.data = bytearray()
                            
                        def add_bytes(self, add_data):
                            if isinstance(add_data, str):
                                add_data = bytearray(ord(x) for x in add_data)
                            if isinstance(add_data, bytes) or isinstance(add_data, bytearray):
                                self.data += add_data
                            else:
                                raise Exception(f"Wrong datatype for add_data: {str(type(add_data))}")
                                
                        def add(self, pattern, substitute = None):
                            sig, mask = pattern_to_sigmask(pattern)
                            if substitute is None:
                                self.add_bytes(sig)
                            else:
                                wildcard_start_index = None
                                def on_end(obj, wildcard_end_index_noninclusive):
                                    substitute_local = substitute
                                    wildcard_length = wildcard_end_index_noninclusive - wildcard_start_index
                                    if wildcard_length == 1:
                                        if substitute_local < 0:
                                            substitute_local = 0x100 + substitute_local
                                        sig[wildcard_start_index : wildcard_start_index + 1] = struct.pack("<B", substitute_local)
                                    elif wildcard_length == 2:
                                        if substitute_local < 0:
                                            substitute_local = 0x10000 + substitute_local
                                        sig[wildcard_start_index : wildcard_start_index + 2] = struct.pack("<H", substitute_local)
                                    elif wildcard_length == 4:
                                        if substitute_local < 0:
                                            substitute_local = 0x100000000 + substitute_local
                                        sig[wildcard_start_index : wildcard_start_index + 4] = struct.pack("<I", substitute_local)
                                    else:
                                        raise Exception(f"Wrong wildcard size: {pattern}")
                                    obj.add_bytes(sig)
                                    
                                for i in range(0, len(sig)):
                                    mask_byte = mask[i]
                                    if mask_byte == ord('?'):
                                        if wildcard_start_index is None:
                                            wildcard_start_index = i
                                    elif wildcard_start_index is not None:
                                        on_end(self, i)
                                        return
                                if wildcard_start_index is not None:
                                    on_end(self, len(sig))
                                else:
                                    raise Exception("Substitute given, but no wildcard.")
                                    
                    new_code = NewCode()
                    
                    FIRST_FSTRING = 0x0  # FString (12 bytes). MUST BE 0 due to using a 8B 04 24 instruction
                    SECOND_FSTRING = 0xc  # FString (12 bytes)
                    FIRST_TEXT = 0x18  # const wchar_t* (4 bytes)
                    RESULT = 0x1c  # double (8 bytes)
                    FILETIMEVAR = 0x24  # FILETIME (8 bytes)
                    SUCCESSFUL_PATH = 0x2c  # const wchar_t* (4 bytes)
                    STACK_SPACE = 0x60
                    
                    
                    new_code.add(
                        "53 55 56 57"            # PUSH EBX,EBP,ESI,EDI
                        " 8b f1"                 # MOV ESI,ECX
                        " 83 ec ??",             # SUB ESP,STACK_SPACE
                        STACK_SPACE)
                    
                    new_code.add("8b 06"         # MOV EAX,dword ptr [ESI]
                        " 8b 50 54"              # MOV EDX,dword ptr [EAX + 0x54]  ; ConvertToAbsolutePath. Takes FString* out and wchar_t* Filename. Returns out
                        " 8B 7C 24 ??",          # MOV EDI,dword ptr [ESP + STACK_SPACE + 0x10 (4 pushes) + 4 (Filename, first stack argument)]
                        STACK_SPACE + 0x10 + 0x4)
                    new_code.add("57")           # PUSH EDI
                    new_code.add("8d 4c 24 ??",  # LEA ECX,[ESP + FIRST_FSTRING + 4]
                        # see PUSH EDI above
                        FIRST_FSTRING + 4)
                    new_code.add("51"            # PUSH ECX
                        " 8b ce"                 # MOV ECX,ESI
                        " ff d2"                 # CALL EDX
                    )
                    
                    stuff = stuff_for_daylight_saving
                    base_raw = stuff.FFileManagerWindows_GetFileTimestamp
                    base_va = raw_to_va(base_raw)
                    empty_string_va = struct.unpack("<I", whole_file[
                        base_raw + stuff.MOV_EAX_EMPTYSTRING + 1 :
                        base_raw + stuff.MOV_EAX_EMPTYSTRING + 5])[0]
                    negative_1_va = struct.unpack("<I", whole_file[
                        base_raw + stuff.NEGATIVE_1 + 4 :
                        base_raw + stuff.NEGATIVE_1 + 8])[0]
                    appFree_va = base_va + stuff.APP_FREE + 5 + struct.unpack("<i", whole_file[
                        base_raw + stuff.APP_FREE + 1 :
                        base_raw + stuff.APP_FREE + 5])[0]
                        
                    relocs = reloc_table.find_relocs_in_region(base_va,
                        base_va + stuff.FFileManagerWindows_GetFileTimestamp_size)
                    reloc_table.remove_entries(relocs)
                    
                    new_code.add(
                        "33 db"                  # XOR EBX,EBX
                        " 39 58 04"              # CMP dword ptr [EAX + 0x4],EBX
                        " 74 04"                 # JZ 0x4
                        " 8b 00"                 # MOV EAX,dword ptr [EAX]  ; read Data member of FString
                        " eb 05"                 # JMP 0x5
                    )
                    new_code_size = len(new_code.data)
                                                 # MOV EAX,emptyString
                    new_code.add("b8 ?? ?? ?? ??", empty_string_va)
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 1 (MOV EAX,emptyString).")
                    reloc_table.add_entry(base_va + new_code_size + 1)
                                                 # MOV dword ptr[ESP+FIRST_TEXT],EAX
                    new_code.add("89 44 24 ??", FIRST_TEXT)
                    new_code.add(
                        "8b 16"                  # MOV EDX,dword ptr [ESI]
                        " 8b 52 58"              # MOV EDX,dword ptr[EDX + 0x58]  ; ConvertAbsolutePathToUserPath. Takes FString* out and wchar_t* AbsolutePath. Returns out
                        " 50"                    # PUSH EAX
                        " 8d 44 24 ??",          # LEA EAX,[ESP + SECOND_FSTRING + 4]
                        # see PUSH EAX above
                        SECOND_FSTRING + 4)
                    new_code.add("50"            # PUSH EAX
                        " 8b ce"                 # MOV ECX,ESI
                        " ff d2"                 # CALL EDX
                        
                        " 39 58 04"              # CMP dword ptr [EAX + 0x4],EBX
                        " 74 04"                 # JZ 0x4
                        " 8b 00"                 # MOV EAX,dword ptr [EAX]  ; read Data member of FString
                        " eb 05"                 # JMP 0x5
                    )
                    new_code_size = len(new_code.data)
                                                 # MOV EAX,emptyString
                    new_code.add("b8 ?? ?? ?? ??", empty_string_va)
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 1 (MOV EAX,emptyString).")
                    reloc_table.add_entry(base_va + new_code_size + 1)
                    
                                                 # MOV dword ptr[ESP + SUCCESSFUL_PATH],EAX
                    new_code.add("89 44 24 ??", SUCCESSFUL_PATH)
                    new_code.add("50")           # PUSH EAX
                    
                    new_code_size = len(new_code.data)
                                                 # MOV EBP,dword ptr[->KERNEL32.DLL::GetFileAttributesW]
                    new_code.add("8b 2d ?? ?? ?? ??", raw_to_va(stuff.GetFileAttributesW_offset))
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 2 (MOV EBP,dword ptr[->KERNEL32.DLL::GetFileAttributesW]).")
                    reloc_table.add_entry(base_va + new_code_size + 2)
                    
                    new_code.add("FF D5"         # CALL EBP
                        " 4B"                    # DEC EBX
                        " 39 D8")                # CMP EAX,EBX
                    jmp_to_after_ret_1 = len(new_code.data)
                    new_code.add("75 00"         # JNZ afterRet, will fill in later
                        " 8B 44 24 ??",          # MOV EAX,dword ptr[ESP + FIRST_TEXT]
                        FIRST_TEXT)
                                                 # MOV dword ptr[ESP + SUCCESSFUL_PATH],EAX
                    new_code.add("89 44 24 ??", SUCCESSFUL_PATH)
                    new_code.add("50"            # PUSH EAX
                        " ff d5"                 # CALL EBP
                        " 39 D8")                # CMP EAX,EBX
                    jmp_to_after_ret_2 = len(new_code.data)
                    new_code.add("75 00")        # JNZ afterRet, will fill in later
                    new_code_size = len(new_code.data)
                    error_return = new_code_size
                                                 # MOVSD XMM0,qword ptr[-1.0]
                    new_code.add("f2 0f 10 05 ?? ?? ?? ??", negative_1_va)
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 4 (MOVSD XMM0,qword ptr[-1.0]).")
                    reloc_table.add_entry(base_va + new_code_size + 4)
                                                 # MOVSD qword ptr[ESP + RESULT],XMM0
                    new_code.add("f2 0f 11 44 24 ??", RESULT)
                    return_label = len(new_code.data)
                    new_code.add("43"            # INC EBX
                        " 8B 04 24"              # MOV EAX,dword ptr[ESP]  ; read Data member of first FString
                        " 39 D8"                 # CMP EAX,EBX
                        " 74 09"                 # JZ 0x9
                        " 50"                    # PUSH EAX
                    )
                    new_code_size = len(new_code.data)
                    offset = appFree_va - (base_va + new_code_size + 5)
                                                 # CALL appFree
                    new_code.add("e8 ?? ?? ?? ??", offset)
                    new_code.add("83 c4 04"      # ADD ESP,0x4
                        " 8b 44 24 ??",          # MOV EAX,dword ptr[ESP + SECOND_FSTRING]  ; read Data member of second FString
                        SECOND_FSTRING)
                    new_code.add("39 D8"         # CMP EAX,EBX
                        " 74 09"                 # JZ 0x9
                        " 50"                    # PUSH EAX
                    )
                    new_code_size = len(new_code.data)
                    offset = appFree_va - (base_va + new_code_size + 5)
                                                 # CALL appFree
                    new_code.add("e8 ?? ?? ?? ??", offset)
                    new_code.add("83 c4 04"      # ADD ESP,0x4
                        " dd 44 24 ??",          # FLD qword ptr[ESP + RESULT]
                        RESULT)
                                                 # ADD ESP,STACK_SPACE
                    new_code.add("83 c4 ??", STACK_SPACE)
                    new_code.add("5f 5e 5d 5b"   # POP EDI,ESI,EBP,EBX
                        " c2 04 00")             # RET 0x4
                    new_code.data[jmp_to_after_ret_1 + 1] = len(new_code.data) - (jmp_to_after_ret_1 + 2)
                    new_code.data[jmp_to_after_ret_2 + 1] = len(new_code.data) - (jmp_to_after_ret_2 + 2)
                    
                    # CreateFileW(L"path",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
                    FILE_ATTRIBUTE_NORMAL = 0x80
                    OPEN_EXISTING = 3
                    FILE_SHARE_READ = 1
                    GENERIC_READ = 0x80000000
                    new_code.add("6A 00")                                  # PUSH 0
                    new_code.add("68 ?? ?? ?? ??", FILE_ATTRIBUTE_NORMAL)  # PUSH FILE_ATTRIBUTE_NORMAL
                    new_code.add("6A ??", OPEN_EXISTING)                   # PUSH OPEN_EXISTING
                    new_code.add("6A 00")                                  # PUSH 0
                    new_code.add("6A ??", FILE_SHARE_READ)                 # PUSH FILE_SHARE_READ
                    new_code.add("68 ?? ?? ?? ??", GENERIC_READ)           # PUSH GENERIC_READ
                    new_code.add("FF 74 24 ??", SUCCESSFUL_PATH + 6*4)     # PUSH dword ptr[ESP + SUCCESSFUL_PATH + 6pushes]
                    new_code_size = len(new_code.data)
                                                                           # CALL dword ptr[->KERNEL32.DLL::CreateFileW]
                    new_code.add("ff 15 ?? ?? ?? ??", raw_to_va(stuff.CreateFileW_offset))
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 2 (CALL dword ptr[->KERNEL32.DLL::CreateFileW]).")
                    reloc_table.add_entry(base_va + new_code_size + 2)
                    new_code.add("8b f0"                                   # MOV ESI,EAX
                        " 39 DE")                                          # CMP ESI,EBX
                                                                           # JZ errorReturn
                    new_code.add("74 ??", error_return - (len(new_code.data) + 2))
                    
                    # GetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
                    new_code.add("8D 44 24 ??", FILETIMEVAR)               # LEA EAX,[ESP+FILETIMEVAR]
                    new_code.add("50"                                      # PUSH EAX
                        " 6A 00"                                           # PUSH 0
                        " 6A 00"                                           # PUSH 0
                        " 56")                                             # PUSH ESI
                    
                    new_code_size = len(new_code.data)
                                                                           # CALL dword ptr[->KERNEL32.DLL::GetFileTime]
                    new_code.add("ff 15 ?? ?? ?? ??", raw_to_va(stuff.GetFileTime_offset))
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 2 (CALL dword ptr[->KERNEL32.DLL::GetFileTime]).")
                    reloc_table.add_entry(base_va + new_code_size + 2)
                    
                    new_code.add("89 c5"                                   # MOV EBP,EAX
                        " 56")                                             # PUSH ESI
                    
                    new_code_size = len(new_code.data)
                                                                           # CALL dword ptr[->KERNEL32.DLL::CloseHandle]
                    new_code.add("ff 15 ?? ?? ?? ??", raw_to_va(stuff.CloseHandle_offset))
                    if debug:
                        print(f"Adding new reloc entry for the new code in FFileManagerWindows::GetFileTimestamp + {new_code_size} + 2 (CALL dword ptr[->KERNEL32.DLL::CloseHandle]).")
                    reloc_table.add_entry(base_va + new_code_size + 2)
                    
                    new_code.add("85 ed"                                   # TEST EBP,EBP
                        " 74 ??",                                          # JZ errorReturn
                        error_return - (len(new_code.data) + 4))
                    
                    # FILETIME:
                    # Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
                    time_diff = (
                        (
                            (1970 - 1601) * 365
                            + 24 * 3             # 3 centuries worth of leap years
                            + (70 - 1) // 4      # leap years between 1900 and 1970, not inclusive
                        ) * 24                   # hours
                        * 60                     # minutes
                        * 60                     # seconds
                        * 1000                   # milliseconds
                        * 1000                   # microseconds
                        * 10                     # 100 nanosecond intervals
                    )
                    new_code.add("81 6C 24 ??", FILETIMEVAR)                    # SUB dword ptr[ESP+FILETIMEVAR],...
                    new_code.add("?? ?? ?? ??", time_diff & 0xFFFFFFFF)         # first 4 bytes of time_diff
                    new_code.add("81 5C 24 ??", FILETIMEVAR + 4)                # SBB dword ptr[ESP+FILETIMEVAR + 4],...
                    new_code.add("?? ?? ?? ??", (time_diff >> 32) & 0xFFFFFFFF) # last 4 bytes of time_diff
                    new_code.add("b9 ?? ?? ?? ??", 10000000)                    # MOV ECX,10000000
                    new_code.add("8b 44 24 ??", FILETIMEVAR + 4)                # MOV EAX,dword ptr[ESP+FILETIMEVAR + 4]
                    new_code.add("31 d2"                                        # XOR EDX,EDX
                        " F7 F1"                                                # DIV ECX
                        " 89 c5")                                               # MOV EBP,EAX
                    new_code.add("8b 44 24 ??", FILETIMEVAR)                    # MOV EAX,dword ptr[ESP+FILETIMEVAR]
                    new_code.add("F7 F1"                                        # DIV ECX
                        " 89 44 24 ??", RESULT)                                 # MOV dword ptr[ESP+RESULT],EAX
                    new_code.add("89 6C 24 ??", RESULT + 4)                     # MOV dword ptr[ESP+RESULT + 4],EBP
                    
                    new_code.add("DF 6C 24 ??", RESULT)                         # FILD qword ptr[ESP+RESULT]
                    new_code.add("dd 5c 24 ??", RESULT)                         # FSTP qword ptr[ESP+RESULT]
                    
                    jump_distance = return_label - (len(new_code.data) + 2)
                    if jump_distance >= -0x80:
                        new_code.add("eb ??", jump_distance)
                    else:
                        jump_distance = return_label - (len(new_code.data) + 5)
                        new_code.add("e9 ?? ?? ?? ??", jump_distance)
                        
                    file_writes.append(FileWrite(base_raw, new_code.data))
                    
                    # now, update timestamps in the INI files
                    redgame_folder = os.path.join(root_folder, "REDGame")
                    redgame_config_folder = os.path.join(redgame_folder, "Config")
                    
                    ini_names = (
                        "Debug.ini",
                        "Engine.ini",
                        "Game.ini",
                        "Input.ini",
                        "Lightmass.ini",
                        "SystemSettings.ini",
                        "TMS.ini",
                        "UI.ini"
                    )
                    
                    for ini_name in ini_names:
                        red_path =     os.path.join(redgame_config_folder, "RED"     + ini_name)
                        default_path = os.path.join(redgame_config_folder, "Default" + ini_name)
                        if not os.path.isfile(red_path) or not os.path.isfile(default_path):
                            continue
                        
                        with open(default_path, "rb") as inif:
                            default_data = inif.read()
                        section_tracker = SectionTracker()
                        section_tracker.redgame_folder = redgame_folder
                        section_tracker.run_loop(default_data, section_tracker.on_line_end_BasedOn)
                        section_tracker.reset()
                        if section_tracker.BasedOn_timestamp is not None:
                            if debug:
                                print(f"INI {ini_name} BasedOn timestamp: {section_tracker.BasedOn_timestamp}.")
                            section_tracker.new_timestamps.append(section_tracker.BasedOn_timestamp)
                        elif debug:
                            print(f"INI {ini_name} BasedOn timestamp is None.")
                        
                        default_timestamp = get_timestamp(default_path)
                        if default_timestamp is not None:
                            if debug:
                                print(f"INI {ini_name} Default timestamp: {default_timestamp}.")
                            section_tracker.new_timestamps.append(default_timestamp)
                        elif debug:
                            print(f"INI {ini_name} Default timestamp is None.")
                        
                        with open(red_path, "rb") as inif:
                            sz = inif.seek(0, os.SEEK_END)
                            inif.seek(0)
                            red_data = bytearray(sz)
                            inif.readinto(red_data)
                        section_tracker.run_loop(red_data, section_tracker.on_line_end_IniVersion)
                        
                        if len(section_tracker.desired_edits) == len(section_tracker.new_timestamps) and section_tracker.desired_edits:
                            if debug:
                                print(f"Applying edits to {ini_name}.")
                            section_tracker.apply_edits(red_data)
                            with open(red_path, "wb") as inif:
                                inif.write(red_data)
                        
                        
                patch_daylight_saving()
        
        if intro_movies_skip_mode == "skippable_by_pressing_enter":
            ini_path = os.path.join(root_folder, "REDGame", "Config", "REDEngine.ini")
            if os.path.isfile(ini_path):
                with open(ini_path, "rb") as inif:
                    sz = inif.seek(0, os.SEEK_END)
                    inif.seek(0)
                    ini_data = bytearray(sz)
                    inif.readinto(ini_data)
                section_tracker = SectionTracker()
                section_tracker.run_loop(ini_data, section_tracker.on_line_end_ignore_intro)
                if section_tracker.already_ignores_intro:
                    if debug:
                        print("REDEngine.ini already ignores intro.")
                else:
                    insert_pos = -1
                    if section_tracker.last_SkippableMovies_end != -1:
                        insert_pos = section_tracker.last_SkippableMovies_end
                    elif section_tracker.FullScreenMovie_section_last_non_empty_line_end != -1:
                        insert_pos = section_tracker.FullScreenMovie_section_last_non_empty_line_end
                    elif section_tracker.FullScreenMovie_section_line_end != -1:
                        insert_pos = section_tracker.FullScreenMovie_section_line_end
                        
                    if insert_pos == -1:
                        if debug:
                            print("Failed to find insert position for ignoring intro in REDEngine.ini.")
                    else:
                        if debug:
                            print("Adding Splash_Steam to SkippableMovies in REDEngine.ini.")
                        section_tracker.desired_edits.append(DesiredEdit(insert_pos, insert_pos, "\r\nSkippableMovies=Splash_Steam"))
                        section_tracker.apply_edits(ini_data)
                        with open(ini_path, "wb") as inif:
                            inif.write(ini_data)
        elif intro_movies_skip_mode == "skip_automatically":
            movie_path_from = os.path.join(root_folder, "REDGame", "Movies", "Splash_Steam.wmv")
            movie_path_to = os.path.join(root_folder, "REDGame", "Movies", "Splash_Steam_.wmv")
            if os.path.isfile(movie_path_from):
                if debug:
                    print("Renaming Splash_Steam.wmv to Splash_Steam_.wmv.")
                os.rename(movie_path_from, movie_path_to)
            elif debug:
                print("Splash_Steam.wmv not found.")
                
        if debug:
            if file_writes:
                print(f"Applying {len(file_writes)} writes.")
            else:
                print("No file writes to apply.")
        for file_write in file_writes:
            f.seek(file_write.pos)
            f.write(file_write.data)
            
        reloc_table.commit_all_writes(f)
        return True
        
# This will not unfix the daylight saving bug and will not edit back the IniVersion timestamps in INIs,
# because those changes could also be done by the GGXrdStopResettingINITwiceAYear.
# But it will, if also_make_intro_cutscenes_unskippable is True, remove the cutscene skipping (completely, even if user did it manually (since there's no way to tell)),
# and will make the bootup do the fake waiting again,
# and make all loading that used to be asynchronous be asynchronous again.
# Returns False if failed.
# Returns True on successful unpatching.
# Raises exception if the EXE file is corrupted.
def unpatch(guilty_gear_xrd_exe_path, also_make_intro_cutscenes_unskippable):
    RelocTable.debug = False
    
    with open(guilty_gear_xrd_exe_path, "r+b") as f:
        if f.read(2) != b'MZ':
            raise Exception("Not a valid EXE.")
        f.seek(0x3c)
        nt_header_off = struct.unpack("<I", f.read(4))[0]
        if nt_header_off != 0x138:
            return False
        f.seek(nt_header_off)
        if f.read(4) != b"PE\x00\x00":
            raise Exception("Not a valid EXE.")
        
        f.seek(nt_header_off + 0x34)
        image_base = struct.unpack("<I", f.read(4))[0]
        
        sections = read_sections(f)
        
        def raw_to_rva(raw_addr):
            for section in reversed(sections):
                if raw_addr >= section.start_raw:
                    return raw_addr - section.start_raw + section.start_rva
            return 0
        
        def rva_to_raw(rva_addr):
            for section in reversed(sections):
                if rva_addr >= section.start_rva:
                    return rva_addr - section.start_rva + section.start_raw
            return 0
        
        def raw_to_va(raw_addr):
            return raw_to_rva(raw_addr) + image_base
        
        def va_to_raw(va_addr):
            return rva_to_raw(va_addr - image_base)
        
        reloc_section = None
        for section in sections:
            if section.name == b".reloc":
                reloc_section = section
                break
        
        if reloc_section is None:
            raise Exception(".reloc section not found.")
        
        f.seek(0x80)
        # This is the entirety of the IMAGE_RICH_HEADER, and the PE header up to and not including the directory information. There're sections after that but we won't check them because I think we have enough assurance that this is the right version.
        init_data = b"\x8F\x3B\x80\x29\xCB\x5A\xEE\x7A\xCB\x5A\xEE\x7A\xCB\x5A\xEE\x7A\x58\x14\x76\x7A\xCF\x5A\xEE\x7A\xD0\xC7\x70\x7A\xC7\x5A\xEE\x7A\xCE\x56\x8E\x7A\xCA\x5A\xEE\x7A\xD0\xC7\x72\x7A\xC3\x5A\xEE\x7A\x19\x08\x72\x7A\xCD\x5A\xEE\x7A\xEC\x9C\x95\x7A\xCF\x5A\xEE\x7A\xA4\x2C\x72\x7A\xCD\x5A\xEE\x7A\xC2\x22\x7D\x7A\xED\x5A\xEE\x7A\xA4\x2C\x45\x7A\xCE\x5A\xEE\x7A\xCE\x56\xB1\x7A\xC1\x5A\xEE\x7A\xEC\x9C\x83\x7A\xCC\x5A\xEE\x7A\xC2\x22\x6D\x7A\xC0\x5A\xEE\x7A\xB6\x23\x33\x7A\xC8\x5A\xEE\x7A\xCB\x5A\xEF\x7A\x3F\x58\xEE\x7A\xD0\xC7\x44\x7A\x80\x5A\xEE\x7A\xD0\xC7\x45\x7A\x7E\x5B\xEE\x7A\xD0\xC7\x75\x7A\xCA\x5A\xEE\x7A\xD0\xC7\x74\x7A\xCA\x5A\xEE\x7A\xD0\xC7\x73\x7A\xCA\x5A\xEE\x7A\x52\x69\x63\x68\xCB\x5A\xEE\x7A\x00\x00\x00\x00\x00\x00\x00\x00\x50\x45\x00\x00\x4C\x01\x05\x00\x8D\x8E\x64\x64\x00\x00\x00\x00\x00\x00\x00\x00\xE0\x00\x22\x01\x0B\x01\x0A\x00\x00\xBC\x08\x01\x00\x1C\xEB\x00\x00\x00\x00\x00\xB4\xFA\xF7\x00\x00\x10\x00\x00\x00\xD0\x08\x01\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x00\x00\xF4\x01\x00\x04\x00\x00\xC5\x1B\x8B\x01\x02\x00\x40\x81\x40\x4B\x4C\x00\x40\x4B\x4C\x00\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00"
        if f.read(len(init_data)) != init_data:
            return False
        
        reloc_table = RelocTable()
        reloc_table.populate_from_file(f)
        
        def code_to_bytearray_with_relocs(code):
            pieces = [piece for piece in code.strip().split(" ") if piece]
            code_bytes = bytearray(len(pieces))
            relocs = []
            reloc_start = -1
            for piece_index in range(0, len(pieces)):
                piece = pieces[piece_index]
                if not piece:
                    continue
                if piece[0] == '[':
                    piece = piece[1:]
                    if reloc_start != -1:
                        raise Exception("Nested reloc not allowed.")
                    reloc_start = piece_index
                if piece[-1] == ']':
                    piece = piece[0:-1]
                    if reloc_start == -1:
                        raise Exception("Unmatched ].")
                    if piece_index - reloc_start != 3:
                        raise Exception("Only relocs of size 4 allowed.")
                    relocs.append(reloc_start)
                    reloc_start = -1
                if not piece:
                    raise Exception("[] not allowed.")
                code_bytes[piece_index] = int(piece, 16)
            return (code_bytes, relocs)
            
        def apply_code(pos, code):
            code_bytes, relocs = code_to_bytearray_with_relocs(code)
            va = raw_to_va(pos)
            reloc_table.remove_entries(
                reloc_table.find_relocs_in_region(
                    va,
                    va + len(code_bytes)
                )
            )
            f.seek(pos)
            f.write(code_bytes)
            for reloc in relocs:
                reloc_table.add_entry(va + reloc)
        
        # REDGfxMoviePlayer_MenuInterlude::execIsAsyncLoading
        apply_code(0xaff080,
        # the original contents of the function and the REDGfxMoviePlayer_MenuInterlude::execProcAsyncLoading below it
            "8b 44 24 04 ff 40 18 56 8b f1 8b 48 18 80 39 41 75 10 41 6a 00 89 48 18 8b 48 14 50 ff 15 [24 54 a3 01] 8b ce e8 e7 89 fa ff 8b 4c 24 0c 89 01 5e c2 08 00 cc cc cc cc cc cc cc cc cc cc cc cc cc 51 0f 57 c0 56 8b 74 24 0c 8b 46 18 f3 0f 11 44 24 04 0f b6 10 40 57 89 46 18 8b 14 95 [20 53 a3 01] 8d 44 24 08 50 8b f9 8b 4e 14 56 ff d2 ff 46 18 8b 46 18 80 38 41 75 10 8b 4e 14 6a 00 40 56 89 46 18 ff 15 [24 54 a3 01] f3 0f 10 44 24 08 51 8b cf f3 0f 11 04 24 e8 94 a6 03 00 5f 5e 59 c2 08 00 cc cc cc cc cc cc cc cc cc cc cc cc cc cc")
        
        # FFileManagerWindows::GetFileTimestamp
        apply_code(0xbeb0, "6a ff 68 [68 6a 38 01] 64 a1 00 00 00 00 50 83 ec 60 a1 [10 1b a1 01] 33 c4 89 44 24 5c 53 55 56 57 a1 [10 1b a1 01] 33 c4 50 8d 44 24 74 64 a3 00 00 00 00 8b bc 24 84 00 00 00 8b f1 8b 06 8b 50 54 57 8d 4c 24 2c 51 8b ce ff d2 33 db 89 5c 24 7c 39 58 04 74 04 8b 00 eb 05 b8 [a0 0b 4a 01] 8b 16 8b 52 58 50 8d 44 24 20 50 8b ce ff d2 39 58 04 74 04 8b 00 eb 05 b8 [a0 0b 4a 01] 8b 2d [44 d5 48 01] 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e f2 0f 10 05 [b0 0d 4a 01] f2 0f 11 44 24 14 8b 44 24 1c 89 5c 24 24 89 5c 24 20 3b c3 74 0d 50 e8 a2 fb 01 00 83 c4 04 89 5c 24 1c 8b 44 24 28 c7 44 24 7c ff ff ff ff 89 5c 24 30 89 5c 24 2c 3b c3 74 09 50 e8 7d fb 01 00 83 c4 04 f2 0f 10 44 24 14 66 0f 2e 05 [b0 0d 4a 01] 9f f6 c4 44 7a 5d 8b 16 8b 52 54 57 8d 44 24 38 50 8b ce ff d2 39 58 04 74 04 8b 00 eb 05 b8 [a0 0b 4a 01] 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e f2 0f 10 05 [b0 0d 4a 01] f2 0f 11 44 24 14 8b 44 24 34 89 5c 24 3c 89 5c 24 38 3b c3 74 09 50 e8 0c fb 01 00 83 c4 04 dd 44 24 14 8b 4c 24 74 64 89 0d 00 00 00 00 59 5f 5e 5d 5b 8b 4c 24 5c 33 cc e8 cc 23 f7 00 83 c4 6c c2 04 00")
        
        f.seek(0xae9714)  # the 00eea314 74 16 JZ LAB_00eea32c instruction (if (bBlocking != 0) {) in the UREDCharaAssetLoader::LoadAssets(...)
        f.write(b"\x74\x16")
        
        # loadingTimewasteCounter = 60; in some unknown place
        # the instructions are MOV dword ptr [loadingTimewasteCounter],0x3c (c7 05 10 05 e4 01 3c 00 00 00)
        offsets = (
            0xb108cb,
            0xb1092f,
            0xb10993,
            0xb109f7,
            0xb10a77
        )
        for offset in offsets:
            f.seek(offset + 6)  # only changing the value of the constant in the assignment
            f.write(struct.pack("<i", 60))
        
        f.seek(0x15e00ec)  # the amountOfTimeToWasteOnInitialMenus variable
        f.write(struct.pack("<i", 90))  # 0x5a, the original value of the amountOfTimeToWasteOnInitialMenus variable
        
        reloc_table.commit_all_writes(f)
    
    if also_make_intro_cutscenes_unskippable:
        binaries_win32_folder = os.path.dirname(guilty_gear_xrd_exe_path)
        binaries_folder = os.path.dirname(binaries_win32_folder)
        root_folder = os.path.dirname(binaries_folder)
        ini_path = os.path.join(root_folder, "REDGame", "Config", "REDEngine.ini")
        if not os.path.isfile(ini_path):
            return True
        
        with open(ini_path, "rb") as inif:
            sz = inif.seek(0, os.SEEK_END)
            inif.seek(0)
            ini_data = bytearray(sz)
            inif.readinto(ini_data)
        
        seq = b"SkippableMovies=Splash_Steam"
        extra = 0
        pos = ini_data.find(seq)
        if pos != -1:
            if pos > 0 and ini_data[pos - 1] == ord('\n'):
                exta = 1
                if pos > 1 and ini_data[pos - 2] == ord('\r'):
                    extra = 2
            ini_data[pos - extra : pos + len(seq)] = b""
            
            with open(ini_path, "wb") as inif:
                inif.write(ini_data)
                
        movie_path_to = os.path.join(root_folder, "REDGame", "Movies", "Splash_Steam.wmv")
        movie_path_from = os.path.join(root_folder, "REDGame", "Movies", "Splash_Steam_.wmv")
        if not os.path.isfile(movie_path_to) and os.path.isfile(movie_path_from):
            os.rename(movie_path_from, movie_path_to)
    
    return True