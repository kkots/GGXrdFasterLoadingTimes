#include "pch.h"
// The purpose of this program is to patch GuiltyGearXrd.exe to speed up the
// loading of assets on pre-battle loading screens
#include <iostream>
#include <string>
#ifndef FOR_LINUX
#include "resource.h"
#include "ConsoleEmulator.h"
#include "InjectorCommonOut.h"
#include <commdlg.h>
#else
#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#endif
#include <vector>
#include "Version.h"
#include "YesNoCancel.h"


#ifndef FOR_LINUX
InjectorCommonOut outputObject;
#define CrossPlatformString std::wstring
#define CrossPlatformChar wchar_t
#define CrossPlatformPerror _wperror
#define CrossPlatformText(txt) L##txt
#define CrossPlatformCout outputObject
#define CrossPlatformNumberToString std::to_wstring
extern void GetLine(std::wstring& line);
extern void AskYesNoCancel(const char* prompt, YesNoCancel* result);
#else
void GetLine(std::string& line) { std::getline(std::cin, line); }
void AskYesNoCancel(const char* prompt, YesNoCancel* result) {
	std::string line;
	while (true) {
		std::cout << "Type 'y' to say 'Yes', 'n' to say 'No' and 'c' to 'Cancel', and hit Enter.\n";
		std::getline(std::cin, line);
		if (strcmp(line.c_str(), "y") == 0 || strcmp(line.c_str(), "Y") == 0) {
			*result = YesNoCancel_Yes;
			return;
		} else if (strcmp(line.c_str(), "n") == 0 || strcmp(line.c_str(), "N") == 0) {
			*result = YesNoCancel_No;
			return;
		} else if (strcmp(line.c_str(), "c") == 0 || strcmp(line.c_str(), "C") == 0) {
			*result = YesNoCancel_Cancel;
			return;
		}
	}
}
#define CrossPlatformString std::string
#define CrossPlatformChar char
#define CrossPlatformPerror perror
#define CrossPlatformText(txt) txt
#define CrossPlatformCout std::cout
#define CrossPlatformNumberToString std::to_string

typedef unsigned int DWORD;

// from winnt.h
//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_DIR64                 10
#define sprintf_s sprintf

#endif

#ifndef FOR_LINUX
#define PATH_SEPARATOR L'\\'
#else
#define PATH_SEPARATOR '/'
#endif

#ifdef FOR_LINUX
void trim(std::string& str) {
    if (str.empty()) return;
    auto it = str.end();
    --it;
    while (true) {
        if (*it > 32) break;
        if (it == str.begin()) {
            str.clear();
            return;
        }
        --it;
    }
    str.resize(it - str.begin() + 1);
}
#endif

char exeName[] = "\x3d\x6b\x5f\x62\x6a\x6f\x3d\x5b\x57\x68\x4e\x68\x5a\x24\x5b\x6e\x5b\xf6";

int findLast(const CrossPlatformString& str, CrossPlatformChar character) {
	if (str.empty() || str.size() > 0xFFFFFFFF) return -1;
	auto it = str.cend();
	--it;
	while (true) {
		if (*it == character) return (it - str.cbegin()) & 0xFFFFFFFF;
		if (it == str.cbegin()) return -1;
		--it;
	}
	return -1;
}

// Does not include trailing slash
CrossPlatformString getParentDir(const CrossPlatformString& path) {
	CrossPlatformString result;
	int lastSlashPos = findLast(path, PATH_SEPARATOR);
	if (lastSlashPos == -1) return result;
	result.insert(result.begin(), path.cbegin(), path.cbegin() + lastSlashPos);
	return result;
}

CrossPlatformString getFileName(const CrossPlatformString& path) {
	CrossPlatformString result;
	int lastSlashPos = findLast(path, PATH_SEPARATOR);
	if (lastSlashPos == -1) return path;
	result.insert(result.begin(), path.cbegin() + lastSlashPos + 1, path.cend());
	return result;
}

bool fileExists(const CrossPlatformString& path) {
	#ifndef FOR_LINUX
	DWORD fileAtrib = GetFileAttributesW(path.c_str());
	if (fileAtrib == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	return true;
	#else
	struct stat buf;
	int result = stat(path.c_str(), &buf);
	if (result == 0) return true;
	if (result == ENOENT) return false;
	std::cout << "Could not access \"" << path << "\":\n";
	perror(nullptr);
	return false;
	#endif
}

int sigscan(const char* start, const char* end, const char* sig, const char* mask) {
	const char* startPtr = start;
	const size_t maskLen = strlen(mask);
	if ((size_t)(end - start) < maskLen) return -1;
	const size_t seekLength = end - start - maskLen + 1;
	for (size_t seekCounter = seekLength; seekCounter != 0; --seekCounter) {
		const char* stringPtr = startPtr;

		const char* sigPtr = sig;
		for (const char* maskPtr = mask; true; ++maskPtr) {
			const char maskPtrChar = *maskPtr;
			if (maskPtrChar != '?') {
				if (maskPtrChar == '\0') return (startPtr - start) & 0xFFFFFFFF;
				if (*sigPtr != *stringPtr) break;
			}
			++sigPtr;
			++stringPtr;
		}
		++startPtr;
	}
	return -1;
}

int sigscanUp(const char* start, const char* startBoundary, int limit, const char* sig, const char* mask) {
	const char* const startBoundaryOrig = startBoundary;
	if (limit <= 0 || start < startBoundary) return -1;
	if ((uintptr_t)start < (uintptr_t)limit - 1) limit = (int)((uintptr_t)start & 0xFFFFFFFF) + 1;
	if (start - (limit - 1) > startBoundary) {
		startBoundary = start - (limit - 1);
	}
	const char* startPtr = start;
	while (startPtr >= startBoundary) {
		const char* stringPtr = startPtr;

		const char* sigPtr = sig;
		for (const char* maskPtr = mask; true; ++maskPtr) {
			const char maskPtrChar = *maskPtr;
			if (maskPtrChar != '?') {
				if (maskPtrChar == '\0') return (startPtr - startBoundaryOrig) & 0xFFFFFFFF;
				if (*sigPtr != *stringPtr) break;
			}
			++sigPtr;
			++stringPtr;
		}
		--startPtr;
	}
	return -1;
}

int sigscanForward(const char* start, const char* end, int limit, const char* sig, const char* mask) {
	if (end - start < limit) limit = (end - start) & 0xFFFFFFFF;
	if (limit <= 0) return -1;
	if (end - start > limit) end = start + limit;
	return sigscan(start, end, sig, mask);
}

enum SigscanRecursiveResult {
	SigscanRecursiveResult_Continue,
	SigscanRecursiveResult_Stop
};

int sigscanRecursive(const char* start, const char* end, const char* sig, const char* mask, SigscanRecursiveResult(*callback)(int pos, void* userData), void* userData) {
	const char* const startOrig = start;
	while (true) {
		int pos = sigscan(start, end, sig, mask);
		if (pos == -1) return -1;
		int posCorrected = pos + (start - startOrig) & 0xFFFFFFFF;
		SigscanRecursiveResult result = callback(posCorrected, userData);
		if (result == SigscanRecursiveResult_Stop) return posCorrected;
		start += pos + 1;
		if (start >= end) return -1;
	}
}

template<int N>
int sigscanEveryNBytes(const char* start, const char* end, const char* sig) {
	if (end - start < N) return -1;
	const char* startPtr = start;
	const int seekLength = ((end - start) & 0xFFFFFFFF) - N + 1;
	for (int seekCounter = seekLength; seekCounter > 0; seekCounter -= N) {
		const char* stringPtr = startPtr;

		const char* sigPtr = sig;
		int n;
		for (n = N; n > 0; --n) {
			if (*sigPtr != *stringPtr) break;
			++sigPtr;
			++stringPtr;
		}
		if (n == 0) return (startPtr - start) & 0xFFFFFFFF;
		startPtr += N;
	}
	return -1;
}

bool readWholeFile(FILE* file, std::vector<char>& wholeFile) {
	fseek(file, 0, SEEK_END);
	size_t fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);
	wholeFile.resize(fileSize);
	char* wholeFilePtr = &wholeFile.front();
	size_t readBytesTotal = 0;
	while (true) {
		size_t sizeToRead = 1024;
		if (fileSize - readBytesTotal < 1024) sizeToRead = fileSize - readBytesTotal;
		if (sizeToRead == 0) break;
		size_t readBytes = fread(wholeFilePtr, 1, sizeToRead, file);
		if (readBytes != sizeToRead) {
			if (ferror(file)) {
				CrossPlatformPerror(CrossPlatformText("Error reading file"));
				return false;
			}
			// assume feof
			break;
		}
		wholeFilePtr += 1024;
		readBytesTotal += 1024;
	}
	return true;
}

std::string repeatCharNTimes(char charToRepeat, int times) {
	std::string result;
	result.resize(times, charToRepeat);
	return result;
}

int calculateRelativeCall(DWORD callInstructionAddress, DWORD calledAddress) {
	return (int)calledAddress - (int)(callInstructionAddress + 5);
}

DWORD followRelativeCall(DWORD callInstructionAddress, const char* callInstructionAddressInRam) {
	int offset = *(int*)(callInstructionAddressInRam + 1);
	return callInstructionAddress + 5 + offset;
}

struct Section {
	std::string name;
	
	// RVA. Virtual address offset relative to the virtual address start of the entire .exe.
	// So let's say the whole .exe starts at 0x400000 and RVA is 0x400.
	// That means the non-relative VA is 0x400000 + RVA = 0x400400.
	// Note that the .exe, although it does specify a base virtual address for itself on the disk,
	// may actually be loaded anywhere in the RAM once it's launched, and that RAM location will
	// become its base virtual address.
	DWORD relativeVirtualAddress = 0;
	
	// VA. Virtual address within the .exe.
	// A virtual address is the location of something within the .exe once it's loaded into memory.
	// An on-disk, file .exe is usually smaller than when it's loaded so it creates this distinction
	// between raw address and virtual address.
	DWORD virtualAddress = 0;
	
	// The size in terms of virtual address space.
	DWORD virtualSize = 0;
	
	// Actual position of the start of this section's data within the file.
	DWORD rawAddress = 0;
	
	// Size of this section's data on disk in the file.
	DWORD rawSize = 0;
};

std::vector<Section> readSections(FILE* file, DWORD* imageBase) {
	size_t readBytes;
	std::vector<Section> result;

	DWORD peHeaderStart = 0;
	fseek(file, 0x3C, SEEK_SET);
	readBytes = fread(&peHeaderStart, 4, 1, file);

	unsigned short numberOfSections = 0;
	fseek(file, peHeaderStart + 0x6, SEEK_SET);
	readBytes = fread(&numberOfSections, 2, 1, file);

	DWORD optionalHeaderStart = peHeaderStart + 0x18;

	unsigned short optionalHeaderSize = 0;
	fseek(file, peHeaderStart + 0x14, SEEK_SET);
	readBytes = fread(&optionalHeaderSize, 2, 1, file);

	fseek(file, peHeaderStart + 0x34, SEEK_SET);
	readBytes = fread(imageBase, 4, 1, file);

	DWORD sectionsStart = optionalHeaderStart + optionalHeaderSize;
	DWORD sectionStart = sectionsStart;
	for (size_t sectionCounter = numberOfSections; sectionCounter != 0; --sectionCounter) {
		Section newSection;
		fseek(file, sectionStart, SEEK_SET);
		newSection.name.resize(8);
		readBytes = fread(&newSection.name.front(), 1, 8, file);
		newSection.name.resize(strlen(newSection.name.c_str()));
		readBytes = fread(&newSection.virtualSize, 4, 1, file);
		readBytes = fread(&newSection.relativeVirtualAddress, 4, 1, file);
		newSection.virtualAddress = *imageBase + newSection.relativeVirtualAddress;
		readBytes = fread(&newSection.rawSize, 4, 1, file);
		readBytes = fread(&newSection.rawAddress, 4, 1, file);
		result.push_back(newSection);
		sectionStart += 40;
	}

	return result;
}

DWORD rawToVa(const std::vector<Section>& sections, DWORD rawAddr) {
	if (sections.empty()) return 0;
	auto it = sections.cend();
	--it;
	while (true) {
		const Section& section = *it;
		if (rawAddr >= section.rawAddress) {
			return rawAddr - section.rawAddress + section.virtualAddress;
		}
		if (it == sections.cbegin()) break;
		--it;
	}
	return 0;
}

DWORD vaToRaw(const std::vector<Section>& sections, DWORD va) {
	if (sections.empty()) return 0;
	auto it = sections.cend();
	--it;
	while (true) {
		const Section& section = *it;
		if (va >= section.virtualAddress) {
			return va - section.virtualAddress + section.rawAddress;
		}
		if (it == sections.cbegin()) break;
		--it;
	}
	return 0;
}

DWORD vaToRva(DWORD va, DWORD imageBase) {
	return va - imageBase;
}

DWORD rvaToVa(DWORD rva, DWORD imageBase) {
	return rva + imageBase;
}

DWORD rvaToRaw(const std::vector<Section>& sections, DWORD rva) {
	if (sections.empty()) return 0;
	auto it = sections.cend();
	--it;
	while (true) {
		const Section& section = *it;
		if (rva >= section.relativeVirtualAddress) {
			return rva - section.relativeVirtualAddress + section.rawAddress;
		}
		if (it == sections.cbegin()) break;
		--it;
	}
	return 0;
}

/// <summary>
/// Writes a relocation entry at the current file position.
/// </summary>
/// <param name="relocType">See macros starting with IMAGE_REL_BASED_</param>
/// <param name="va">Virtual address of the place to be relocated by the reloc.</param>
void writeRelocEntry(FILE* file, char relocType, DWORD va) {
	DWORD vaMemoryPage = va & 0xFFFFF000;
	unsigned short relocEntry = ((DWORD)relocType << 12) | ((va - vaMemoryPage) & 0x0FFF);
	fwrite(&relocEntry, 2, 1, file);
}

/// <summary>
/// Specify nameCounter 0 to not use it
/// </summary>
CrossPlatformString generateBackupPath(const CrossPlatformString& parentDir, const CrossPlatformString& fileName, int nameCounter) {
	CrossPlatformString result;
	
	int pos = findLast(fileName, CrossPlatformText('.'));
	result = parentDir + PATH_SEPARATOR;
	if (pos == -1) {
		result += fileName + CrossPlatformText("_backup");
		if (nameCounter) {
			result += CrossPlatformNumberToString(nameCounter);
		}
	} else {
		result.append(fileName.begin(), fileName.begin() + pos);
		result += CrossPlatformText("_backup");
		if (nameCounter) {
			result += CrossPlatformNumberToString(nameCounter);
		}
		result += fileName.c_str() + pos;
	}
	
	return result;
}

bool crossPlatformOpenFile(FILE** file, const CrossPlatformString& path) {
	#ifndef FOR_LINUX
	errno_t errorCode = _wfopen_s(file, path.c_str(), CrossPlatformText("r+b"));
	if (errorCode != 0 || !*file) {
		if (errorCode != 0) {
			wchar_t buf[1024];
			_wcserror_s(buf, errorCode);
			CrossPlatformCout << L"Failed to open file: " << buf << L'\n';
		} else {
			CrossPlatformCout << L"Failed to open file.\n";
		}
		if (*file) {
			fclose(*file);
		}
		return false;
	}
	return true;
	#else
	*file = fopen(path.c_str(), "r+b");
	if (!*file) {
		perror("Failed to open file");
		return false;
	}
	return true;
	#endif
}

#ifdef FOR_LINUX
void copyFileLinux(const std::string& pathSource, const std::string& pathDestination) {
	std::ifstream src(pathSource, std::ios::binary);
	std::ofstream dst(pathDestination, std::ios::binary);

	dst << src.rdbuf();
}
#endif

struct FoundReloc {
	char type;  // see macros starting with IMAGE_REL_BASED_
	DWORD regionVa;  // position of the place that the reloc is patching
	DWORD relocVa;  // position of the reloc entry itself
};

struct FoundRelocBlock {
	const char* ptr;  // points to the page base member of the block
	DWORD pageBaseVa;  // page base of all patches that the reloc is responsible for
	DWORD relocVa;  // position of the reloc block itself. Points to the page base member of the block
	DWORD size;  // size of the entire block, including the page base and block size and all entries
};

struct RelocBlockIterator {
	
	const char* const relocTableOrig;
	const DWORD relocTableVa;
	const DWORD imageBase;
	DWORD relocTableSize;  // remaining size
	const char* relocTableNext;
	
	RelocBlockIterator(const char* relocTable, DWORD relocTableVa, DWORD relocTableSize, DWORD imageBase)
		:
		relocTableOrig(relocTable),
		relocTableVa(relocTableVa),
		imageBase(imageBase),
		relocTableSize(relocTableSize),
		relocTableNext(relocTable) { }
		
	bool getNext(FoundRelocBlock& block) {
		
		if (relocTableSize == 0) return false;
		
		const char* relocTable = relocTableNext;
		
		DWORD pageBaseRva = *(DWORD*)relocTable;
		DWORD pageBaseVa = rvaToVa(pageBaseRva, imageBase);
		DWORD blockSize = *(DWORD*)(relocTable + 4);
		
		relocTableNext += blockSize;
		
		if (relocTableSize <= blockSize) relocTableSize = 0;
		else relocTableSize -= blockSize;
		
		block.ptr = relocTable;
		block.pageBaseVa = pageBaseVa;
		block.relocVa = relocTableVa + ((uintptr_t)(relocTable - relocTableOrig) & 0xFFFFFFFF);
		block.size = blockSize;
		return true;
	}
};

struct RelocEntryIterator {
	const DWORD blockVa;
	const char* const blockStart;
	const char* ptr;  // the pointer to the next entry
	DWORD blockSize;  // the remaining, unconsumed size of the block (we don't actually modify any data, so maybe consume is not the right word)
	const DWORD pageBaseVa;
	
	/// <param name="ptr">The address of the start of the whole reloc block, NOT the first member.</param>
	/// <param name="blockSize">The size of the entire reloc block, in bytes, including the page base member and the block size member.</param>
	/// <param name="pageBaseVa">The page base of the reloc block.</param>
	/// <param name="blockVa">The Virtual Address where the reloc block itself is located. Must point to the page base member of the block.</param>
	RelocEntryIterator(const char* ptr, DWORD blockSize, DWORD pageBaseVa, DWORD blockVa)
		:
		ptr(ptr + 8),
		blockSize(blockSize <= 8 ? 0 : blockSize - 8),
		pageBaseVa(pageBaseVa),
		blockStart(ptr),
		blockVa(blockVa) { }
		
	RelocEntryIterator(const FoundRelocBlock& block) : RelocEntryIterator(block.ptr, block.size, block.pageBaseVa, block.relocVa) { }
	
	bool getNext(FoundReloc& reloc) {
		if (blockSize == 0) return false;
		
		unsigned short entry = *(unsigned short*)ptr;
		char blockType = (entry & 0xF000) >> 12;
		
		DWORD entrySize = blockType == IMAGE_REL_BASED_HIGHADJ ? 4 : 2;
		
		reloc.type = blockType;
		reloc.regionVa = pageBaseVa | (entry & 0xFFF);
		reloc.relocVa = blockVa + ((uintptr_t)(ptr - blockStart) & 0xFFFFFFFF);
		
		if (blockSize <= entrySize) blockSize = 0;
		else blockSize -= entrySize;
		
		ptr += entrySize;
		
		return true;
	}
	
};

struct RelocTable {
	
	char* relocTable;  // the pointer pointing to the reloc table's start. Typically that'd be the page base member of the first block
	DWORD va;  // Virtual Address of the reloc table's start
	DWORD raw;  // the raw position of the reloc table's start
	DWORD size;  // the size of the whole reloc table
	int sizeWhereRaw;  // the raw location of the size of the whole reloc table
	DWORD imageBase;  // the Virtual Address of the base of the image
	
	// Finds the file position of the start of the reloc table and its size
	void findRelocTable(char* wholeFileBegin, const std::vector<Section>& sections, DWORD imageBase) {
		
		const char* peHeaderStart = wholeFileBegin + *(DWORD*)(wholeFileBegin + 0x3C);
		
	    const char* relocSectionHeader = peHeaderStart + 0xA0;
	    
	    DWORD relocRva = *(DWORD*)relocSectionHeader;
	    DWORD* relocSizePtr = (DWORD*)relocSectionHeader + 1;
	    sizeWhereRaw = (uintptr_t)((const char*)relocSizePtr - wholeFileBegin) & 0xFFFFFFFF;
	    
	    va = rvaToVa(relocRva, imageBase);
	    raw = rvaToRaw(sections, relocRva);
	    relocTable = wholeFileBegin + raw;
	    size = *relocSizePtr;
	    this->imageBase = imageBase;
	}
	
	// region specified in Virtual Address space
	std::vector<FoundReloc> findRelocsInRegion(DWORD regionStart, DWORD regionEnd) const {
		std::vector<FoundReloc> result;
		
		RelocBlockIterator blockIterator(relocTable, va, size, imageBase);
		
		FoundRelocBlock block;
		while (blockIterator.getNext(block)) {
			if (block.pageBaseVa >= regionEnd || (block.pageBaseVa | 0xFFF) + 8 < regionStart) {
				continue;
			}
			RelocEntryIterator entryIterator(block);
			FoundReloc reloc;
			while (entryIterator.getNext(reloc)) {
				if (reloc.type == IMAGE_REL_BASED_ABSOLUTE) continue;
				DWORD patchVa = reloc.regionVa;
				DWORD patchSize = 4;
				
				switch (reloc.type) {
					case IMAGE_REL_BASED_HIGH: patchVa += 2; patchSize = 2; break;
					case IMAGE_REL_BASED_LOW: patchSize = 2; break;
					case IMAGE_REL_BASED_HIGHLOW: break;
					case IMAGE_REL_BASED_HIGHADJ:
						patchSize = 2;
						break;
					case IMAGE_REL_BASED_DIR64: patchSize = 8; break;
				}
				
				if (patchVa >= regionEnd || patchVa + patchSize < regionStart) continue;
				
				result.push_back(reloc);
			}
		}
		return result;
	}
	
	FoundRelocBlock findLastRelocBlock() const {
		
		RelocBlockIterator blockIterator(relocTable, va, size, imageBase);
		
		FoundRelocBlock block;
		while (blockIterator.getNext(block));
		return block;
	}
	
	// returns empty, unused entries that could potentially be reused for the desired vaToPatch
	std::vector<FoundReloc> findReusableRelocEntries(DWORD vaToPatch) const {
		std::vector<FoundReloc> result;
		
		RelocBlockIterator blockIterator(relocTable, va, size, imageBase);
		
		FoundRelocBlock block;
		while (blockIterator.getNext(block)) {
			
			if (!(
				block.pageBaseVa <= vaToPatch && vaToPatch <= (block.pageBaseVa | 0xFFF)
			)) {
				continue;
			}
			
			RelocEntryIterator entryIterator(block);
			FoundReloc reloc;
			while (entryIterator.getNext(reloc)) {
				if (reloc.type == IMAGE_REL_BASED_ABSOLUTE) {
					result.push_back(reloc);
				}
			}
		}
		
		return result;
	}
	
	template<typename T>
	void write(FILE* file, int filePosition, T value) {
		fseek(file, filePosition, SEEK_SET);
		fwrite(&value, sizeof(T), 1, file);
	}
	
	template<typename T, size_t size>
	void write(FILE* file, int filePosition, T (&value)[size]) {
		fseek(file, filePosition, SEEK_SET);
		fwrite(value, sizeof(T), size, file);
	}
	
	// Resize the whole reloc table.
	// Writes both into the file and into the size member.
	void increaseSizeBy(FILE* file, DWORD n) {
		
	    DWORD relocSizeRoundUp = (size + 3) & ~3;
		size = relocSizeRoundUp + n;  // reloc size includes the page base VA and the size of the reloc table entry and of all the entries
		// but I still have to round it up to 32 bits
		
		write(file, sizeWhereRaw, size);
		
	}
	
	// Try to:
	// 1) Reuse an existing 0000 entry that has a page base from which we can reach the target;
	// 2) Try to expand the last block if the target is reachable from its page base;
	// 3) Add a new block to the end of the table with that one entry.
	void addEntry(FILE* file, DWORD vaToRelocate, char type) {
		unsigned short relocEntry = ((unsigned short)type << 12) | (vaToRva(vaToRelocate, imageBase) & 0xFFF);
		
		std::vector<FoundReloc> reusableEntries = findReusableRelocEntries(vaToRelocate);
		if (!reusableEntries.empty()) {
			const FoundReloc& firstReloc = reusableEntries.front();
			write(file, firstReloc.relocVa - va + raw, relocEntry);
			*(unsigned short*)(relocTable + firstReloc.relocVa - va) = relocEntry;
			
			CrossPlatformCout << "Reused reloc entry located at va:0x" << std::hex
				<< firstReloc.relocVa << " that now relocates va:0x" << vaToRelocate << std::dec << ".\n";
			return;
		}
		
		const FoundRelocBlock lastBlock = findLastRelocBlock();
		if (lastBlock.pageBaseVa <= vaToRelocate && vaToRelocate <= (lastBlock.pageBaseVa | 0xFFF)) {
			DWORD newSize = lastBlock.size + 2;
			newSize  = (newSize + 3) & ~3;  // round the size up to 32 bits
			
			DWORD oldTableSize = size;
			DWORD sizeIncrease = newSize - lastBlock.size;
			increaseSizeBy(file, sizeIncrease);
			
			int pos = lastBlock.relocVa - va + raw;
			write(file, pos + 4, newSize);
			*(DWORD*)(relocTable + lastBlock.relocVa - va + 4) = newSize;
			
			write(file, pos + lastBlock.size, relocEntry);
			unsigned short* newEntryPtr = (unsigned short*)(relocTable + lastBlock.relocVa - va + lastBlock.size);
			*newEntryPtr = relocEntry;
			
			if (sizeIncrease > 2) {
				unsigned short zeros = 0;
				write(file, pos + lastBlock.size + 2, zeros);
				*(newEntryPtr + 1) = zeros;
			}
			
			CrossPlatformCout << "Expanded reloc block located at va:0x" << std::hex
				<< lastBlock.relocVa << " to size 0x" << newSize << ", and whole reloc table expanded to size "
				<< size << " (from " << oldTableSize << "), and added a reloc entry located at va:0x" << std::hex
				<< lastBlock.relocVa + lastBlock.size << " that now relocates va:0x" << vaToRelocate << std::dec << ".\n";
			return;
		}
		
		DWORD oldSize = size;
	    // "Each block must start on a 32-bit boundary." - Microsoft
		DWORD oldSizeRoundedUp = (oldSize + 3) & ~3;
		
		// add a new reloc table with one entry
		increaseSizeBy(file, 12);  // changes 'size'
		
		
		DWORD rvaToRelocate = vaToRva(vaToRelocate, imageBase);
		DWORD newRelocPageBase = rvaToRelocate & 0xFFFFF000;
		
		DWORD tableData[3];
		tableData[0] = newRelocPageBase;
		tableData[1] = 12;  // page base (4) + size of whole block (4) + one entry (2) + padding to make it 32-bit complete (2)
		tableData[2] = relocEntry;
		
		write(file, raw + oldSizeRoundedUp, tableData);
		memcpy(relocTable + oldSizeRoundedUp, tableData, sizeof tableData);
		
		CrossPlatformCout << "Expanded reloc table from size 0x" << std::hex << oldSize
			<< " to size 0x" << size << ", and added a new reloc block, located at va:0x"
			<< va + oldSizeRoundedUp << ", and added a new reloc entry into it located at va:0x"
			<< va + oldSizeRoundedUp + 8 << " which relocates va:0x" << vaToRelocate << std::dec << ".\n";
	}
	
	// fills entry with zeros, diabling it. Does not change the size of either the reloc table or the reloc block
	void removeEntry(FILE* file, const FoundReloc& reloc) {
		unsigned short zeros = 0;
		write(file, reloc.relocVa - va + raw, zeros);
		*(unsigned short*)(relocTable + reloc.relocVa - va) = zeros;
		
		CrossPlatformCout << "Removing reloc entry located at va:0x" << std::hex
			<< reloc.relocVa << " that relocates va:0x" << reloc.regionVa << std::dec << ".\n";
	}
	
};

// you must use the returned result immediately or copy it somewhere. Do not store it as-is. This function is not thread-safe either
const char* printRelocType(char type) {
	static char printRelocTypeBuf[12];  // the maximum possible length of string printed by printf("%d", (int)value), plus null terminating character
	switch (type) {
		case IMAGE_REL_BASED_HIGH: return "IMAGE_REL_BASED_HIGH";
		case IMAGE_REL_BASED_LOW: return "IMAGE_REL_BASED_LOW";
		case IMAGE_REL_BASED_HIGHLOW: return "IMAGE_REL_BASED_HIGHLOW";
		case IMAGE_REL_BASED_HIGHADJ: return "IMAGE_REL_BASED_HIGHADJ";
		case IMAGE_REL_BASED_DIR64: return "IMAGE_REL_BASED_DIR64";
		default: sprintf_s(printRelocTypeBuf, "%d", (int)type); return printRelocTypeBuf;
	}
}

void printFoundRelocs(const std::vector<FoundReloc>& relocs) {
	CrossPlatformCout << '[';
	bool isFirst = true;
	for (const FoundReloc& reloc : relocs) {
		if (!isFirst) CrossPlatformCout << ',';
		else isFirst = false;
		
		CrossPlatformCout << "\n\t{\n\t\t\"type\": \""
			<< printRelocType(reloc.type)
			<< "\",\n"
				"\t\t\"relocVa\": \"0x" << std::hex << reloc.relocVa << "\",\n"
				"\t\t\"regionVa\": \"0x" << reloc.regionVa << std::dec << "\"\n"
				"\t}";
	}
	if (!isFirst) CrossPlatformCout << '\n';
	CrossPlatformCout << ']';
}

bool findExec(const char* name,
			const char* wholeFileBegin,
			const char* rdataBegin, const char* rdataEnd,
			const char* dataBegin, const char* dataEnd,
			const std::vector<Section>& sections,
			DWORD* va, DWORD* pos) {
	
	std::vector<char> nameAr;
	nameAr.resize(strlen(name) + 2);
	memcpy(nameAr.data(), name, nameAr.size() - 2);
	memset(nameAr.data() + (nameAr.size() - 2), 0, 2);
	
	std::vector<char> maskAr;
	maskAr.resize(nameAr.size());
	memset(maskAr.data(), 'x', nameAr.size() - 1);
	maskAr[nameAr.size() - 1] = '\0';
	
	int strPos = sigscan(rdataBegin, rdataEnd, nameAr.data(), maskAr.data());
	if (strPos == -1) {
		CrossPlatformCout << "Failed to find " << name << " string.\n";
		return false;
	}
	strPos += (rdataBegin - wholeFileBegin) & 0xFFFFFFFF;
	CrossPlatformCout << "Found " << name << " string at file:0x" << std::hex << strPos << std::dec << ".\n";
	
	DWORD strVa = rawToVa(sections, strPos);
	
	int strMentionPos = sigscanEveryNBytes<4>(dataBegin, dataEnd, (const char*)&strVa);
	if (strMentionPos == -1) {
		CrossPlatformCout << "Failed to find mention of " << name << " string.\n";
		return false;
	}
	strMentionPos += (dataBegin - wholeFileBegin) & 0xFFFFFFFF;
	CrossPlatformCout << "Found mention of " << name << " string at file:0x" << std::hex << strMentionPos << std::dec << ".\n";
	
	*va = *(DWORD*)(wholeFileBegin + strMentionPos + 4);
	CrossPlatformCout << "Found " << name << " function at va:0x" << std::hex << *va << std::dec << ".\n";
	
	*pos = vaToRaw(sections, *va);
	return true;
}

void meatOfTheProgram() {
	CrossPlatformString ignoreLine;
	#ifndef FOR_LINUX
	CrossPlatformCout << CrossPlatformText("Please select a path to your ") << exeName << CrossPlatformText(" file that will be patched...\n");
	#else
	CrossPlatformCout << CrossPlatformText("Please type in/paste a path to the file, or drag and drop the ")
		<< exeName << CrossPlatformText(" file"
		" (including the file name and extension) that will be patched...\n");
	#endif

	#ifndef FOR_LINUX
	std::wstring szFile;
	szFile.resize(MAX_PATH);

	OPENFILENAMEW selectedFiles{ 0 };
	selectedFiles.lStructSize = sizeof(OPENFILENAMEW);
	selectedFiles.hwndOwner = NULL;
	selectedFiles.lpstrFile = &szFile.front();
	selectedFiles.lpstrFile[0] = L'\0';
	selectedFiles.nMaxFile = (szFile.size() & 0xFFFFFFFF) + 1;
	char scramble[] =
		"\x4d\xf6\x5f\xf6\x64\xf6\x5a\xf6\x65\xf6\x6d\xf6\x69\xf6\x16\xf6\x3b\xf6"
		"\x6e\xf6\x5b\xf6\x59\xf6\x6b\xf6\x6a\xf6\x57\xf6\x58\xf6\x62\xf6\x5b\xf6"
		"\xf6\xf6\x20\xf6\x24\xf6\x3b\xf6\x4e\xf6\x3b\xf6\xf6\xf6\xf6\xf6";
	wchar_t filter[(sizeof scramble - 1) / sizeof (wchar_t)];
	int offset = (int)(
		(GetTickCount64() & 0xF000000000000000ULL) >> (63 - 4)
	) & 0xFFFFFFFF;
	for (int i = 0; i < sizeof scramble - 1; ++i) {
		char c = scramble[i] + offset + 10;
		((char*)filter)[i] = c;
	}
	selectedFiles.lpstrFilter = filter;
	selectedFiles.nFilterIndex = 1;
	selectedFiles.lpstrFileTitle = NULL;
	selectedFiles.nMaxFileTitle = 0;
	selectedFiles.lpstrInitialDir = NULL;
	selectedFiles.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!GetOpenFileNameW(&selectedFiles)) {
		DWORD errCode = CommDlgExtendedError();
		if (!errCode) {
			std::wcout << "The file selection dialog was closed by the user.\n";
		} else {
			std::wcout << "Error selecting file. Error code: 0x" << std::hex << errCode << std::dec << std::endl;
		}
		return;
	}
	szFile.resize(lstrlenW(szFile.c_str()));
	#else
	std::string szFile;
	std::getline(std::cin, szFile);
	trim(szFile);
	if (!szFile.empty() && (szFile.front() == '\'' || szFile.front() == '"')) {
		szFile.erase(szFile.begin());
	}
	if (!szFile.empty() && (szFile.back() == '\'' || szFile.back() == '"')) {
		szFile.erase(szFile.begin() + (szFile.size() - 1));
	}
	trim(szFile);
	if (szFile.empty()) {
		std::cout << "Empty path provided. Aborting.\n";
		return;
	}
	#endif
	CrossPlatformCout << "Selected file: " << szFile.c_str() << std::endl;

	CrossPlatformString fileName = getFileName(szFile);
	CrossPlatformString parentDir = getParentDir(szFile);
	
	CrossPlatformCout << "\n";
	
	YesNoCancel askResult = YesNoCancel_Cancel;
	const char* askPrompt = "Should the loading screen automatically mash for you so that its animation-only portion gets skipped"
		" faster after it finishes loading? Without this, you will either have to mash manually (mash is an overexaggeration,"
		" a single button press may be enough) or not mash and let the loading screen play out.\n";
	CrossPlatformCout << askPrompt;
	AskYesNoCancel(askPrompt, &askResult);
	
	if (askResult == YesNoCancel_Yes) {
		CrossPlatformCout << "'Yes' selected. Not implemented yet, patching will continue as if 'No' is selected.\n";
	} else if (askResult == YesNoCancel_No) {
		CrossPlatformCout << "'No' selected.\n";
	} else if (askResult == YesNoCancel_Cancel) {
		CrossPlatformCout << "'Cancel' selected. Aborting.\n";
		return;
	}
	
	CrossPlatformString backupFilePath = generateBackupPath(parentDir, fileName, 0);
	int backupNameCounter = 1;
	while (fileExists(backupFilePath)) {
		backupFilePath = generateBackupPath(parentDir, fileName, backupNameCounter);
		++backupNameCounter;
	}
	CrossPlatformCout << "Will use backup file path: " << backupFilePath.c_str() << std::endl;
	
	#ifndef FOR_LINUX
	if (!CopyFileW(szFile.c_str(), backupFilePath.c_str(), true)) {
		std::wcout << "Failed to create a backup copy. Do you want to continue anyway? You won't be able to revert the file to the original. Press Enter to agree...\n";
		std::getline(std::wcin, ignoreLine);
	} else {
		std::wcout << "Backup copy created successfully.\n";
	}
	#else
	copyFileLinux(szFile, backupFilePath);
	std::wcout << "Backup copy created successfully.\n";
	#endif
	
	struct CloseFileOnExit {
		~CloseFileOnExit() {
			if (file) fclose(file);
		}
		FILE* file = nullptr;
	} fileCloser;
	
	FILE* file = nullptr;
	if (!crossPlatformOpenFile(&file, szFile)) return;
	fileCloser.file = file;

	std::vector<char> wholeFile;
	if (!readWholeFile(file, wholeFile)) return;
	char* wholeFileBegin = &wholeFile.front();
	char* wholeFileEnd = &wholeFile.front() + wholeFile.size();
	char* textBegin = nullptr;
	char* textEnd = nullptr;
	char* rdataBegin = nullptr;
	char* rdataEnd = nullptr;
	char* dataBegin = nullptr;
	char* dataEnd = nullptr;
	
	DWORD imageBase;
	std::vector<Section> sections = readSections(file, &imageBase);
	if (sections.empty()) {
		CrossPlatformCout << "Failed to read sections\n";
		return;
	}
	CrossPlatformCout << "Read sections: [\n";
	CrossPlatformCout << std::hex;
	bool isFirst = true;
	for (const Section& section : sections) {
		if (!isFirst) {
			CrossPlatformCout << ",\n";
		}
		isFirst = false;
		CrossPlatformCout << "{\n\tname: \"" << section.name.c_str() << "\""
			<< ",\n\tvirtualSize: 0x" << section.virtualSize
			<< ",\n\tvirtualAddress: 0x" << section.virtualAddress
			<< ",\n\trawSize: 0x" << section.rawSize
			<< ",\n\trawAddress: 0x" << section.rawAddress
			<< "\n}";
		
		if (section.name == ".text") {
			textBegin = &wholeFile.front() + section.rawAddress;
			textEnd = textBegin + section.rawSize;
		} else if (section.name == ".rdata") {
			rdataBegin = &wholeFile.front() + section.rawAddress;
			rdataEnd = rdataBegin + section.rawSize;
		} else if (section.name == ".data") {
			dataBegin = &wholeFile.front() + section.rawAddress;
			dataEnd = dataBegin + section.rawSize;
		}
	}
	CrossPlatformCout << "\n]\n";
	CrossPlatformCout << std::dec;
	
	if (!textBegin) {
		CrossPlatformCout << "Failed to find .text section.\n";
		return;
	}
	
	if (!rdataBegin) {
		CrossPlatformCout << "Failed to find .rdata section.\n";
		return;
	}
	
	if (!dataBegin) {
		CrossPlatformCout << "Failed to find .data section.\n";
		return;
	}
	
	DWORD execIsAsyncLoadingVa, execIsAsyncLoadingPos;
	if (!findExec("UREDGfxMoviePlayer_MenuInterludeexecIsAsyncLoading",
			wholeFileBegin,
			rdataBegin, rdataEnd,
			dataBegin, dataEnd,
			sections,
			&execIsAsyncLoadingVa, &execIsAsyncLoadingPos)) return;
	
	const char* execIsAsyncLoadingPtr = wholeFileBegin + execIsAsyncLoadingPos;
	DWORD oldGNativesExDebugInfoMentionVa = 0;
	DWORD GNativesExDebugInfoVa = 0;
	int oldGNativesExDebugInfoPos = sigscan(execIsAsyncLoadingPtr, execIsAsyncLoadingPtr + 0x40, "\xff\x15", "xx");
	if (oldGNativesExDebugInfoPos == -1) {
		const char anotherGNativesExDebugInfoSig[] = "\x8b\x46\x18\x80\x38\x41\x75\x10\x8b\x4e\x14\x6a\x00\x40\x56\x89\x46\x18\xff\x15";
		int anotherGNativesExDebugInfoPos = sigscan(textBegin, textEnd,
			anotherGNativesExDebugInfoSig,
			"xxxxxxxxxxxxxxxxxxxx");
		if (anotherGNativesExDebugInfoPos == -1) {
			CrossPlatformCout << "Failed to find GNatives[EX_DebugInfo].\n";
			return;
		}
		anotherGNativesExDebugInfoPos += sizeof anotherGNativesExDebugInfoSig - 1;
		
		DWORD anotherGNativesExDebugInfoMentionVa = rawToVa(sections,
			anotherGNativesExDebugInfoPos + ((uintptr_t)(textBegin - wholeFileBegin) & 0xFFFFFFFF));
		
		CrossPlatformCout << "Found the mention of GNatives[EX_DebugInfo] not in execIsAsyncLoading, but somewhere else: va:0x"
			<< std::hex << anotherGNativesExDebugInfoMentionVa << std::dec << ". execIsAsyncLoading itself doesn't mention GNatives[EX_DebugInfo].\n";
		
		GNativesExDebugInfoVa = *(DWORD*)(textBegin + anotherGNativesExDebugInfoPos);
	} else {
		oldGNativesExDebugInfoMentionVa = execIsAsyncLoadingVa + oldGNativesExDebugInfoPos + 2;
		CrossPlatformCout << "Found the mention of GNatives[EX_DebugInfo] in execIsAsyncLoading: va:0x"
			<< std::hex << oldGNativesExDebugInfoMentionVa << std::dec << ".\n";
		
		GNativesExDebugInfoVa = *(DWORD*)(execIsAsyncLoadingPtr + oldGNativesExDebugInfoPos + 2);
	}
	CrossPlatformCout << "Found GNatives[EX_DebugInfo]: va:0x" << std::hex << GNativesExDebugInfoVa << std::dec << ".\n";
	
	RelocTable relocTable;  // RelocTable is able to modify the contents of wholeFileBegin
	relocTable.findRelocTable(wholeFileBegin, sections, imageBase);
	
	
	// Now find the jump that goes after the bBlocking check in UREDCharaAssetLoader::LoadAssets
	
	DWORD execLoadAssetsVa, execLoadAssetsPos;
	if (!findExec("UREDCharaAssetLoaderexecLoadAssets",
			wholeFileBegin,
			rdataBegin, rdataEnd,
			dataBegin, dataEnd,
			sections,
			&execLoadAssetsVa, &execLoadAssetsPos)) return;
	CrossPlatformCout << "Found execLoadAssets at va:0x" << std::hex << execLoadAssetsVa << std::dec << ".\n";
	
	const char* execLoadAssetsBegin = wholeFileBegin + vaToRaw(sections, execLoadAssetsVa);
	int loadAssetsCallPlacePos = sigscanForward(execLoadAssetsBegin, textEnd, 0x130, "\x8b\xcb\xe8", "xxx");
	if (loadAssetsCallPlacePos == -1) {
		CrossPlatformCout << "Couldn't find LoadAssets calling place.\n";
		return;
	}
	loadAssetsCallPlacePos += 2 + (execLoadAssetsBegin - wholeFileBegin) & 0xFFFFFFFF;
	CrossPlatformCout << "Found LoadAssets calling place: file:0x" << std::hex << loadAssetsCallPlacePos << std::dec << ".\n";
	
	DWORD loadAssetsVa = followRelativeCall(rawToVa(sections, loadAssetsCallPlacePos), wholeFileBegin + loadAssetsCallPlacePos);
	
	const char* loadAssetsBegin = wholeFileBegin + vaToRaw(sections, loadAssetsVa);
	bool jmpAlreadyNopedOut = false;
	int jmpPos = sigscanForward(loadAssetsBegin, textEnd, 0x1b0, "\x39\x5c\x24\x48\x74\x16", "xxxxxx");
	if (jmpPos == -1) {
		jmpPos = sigscanForward(loadAssetsBegin, textEnd, 0x1b0, "\x39\x5c\x24\x48\x90\x90", "xxxxxx");
		if (jmpPos == -1) {
			CrossPlatformCout << "Couldn't find 'if (bBlocking != 0) {' instruction in LoadAssets.\n";
			return;
		}
		jmpAlreadyNopedOut = true;
	}
	jmpPos += 4;
	jmpPos += (loadAssetsBegin - wholeFileBegin) & 0xFFFFFFFF;
	CrossPlatformCout << "Found 'if (bBlocking != 0) {' instruction in LoadAssets at file:0x" << std::hex << jmpPos << std::dec << ".";
	if (jmpAlreadyNopedOut) {
		CrossPlatformCout << " It's already deleted. Moving on.\n";
	} else {
		CrossPlatformCout << "\n";
	}
	
	DWORD FNameInitVa = 0;
	DWORD FNameCompareVa = 0;
	if (askResult == YesNoCancel_Yes) {
		int FNameInitMiddlePos = sigscan(textBegin, textEnd,
			"\x8b\x46\x08\xd1\xf8\x83\x7c\x24\x00\x02\x89\x07\x0f\x85\x00\x00\x00\x00\xf6\x46\x08\x01",
			"xxxxxxxx?xxxxx????xxxx");
		if (FNameInitMiddlePos == -1) {
			CrossPlatformCout << "Couldn't find FName::Init(const ANSICHAR* InName, INT InNumber, EFindName FindType)\n";
			return;
		}
		int FNameInitStartPos = sigscanUp(textBegin + FNameInitMiddlePos, textBegin, 0x230, "\x51\x55\x57\x8b\xf9", "xxxxx");
		if (FNameInitStartPos == -1) {
			CrossPlatformCout << "Couldn't find the start of FName::Init(const ANSICHAR* InName, INT InNumber, EFindName FindType)\n";
			return;
		}
		FNameInitVa = rawToVa(sections, ((uintptr_t)(textBegin - wholeFileBegin) & 0xFFFFFFFF) + FNameInitStartPos);
		CrossPlatformCout << "Found FName::Init(const ANSICHAR* InName, INT InNumber, EFindName FindType) at va:0x"
			<< std::hex << FNameInitVa << std::dec << "\n";
		
		int FNameCompareMiddlePos = sigscan(textBegin, textEnd,
			"\x8b\x34\x82\x8b\x04\x8a\x8b\x48\x08\x8b\x56\x08\x83\xe1\x01\x83\xe2\x01\x3b\xd1",
			"xxxxxxxxxxxxxxxxxxxx");
		if (FNameCompareMiddlePos == -1) {
			CrossPlatformCout << "Couldn't find FName::Compare\n";
			return;
		}
		int FNameCompareStartPos = sigscanUp(textBegin + FNameCompareMiddlePos, textBegin, 0x193,
			"\x6a\xff\x68\x00\x00\x00\x00\x64\xa1\x00\x00\x00\x00\x50\x81\xec\x00\x00\x00\x00",
			"xxx????xxxxxxxxx????");
		if (FNameCompareStartPos == -1) {
			CrossPlatformCout << "Couldn't find the start of FName::Compare\n";
			return;
		}
		FNameCompareVa = rawToVa(sections, ((uintptr_t)(textBegin - wholeFileBegin) & 0xFFFFFFFF) + FNameCompareStartPos);
		CrossPlatformCout << "Found FName::Compare at va:0x" << std::hex << FNameCompareVa << std::dec << "\n";
	}
	
	char* writeBuf = nullptr;
	size_t writeBufSize = 0;
	
	char writeBuf_noMash[] =
		"\x8B\x44\x24\x04"         // MOV EAX,dword [ESP+0x4]  ; this argument is an FFrame* and is called Stack in UE3 source code
		"\x56"                     // PUSH ESI
		"\x89\xCE"                 // MOV ESI,ECX
		"\xFF\x40\x18"             // INC dword [EAX+0x18]  ; increment stack->Code
		"\x8b\x48\x18"             // MOV ECX,dword ptr [EAX + 0x18]  ; read stack->Code
		"\x80\x39\x41"             // CMP byte ptr [ECX],0x41  ; compare *stack->Code to EX_DebugInfo
		"\x75\x14"                 // JNZ not_EX_DebugInfo
		"\x41"                     // INC ECX
		"\x6a\x00"                 // PUSH 0
		"\x89\x48\x18"             // MOV dword ptr [EAX + 0x18],ECX
		"\x8b\x48\x14"             // MOV ECX,dword ptr [EAX + 0x14]  // stack->Object
		"\x50"                     // PUSH EAX
		"\xff\x15\x00\x00\x00\x00" // CALL dword ptr [GNatives[0x41]]  ; call GNatives[EX_DebugInfo]. We'll write the address soon
		"\x8B\x44\x24\x08"         // MOV EAX,dword [ESP+0x8]
		// not_EX_DebugInfo
		"\x8B\x48\x1C"             // MOV ECX,dword [EAX+0x1c]  ; this is stack->Locals, it stores function arguments and local variables of the unrealscript
		"\x31\xD2"                 // XOR EDX,EDX
		"\x42"                     // INC EDX
		"\x8B\x41\x04"             // MOV EAX,dword [ECX+0x4]  ; The first value is always bTrigger, a function argument. The second could either be a TArray (local array<SpawnPlayerInfo> Info) or a BOOL (local bool press1P). TArray's first element is a pointer but the array starts empty and so everything should be null in it
		"\x39\xD0"                 // CMP EAX,EDX
		"\x77\x04"                 // JA returnZero  ; > 1? Probably it's a TArray. In this part of unrealscript (UpdateWaitCharaLoad unrealscript function) we want to report that we're not async loading
		"\x74\x06"                 // JZ doProperCheck  ; if it's 1, that means it's the local bool press1P variable and it is TRUE. In this part of the script, we want to check if loading is actually finished
		"\xEB\x14"                 // JMP second  ; check the other variable, press2P
		// returnZero:
		"\x31\xC0"                 // XOR EAX,EAX
		"\xEB\x19"                 // JMP return
		// doProperCheck:
		"\x8B\x86\xD0\x01\x00\x00" // MOV EAX,dword [ESI+0x1d0]  ; this object is a REDGfxMoviePlayer_MenuInterlude and 0x1d0 is an int VSLoadPercent, from 0 to 100
		"\x83\xF8\x64"             // CMP EAX,0x64  ; compare to 100
		"\x74\xF1"                 // JZ returnZero  ; if it's fully loaded, we want to report that we're not async loading, which will let the user's mash skip the loading screen
		"\x31\xC0"                 // XOR EAX,EAX  ; report that we're async loading (EAX 1). This means that the user cannot skip the loading screen despite them mashing
		"\x40"                     // INC EAX
		"\xEB\x09"                 // JMP return
		// second:
		"\x8B\x41\x08"             // MOV EAX,dword [ECX+0x8]  ; check local bool press2P. In UpdateWaitCharaLoad this would be ArrayNum of the array. That array is empty at the time of this call, so it should be 0
		"\x39\xD0"                 // CMP EAX,EDX
		"\x74\xE9"                 // JZ doProperCheck
		"\x31\xC0"                 // XOR EAX,EAX
		// return:
		"\x8B\x4C\x24\x0C"         // MOV ECX,dword [ESP+0xc]  ; this function argument is called void* Result and we cast it to BOOL* to return a BOOL
		"\x89\x01"                 // MOV dword [ECX],EAX
		"\x5E"                     // POP ESI
		"\xC2\x08\x00";            // RET 0x8
	
	// The function we're overwriting, execIsAsyncLoading, is called IsAsyncLoading in unrealscript and is a member of REDGfxMoviePlayer_MenuInterlude.
	// It is called from two places: UpdateWaitCharaLoad and UpdateExec.
	// In UpdateWaitCharaLoad we just want to return false and not modify its local variables, because they start with local array<SpawnPlayerInfo> Info.
	// In UpdateExec we want to write TRUE into press1P and return false if we've finished loading,
	// while returning true (yes we're async loading) whenever the user mashes before we've finished loading.
	// dword ptr[dword ptr[ESP+0x4]+0x10] + 0x50 is PropertiesSize. It has been observed to be 0x4C for UpdateWaitCharaLoad and 0x30 for UpdateExec.
	// But we are not going to hardcore these values. We will instead do a proper string check for the name.
	
	char writeBuf_mash[] =
	// *serial killer breath* I calculated the offsets manually...
		/* 0  */ "\x56"                     // PUSH ESI
		/* 1  */ "\x57"                     // PUSH EDI
		/* 2  */ "\x8B\x7C\x24\x0C"         // MOV EDI,dword [ESP+0xc]  ; this argument is an FFrame* and is called Stack in UE3 source code
		/* 6  */ "\x89\xCE"                 // MOV ESI,ECX
		/* 8  */ "\xFF\x47\x18"             // INC dword [EDI+0x18]  ; increment stack->Code
		/* B  */ "\x8B\x4F\x18"             // MOV ECX,dword [EDI+0x18]  ; read stack->Code
		/* E  */ "\x80\x39\x41"             // CMP byte [ECX],0x41  ; compare *stack->Code to EX_DebugInfo
		/* 11 */ "\x75\x1D"                 // JNZ string_literal_end
		/* 13 */ "\x41"                     // INC ECX
		/* 14 */ "\x6a\x00"                 // PUSH 0
		/* 16 */ "\x89\x4F\x18"             // MOV dword [EDI+0x18],ECX
		/* 19 */ "\x8b\x4F\x14"             // MOV ECX,dword [EDI+0x14]  // stack->Object
		/* 1C */ "\x57"                     // PUSH EDI
		/* 1D */ "\xff\x15\x00\x00\x00\x00" // CALL dword [GNatives[0x41]]  ; call GNatives[EX_DebugInfo]. We'll write the address soon
		/* 24 */ "\xEB\x0B"                 // JMP string_literal_end
		/* 26 */ "UpdateExec\x00"
		         // string_literal_end
		/* 31 */ "\x83\xEC\x08"             // SUB ESP,0x8  ; allocate stack space for an FName
		/* 34 */ "\x8d\x0c\x24"             // LEA ECX,[ESP]
		/* 37 */ "\x6A\x00"                 // PUSH 0  ; this is the EFindName FindType argument of the FName::Init function. Value 0 means FNAME_Find
		/* 39 */ "\x6A\x00"                 // PUSH 0  ; this will be the number part of the new FName. 0 means there is no number
		/* 3B */ "\x68\x00\x00\x00\x00"     // PUSH UpdateExec  ; we'll write the address of the string later. This needs a relocation entry too
		/* 40 */ "\xE8\x00\x00\x00\x00"     // CALL FName::Init. We'll write the call offset later. This cleans the stack for us
		/* 45 */ "\x8D\x0C\x24"             // LEA ECX,[ESP]  ; ECX will be the FName we just initted
		/* 48 */ "\x8B\x47\x10"             // MOV EAX,dword [EDI+0x10]  ; 0x10 is UStruct* Node member of FFrame
		/* 4B */ "\x8D\x40\x2C"             // LEA EAX,dword [EAX+0x2c]  ; 0x2c is FName Name member of UObject (UStruct extends UObject)
		/* 4E */ "\x50"                     // PUSH EAX
		/* 4F */ "\xE8\x00\x00\x00\x00"     // CALL FName::Compare  ; Cleans up the one stack argument. We'll write the call offset later.
		/* 54 */ "\x83\xC4\x08"             // ADD ESP,0x8  ; clean up our stack allocated FName
		/* 57 */ "\x31\xD2"                 // XOR EDX,EDX
		/* 59 */ "\x39\xD0"                 // CMP EAX,EDX
		/* 5B */ "\x75\x2C"                 // JNZ returnZero  ; for UpdateWaitCharaLoad we always want to return false, that we're not async oading
		/* 5E */ "\x8B\x47\x10"             // MOV EAX,dword [EDI+0x10]  ; 0x10 is UStruct* Node member of FFrame
		/* 61 */ "\x8B\x40\x54"             // MOV EAX,dword [EAX+0x54]  ; 0x54 is TArray<BYTE> Script member of UStruct, and the first member of this TArray is BYTE* Data
		/* 64 */ "\x8B\x57\x18"             // MOV EDX,dword [EDI+0x18]  ; 0x18 is the EExprToken* Code member of FFrame. It should be somewhere inside Script
		/* 67 */ "\x29\xC2"                 // SUB EDX,EAX
		/* 69 */ "\x81\xFA\x93\x01\x00\x00" // CMP EDX,0x193  ; past 0x193 the script obtains press1P and press2P and it actually becomes dangerous to return true
		/* 6F */ "\x7c\x19"                 // JB returnZero  ; before 0x193 it's OK to just always return false
		/* 71 */ "\x8B\x86\xD0\x01\x00\x00" // MOV EAX,dword [ESI+0x1d0]  ; this object is a REDGfxMoviePlayer_MenuInterlude and 0x1d0 is an int VSLoadPercent, from 0 to 100
		/* 77 */ "\x83\xF8\x64"             // CMP EAX,0x64  ; compare to 100
		/* 7A */ "\x7D\x05"                 // JGE forceWayThrough
		/* 7C */ "\x31\xC0"                 // XOR EAX,EAX
		/* 7E */ "\x40"                     // INC EAX
		/* 7F */ "\xEB\x0B"                 // JMP return
		         // forceWayThrough:
		/* 81 */ "\x8B\x4F\x1C"             // MOV ECX,dword [EDI+0x1c]  ; this is stack->Locals, it stores function arguments and local variables of the unrealscript
		/* 84 */ "\x31\xC0"                 // XOR EAX,EAX
		/* 86 */ "\x40"                     // INC EAX
		/* 87 */ "\x89\x41\x04"             // MOV dword [ECX+0x4],EAX  ; The first value (ECX+0x0) is always bTrigger, a function argument. The second is local bool press1P
		         // returnZero:
		/* 8A */ "\x31\xC0"                 // XOR EAX,EAX
		         // return:
		/* 8C */ "\x8B\x4C\x24\x10"         // MOV ECX,dword [ESP+0x10]  ; this function argument is called void* Result and we cast it to BOOL* to return a BOOL
		/* 90 */ "\x89\x01"                 // MOV dword [ECX],EAX
		/* 92 */ "\x5F"                     // POP EDI
		/* 93 */ "\x5E"                     // POP ESI
		/* 94 */ "\xC2\x08\x00";            // RET 0x8
	
	if (askResult == YesNoCancel_No) {
		writeBuf = writeBuf_noMash;
		writeBufSize = sizeof writeBuf_noMash;
	} else {
		writeBuf = writeBuf_mash;
		writeBufSize = sizeof writeBuf_mash;
	}
	char* writeBufEnd = writeBuf + writeBufSize - 1;
	
	int GNativesExDebugInfoMentionInWriteBuf = sigscan(writeBuf, writeBufEnd, "\xff\x15\x00\x00\x00\x00", "xxxxxx");
	GNativesExDebugInfoMentionInWriteBuf += 2;
	*(DWORD*)&writeBuf[GNativesExDebugInfoMentionInWriteBuf] = GNativesExDebugInfoVa;
	
	std::vector<FoundReloc> relocs = relocTable.findRelocsInRegion(execIsAsyncLoadingVa, execIsAsyncLoadingVa + (DWORD)writeBufSize - 1);
	
	for (const FoundReloc& foundReloc : relocs) {
		relocTable.removeEntry(file, foundReloc);  // not necessarily able to reuse these entries due to the possibility of crossing page boundaries
	}
	
	if (askResult == YesNoCancel_Yes) {
		int UpdateExecStrPos = sigscan(writeBuf, writeBufEnd, "UpdateExec", "xxxxxxxxxx");
		DWORD UpdateExecStrVa = execIsAsyncLoadingVa + UpdateExecStrPos;
		
		int UpdateExecStrUsagePos = sigscan(writeBuf, writeBufEnd, "\x68\x00\x00\x00\x00", "xxxxx");
		
		memcpy(writeBuf + UpdateExecStrUsagePos + 1, &UpdateExecStrVa, 4);
		
		relocTable.addEntry(file, execIsAsyncLoadingVa + UpdateExecStrUsagePos + 1, IMAGE_REL_BASED_HIGHLOW);
		
		
		
		int FNameInitCallPos = sigscan(writeBuf, writeBufEnd, "\xE8\x00\x00\x00\x00", "xxxxx");
		int callOffset = calculateRelativeCall(rawToVa(sections, execIsAsyncLoadingPos + FNameInitCallPos), FNameInitVa);
		memcpy(writeBuf + FNameInitCallPos + 1, &callOffset, 4);
		
		
		int FNameCompareCallPos = sigscan(writeBuf, writeBufEnd, "\xE8\x00\x00\x00\x00", "xxxxx");
		callOffset = calculateRelativeCall(rawToVa(sections, execIsAsyncLoadingPos + FNameCompareCallPos), FNameCompareVa);
		memcpy(writeBuf + FNameCompareCallPos + 1, &callOffset, 4);
		
		
	}
	
	fseek(file, execIsAsyncLoadingPos, SEEK_SET);
	fwrite(writeBuf, 1, writeBufSize - 1, file);
	CrossPlatformCout << "Overwrote execIsAsyncLoading() function successfully!\n";
	
	relocTable.addEntry(file, execIsAsyncLoadingVa + GNativesExDebugInfoMentionInWriteBuf, IMAGE_REL_BASED_HIGHLOW);
	
	if (!jmpAlreadyNopedOut) {
		fseek(file, jmpPos, SEEK_SET);
		char twoNops[2] = { '\x90', '\x90' };
		fwrite(twoNops, 1, 2, file);
		CrossPlatformCout << "Deleted 'if (bBlocking != 0) {' instruction in LoadAssets successfully!\n";
	}
	
	CrossPlatformCout << "Patch successful!\n";
	
	CrossPlatformCout << "Remember, the backup copy has been created at: " << backupFilePath.c_str() << "\n";
	
	// file gets closed automatically by fileCloser
}

#ifndef FOR_LINUX
int patcherMain() {
#else
int main() {
#endif
	
	#ifndef FOR_LINUX
	int offset = (int)(
		(GetTickCount64() & 0xF000000000000000ULL) >> (63 - 4)
	) & 0xFFFFFFFF;
	#else
	int offset = 0;
	#endif
	
	for (int i = 0; i < sizeof exeName - 1; ++i) {
		exeName[i] += offset + 10;
	}
	
	CrossPlatformCout <<
				  "This program patches " << exeName << " executable to permanently reduce the time it takes to load game assets before each fight.\n"
				  "This cannot be undone, and a backup copy of the file will be automatically created (but that may fail; if that happens, a warning will be displayed).\n"
				  "Only Guilty Gear Xrd Rev2 version 2211 may work with this patcher. A different version of the game may crash after patching.\n"
				  "Press Enter when ready...\n";
	
	CrossPlatformString ignoreLine;
	GetLine(ignoreLine);

	meatOfTheProgram();

	CrossPlatformCout << "Press Enter to exit...\n";
	GetLine(ignoreLine);
	return 0;
}

#ifndef FOR_LINUX
bool forceAllowed = false;
UINT windowAppTitleResourceId = IDS_APP_TITLE;
UINT windowClassNameResourceId = IDC_GGXRDFASTERLOADINGTIMES;
LPCWSTR windowIconId = MAKEINTRESOURCEW(IDI_GGXRDFASTERLOADINGTIMES);
LPCWSTR windowMenuName = MAKEINTRESOURCEW(IDC_GGXRDFASTERLOADINGTIMES);
LPCWSTR windowAcceleratorId = MAKEINTRESOURCEW(IDC_GGXRDFASTERLOADINGTIMES);

bool parseArgs(int argc, LPWSTR* argv, int* exitCode) {
	for (int i = 0; i < argc; ++i) {
		if (_wcsicmp(argv[i], L"/?") == 0
				|| _wcsicmp(argv[i], L"--help") == 0
				|| _wcsicmp(argv[i], L"-help") == 0) {
			MessageBoxA(NULL,
				"Patcher for improving loading times for Guilty Gear Xrd Rev2 version 2211.",
				"GGXrdFasterLoadingTimes " VERSION,
				MB_OK);
			*exitCode = 0;
			return false;
		}
	}
	return true;
}

unsigned long __stdcall taskThreadProc(LPVOID unused) {
	unsigned long result = patcherMain();
	PostMessageW(mainWindow, WM_TASK_ENDED, 0, 0);
	return result;
}
#endif
