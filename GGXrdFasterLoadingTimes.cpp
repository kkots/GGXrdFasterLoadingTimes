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


#ifndef FOR_LINUX
InjectorCommonOut outputObject;
#define CrossPlatformString std::wstring
#define CrossPlatformChar wchar_t
#define CrossPlatformPerror _wperror
#define CrossPlatformText(txt) L##txt
#define CrossPlatformCout outputObject
#define CrossPlatformNumberToString std::to_wstring
extern void GetLine(std::wstring& line);
#else
void GetLine(std::string& line) { std::getline(std::cin, line); }
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
        if (*it >= 32) break;
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

	std::vector<Section> result;

	DWORD peHeaderStart = 0;
	fseek(file, 0x3C, SEEK_SET);
	fread(&peHeaderStart, 4, 1, file);

	unsigned short numberOfSections = 0;
	fseek(file, peHeaderStart + 0x6, SEEK_SET);
	fread(&numberOfSections, 2, 1, file);

	DWORD optionalHeaderStart = peHeaderStart + 0x18;

	unsigned short optionalHeaderSize = 0;
	fseek(file, peHeaderStart + 0x14, SEEK_SET);
	fread(&optionalHeaderSize, 2, 1, file);

	fseek(file, peHeaderStart + 0x34, SEEK_SET);
	fread(imageBase, 4, 1, file);

	DWORD sectionsStart = optionalHeaderStart + optionalHeaderSize;
	DWORD sectionStart = sectionsStart;
	for (size_t sectionCounter = numberOfSections; sectionCounter != 0; --sectionCounter) {
		Section newSection;
		fseek(file, sectionStart, SEEK_SET);
		newSection.name.resize(8);
		fread(&newSection.name.front(), 1, 8, file);
		newSection.name.resize(strlen(newSection.name.c_str()));
		fread(&newSection.virtualSize, 4, 1, file);
		fread(&newSection.relativeVirtualAddress, 4, 1, file);
		newSection.virtualAddress = *imageBase + newSection.relativeVirtualAddress;
		fread(&newSection.rawSize, 4, 1, file);
		fread(&newSection.rawAddress, 4, 1, file);
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

std::vector<FoundReloc> findRelocsInRegion(DWORD regionStart, DWORD regionEnd, const char* relocTable, DWORD relocTableVa, DWORD relocTableSize, DWORD imageBase) {
	std::vector<FoundReloc> result;
	
	const char* const relocTableOrig = relocTable;
	
	const char* relocTableNext = relocTable;
	while ((int)relocTableSize > 0) {  // loop over blocks
		relocTable = relocTableNext;
		DWORD pageBaseRva = *(DWORD*)relocTable;
		DWORD pageBaseVa = rvaToVa(pageBaseRva, imageBase);
		int blockSize = *(int*)(relocTable + 4);
		relocTableNext += blockSize;
		(int&)relocTableSize -= blockSize;
		
		if (pageBaseVa >= regionEnd || pageBaseVa + 0xFFF + 8 < regionStart) {
			continue;
		}
		
		blockSize -= 8;
		relocTable += 8;
		while (blockSize > 0) {  // loop over entries in the block
			const char* relocTableEntryOrig = relocTable;
			unsigned short entry = *(unsigned short*)relocTable;
			relocTable += 2;
			blockSize -= 2;
			
			char blockType = (entry & 0xF000) >> 12;
			DWORD patchVa = pageBaseVa + (entry & 0xFFF);
			if (blockType == IMAGE_REL_BASED_ABSOLUTE) continue;
			DWORD patchSize = 4;
			
			switch (blockType) {
				case IMAGE_REL_BASED_HIGH: patchVa += 2; patchSize = 2; break;
				case IMAGE_REL_BASED_LOW: patchSize = 2; break;
				case IMAGE_REL_BASED_HIGHLOW: break;
				case IMAGE_REL_BASED_HIGHADJ:
					// I'm not very confident with this
					blockSize -= 2;
					relocTable += 2;
					patchSize = 2;
					break;
				case IMAGE_REL_BASED_DIR64: patchSize = 8; break;
			}
			
			if (patchVa >= regionEnd || patchVa + patchSize < regionStart) continue;
			
			FoundReloc newReloc;
			newReloc.type = blockType;
			newReloc.relocVa = relocTableVa + (relocTableEntryOrig - relocTableOrig) & 0xFFFFFFFF;
			newReloc.regionVa = patchVa;
			result.push_back(newReloc);
			
		}
		
	}
	
	return result;
}

void printFoundRelocs(const std::vector<FoundReloc>& relocs) {
	CrossPlatformCout << '[';
	bool isFirst = true;
	for (const FoundReloc& reloc : relocs) {
		if (!isFirst) CrossPlatformCout << ',';
		else isFirst = false;
		
		CrossPlatformCout << "\n\t{\n\t\t\"type\": \"";
		switch (reloc.type) {
			case IMAGE_REL_BASED_HIGH: CrossPlatformCout << "IMAGE_REL_BASED_HIGH"; break;
			case IMAGE_REL_BASED_LOW: CrossPlatformCout << "IMAGE_REL_BASED_LOW"; break;
			case IMAGE_REL_BASED_HIGHLOW: CrossPlatformCout << "IMAGE_REL_BASED_HIGHLOW"; break;
			case IMAGE_REL_BASED_HIGHADJ: CrossPlatformCout << "IMAGE_REL_BASED_HIGHADJ"; break;
			case IMAGE_REL_BASED_DIR64: CrossPlatformCout << "IMAGE_REL_BASED_DIR64"; break;
			default: CrossPlatformCout << (int)reloc.type;
		}
		CrossPlatformCout << "\",\n"
			"\t\t\"relocVa\": \"0x" << std::hex << reloc.relocVa << "\",\n"
			"\t\t\"regionVa\": \"0x" << reloc.regionVa << std::dec << "\"\n"
			"\t}";
	}
	if (!isFirst) CrossPlatformCout << '\n';
	CrossPlatformCout << ']';
}

// Finds the file position of the start of the reloc table and its size
void findRelocTable(FILE* file, const std::vector<Section>& sections, DWORD* relocRawPosPtr, DWORD* relocSizePtr,
					DWORD* relocSectionHeader, bool seekFileBackToWhereItWas = true) {
	
	int oldPos;
	if (seekFileBackToWhereItWas) {
		oldPos = ftell(file);
	}
	
    fseek(file, 0x3C, SEEK_SET);
	
	DWORD peHeaderStart = 0;
    fread(&peHeaderStart, 4, 1, file);
	
    *relocSectionHeader = peHeaderStart + 0xA0;
    fseek(file, peHeaderStart + 0xA0, SEEK_SET);
    
    DWORD relocRva = 0;
    fread(&relocRva, 4, 1, file);
    DWORD relocSize = 0;
    fread(&relocSize, 4, 1, file);
    
    if (seekFileBackToWhereItWas) {
    	fseek(file, oldPos, SEEK_SET);
    }
    
    *relocRawPosPtr = rvaToRaw(sections, relocRva);
    *relocSizePtr = relocSize;
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
	CrossPlatformCout << CrossPlatformText("Please type in/paste a path, without quotes, to your ") << exeName << CrossPlatformText(" file"
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
	if (szFile.empty()) {
		std::cout << "Empty path provided. Aborting.\n";
		return;
	}
	#endif
	CrossPlatformCout << "Selected file: " << szFile.c_str() << std::endl;

	CrossPlatformString fileName = getFileName(szFile);
	CrossPlatformString parentDir = getParentDir(szFile);
	
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
	
	DWORD relocRaw;
	DWORD relocSize;
	DWORD relocSectionHeader;
	findRelocTable(file, sections, &relocRaw, &relocSize, &relocSectionHeader, false);
	
	
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
	int jmpPos = sigscanForward(loadAssetsBegin, textEnd, 0x1b0, "\x39\x5c\x24\x48\x74\x16", "xxxxxx");
	if (jmpPos == -1) {
		CrossPlatformCout << "Couldn't find 'if (bBlocking != 0) {' instruction in LoadAssets.\n";
		return;
	}
	jmpPos += (loadAssetsBegin - wholeFileBegin) & 0xFFFFFFFF;
	CrossPlatformCout << "Found 'if (bBlocking != 0) {' instruction in LoadAssets at file:0x" << std::hex << jmpPos << std::dec << ".\n";
	
	fseek(file, execIsAsyncLoadingPos, SEEK_SET);
	char writeBuf[] =
		"\x8B\x44\x24\x04"         // MOV EAX,dword [ESP+0x4]  ; this argument is an FFrame* and is called Stack in most UE3 source code
		"\x56"                     // PUSH ESI
		"\x89\xCE"                 // MOV ESI,ECX
		"\xFF\x40\x18"             // INC dword [EAX+0x18]  ; increment stack->Code
		"\x8B\x48\x1C"             // MOV ECX,dword [EAX+0x1c]  ; this is stack->Locals, it stores function arguments and local variables of the unrealscript
		"\x31\xD2"                 // XOR EDX,EDX
		"\x42"                     // INC EDX
		"\x8B\x41\x04"             // MOV EAX,dword [ECX+0x4]  ; The first value is always bTrigger, a function argument. The second could either be a TArray (local array<SpawnPlayerInfo> Info) or a BOOL (local bool press1P). TArray's first element is a pointer
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
		"\x8B\x41\x08"             // MOV EAX,dword [ECX+0x8]  ; check local bool press2P
		"\x39\xD0"                 // CMP EAX,EDX
		"\x74\xE9"                 // JZ doProperCheck
		"\x31\xC0"                 // XOR EAX,EAX
		// return:
		"\x8B\x4C\x24\x0C"         // MOV ECX,dword [ESP+0xc]  ; this function argument is called void* Result and we cast it to BOOL* to return a BOOL
		"\x89\x01"                 // MOV dword [ECX],EAX
		"\x5E"                     // POP ESI
		"\xC2\x08\x00";            // RET 0x8
	fwrite(writeBuf, 1, sizeof writeBuf - 1, file);
	CrossPlatformCout << "Overwrote execIsAsyncLoading() function successfully!\n";
	
	std::vector<FoundReloc> relocs = findRelocsInRegion(execIsAsyncLoadingVa, execIsAsyncLoadingVa + sizeof writeBuf - 1,
		wholeFileBegin + relocRaw, rawToVa(sections, relocRaw), relocSize, imageBase);
	
	int numEntriesDeleted = 0;
	for (const FoundReloc& reloc : relocs) {
		fseek(file, vaToRaw(sections, reloc.relocVa), SEEK_SET);
		unsigned short zeros = 0;
		fwrite(&zeros, 2, 1, file);
		++numEntriesDeleted;
	}
	if (numEntriesDeleted) {
		CrossPlatformCout << "Deleted ";
		if (numEntriesDeleted == 1) {
			CrossPlatformCout << "one old relocation entry";
		} else {
			CrossPlatformCout << numEntriesDeleted << " old relocation entries";
		}
		CrossPlatformCout << " in execIsAsyncLoading() successfully!\n";
	}
	
	fseek(file, jmpPos + 4, SEEK_SET);
	char twoNops[2] = { '\x90', '\x90' };
	fwrite(twoNops, 1, 2, file);
	CrossPlatformCout << "Deleted 'if (bBlocking != 0) {' instruction in LoadAssets successfully!\n";
	
	CrossPlatformCout << "Patch successful!\n";
	
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
