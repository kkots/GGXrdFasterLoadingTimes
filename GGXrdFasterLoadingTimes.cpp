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
#include <io.h>     // for _get_osfhandle
#else
#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <climits>
#include <unistd.h>
#include <sys/types.h>
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
#define CrossPlatformStringCompareCaseInsensitive _stricmp
#define CrossPlatformPathCompare wcscmp
#define SPRINTF_NARROW sprintf_s
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
#define CrossPlatformStringCompareCaseInsensitive stricmp
#define CrossPlatformPathCompare strcmp
#define SPRINTF_NARROW sprintf

int stricmp(const char* left, const char* right) {
	while (true) {
		char leftLower = tolower(*left);
		char rightLower = tolower(*right);
		if (leftLower == rightLower) {
			if (leftLower == 0) return 0;
			++left;
			++right;
			continue;
		}
		return leftLower - rightLower;
	}
}

typedef unsigned char BYTE, *PBYTE;
typedef int LONG;
typedef unsigned short WORD;
typedef unsigned int DWORD;

// from winnt.h
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
  
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;

typedef IMAGE_NT_HEADERS32     IMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))
    
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_HIGHADJ 4
#define IMAGE_REL_BASED_DIR64 10

#define FIELD_OFFSET offsetof
    
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

#define FILE_ATTRIBUTE_NORMAL 0x80
#define OPEN_EXISTING 3
#define FILE_SHARE_READ 1
#define GENERIC_READ 0x80000000

typedef unsigned long long ULONGLONG;
typedef unsigned long ULONG;
typedef uintptr_t ULONG_PTR;
#endif

#if defined( _WIN64 )
typedef PIMAGE_NT_HEADERS32 nthdr;
#undef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))
#else
typedef PIMAGE_NT_HEADERS nthdr;
#endif
nthdr pNtHeader = nullptr;
BYTE* fileBase = nullptr;

#ifndef FOR_LINUX
#define PATH_SEPARATOR L'\\'
#else
#define PATH_SEPARATOR '/'
#endif

char exeName[] = "\x3d\x6b\x5f\x62\x6a\x6f\x3d\x5b\x57\x68\x4e\x68\x5a\x24\x5b\x6e\x5b\xf6";

#ifdef FOR_LINUX
void copyFileLinux(const std::string& pathSource, const std::string& pathDestination);
#endif

bool crossPlatformFileCopy(const CrossPlatformString& dst, const CrossPlatformString& src,
		const CrossPlatformChar* successMsg,
		const CrossPlatformChar* errorMsg) {
    bool success = true;
    #ifndef FOR_LINUX
    if (!CopyFileW(src.c_str(), dst.c_str(), true)) {
        CrossPlatformCout << errorMsg;
    	CrossPlatformString ignoreLine;
    	GetLine(ignoreLine);
    	success = false;
    }
    #else
    copyFileLinux(src, dst);
    std::cout << "Backup copy created successfully.\n";
    #endif
    CrossPlatformCout << successMsg;
    return success;
}

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

#ifndef FOR_LINUX
extern HWND mainWindow;
#endif

#if defined(FOR_LINUX) || !defined(_DEBUG)
#define byteSpecificationError
#else
#define byteSpecificationError { \
    OutputDebugStringA("Wrong byte specification: "); \
    OutputDebugStringA(byteSpecification); \
    OutputDebugStringA("\n"); \
	return numOfTriangularChars; \
}
#endif

// byteSpecification is of the format "00 8f 1e ??". ?? means unknown byte.
// Converts a "00 8f 1e ??" string into two vectors:
// sig vector will contain bytes '00 8f 1e' for the first 3 bytes and 00 for every ?? byte.
// sig vector will be terminated with an extra 0 byte.
// mask vector will contain an 'x' character for every non-?? byte and a '?' character for every ?? byte.
// mask vector will be terminated with an extra 0 byte.
// Can additionally provide an size_t* position argument. If the byteSpecification contains a ">" character, position will store the offset of that byte.
// If multiple ">" characters are present, position must be an array able to hold all positions, and positionLength specifies the length of the array.
// If positionLength is 0, it is assumed the array is large enough to hold all > positions.
// Returns the number of > characters.
size_t byteSpecificationToSigMask(const char* byteSpecification, std::vector<char>& sig, std::vector<char>& mask, size_t* position = nullptr, size_t positionLength = 0) {
	if (position && positionLength == 0) positionLength = UINT_MAX;
	size_t numOfTriangularChars = 0;
	sig.clear();
	mask.clear();
	unsigned long long accumulatedNibbles = 0;
	int nibbleCount = 0;
	bool nibblesUnknown = false;
	const char* byteSpecificationPtr = byteSpecification;
	bool nibbleError = false;
	const char* nibbleSequenceStart = byteSpecification;
	while (true) {
		char currentChar = *byteSpecificationPtr;
		if (currentChar == '>') {
			if (position && numOfTriangularChars < positionLength) {
				*position = sig.size();
				++position;
			}
			++numOfTriangularChars;
			nibbleSequenceStart = byteSpecificationPtr + 1;
		} else if (currentChar == '(') {
			nibbleCount = 0;
			nibbleError = false;
			nibblesUnknown = false;
			accumulatedNibbles = 0;
			if (byteSpecificationPtr <= nibbleSequenceStart) {
				byteSpecificationError
			}
			const char* moduleNameEnd = byteSpecificationPtr;
			++byteSpecificationPtr;
			bool parseOk = true;
			#define skipWhitespace \
				while (*byteSpecificationPtr != '\0' && *byteSpecificationPtr <= 32) { \
					++byteSpecificationPtr; \
				}
			#define checkQuestionMarks \
				if (parseOk) { \
					if (strncmp(byteSpecificationPtr, "??", 2) != 0) { \
						parseOk = false; \
					} else { \
						byteSpecificationPtr += 2; \
					} \
				}
			#define checkWhitespace \
				if (parseOk) { \
					if (*byteSpecificationPtr == '\0' || *byteSpecificationPtr > 32) { \
						parseOk = false; \
					} else { \
						while (*byteSpecificationPtr != '\0' && *byteSpecificationPtr <= 32) { \
							++byteSpecificationPtr; \
						} \
					} \
				}
			skipWhitespace
			checkQuestionMarks
			checkWhitespace
			checkQuestionMarks
			checkWhitespace
			checkQuestionMarks
			checkWhitespace
			checkQuestionMarks
			skipWhitespace
			#undef skipWhitespace
			#undef checkQuestionMarks
			#undef checkWhitespace
			if (*byteSpecificationPtr != ')') {
				parseOk = false;
			}
			if (!parseOk) {
				byteSpecificationError
			}
		} else if (currentChar != ' ' && currentChar != '\0') {
			char currentNibble = 0;
			if (currentChar >= '0' && currentChar <= '9' && !nibblesUnknown) {
				currentNibble = currentChar - '0';
			} else if (currentChar >= 'a' && currentChar <= 'f' && !nibblesUnknown) {
				currentNibble = currentChar - 'a' + 10;
			} else if (currentChar >= 'A' && currentChar <= 'F' && !nibblesUnknown) {
				currentNibble = currentChar - 'A' + 10;
			} else if (currentChar == '?' && (nibbleCount == 0 || nibblesUnknown)) {
				nibblesUnknown = true;
			} else {
				nibbleError = true;
			}
			accumulatedNibbles = (accumulatedNibbles << 4) | currentNibble;
			++nibbleCount;
			if (nibbleCount > 16) {
				nibbleError = true;
			}
		} else {
			if (nibbleCount) {
				if (nibbleError) {
					byteSpecificationError
				}
				do {
					if (!nibblesUnknown) {
						sig.push_back(accumulatedNibbles & 0xff);
						mask.push_back('x');
						accumulatedNibbles >>= 8;
					} else {
						sig.push_back(0);
						mask.push_back('?');
					}
					nibbleCount -= 2;
				} while (nibbleCount > 0);
				nibbleCount = 0;
				nibblesUnknown = false;
			}
			if (currentChar == '\0') {
				break;
			}
			nibbleSequenceStart = byteSpecificationPtr + 1;
		}
		++byteSpecificationPtr;
	}
	sig.push_back('\0');
	mask.push_back('\0');
	#undef byteSpecificationError
	return numOfTriangularChars;
}

struct Sig {
    std::vector<char> sig;
    std::vector<char> mask;
    std::vector<size_t> positions;
    Sig() = default;
    Sig(const char* byteSpecification) {
        size_t numChar = 0;
        for (const char* ptr = byteSpecification; *ptr != '\0'; ++ptr) {
            if (*ptr == '>') ++numChar;
        }
        if (numChar) {
            positions.resize(numChar);
        }
        byteSpecificationToSigMask(byteSpecification, sig, mask, positions.data(), numChar);
    }
};

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

DWORD rawToVa(DWORD rawAddr) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader) + pNtHeader->FileHeader.NumberOfSections;
    for (int sectionIndex = (int)pNtHeader->FileHeader.NumberOfSections - 1; sectionIndex >= 0; --sectionIndex) {
        --section;
        if (rawAddr >= section->PointerToRawData) {
			return rawAddr - section->PointerToRawData + section->VirtualAddress + pNtHeader->OptionalHeader.ImageBase;
		}
	}
	return 0;
}

DWORD vaToRaw(DWORD va) {
    va -= pNtHeader->OptionalHeader.ImageBase;
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader) + pNtHeader->FileHeader.NumberOfSections;
    for (int sectionIndex = (int)pNtHeader->FileHeader.NumberOfSections - 1; sectionIndex >= 0; --sectionIndex) {
        --section;
        if (va >= section->VirtualAddress) {
			return va - section->VirtualAddress + section->PointerToRawData;
		}
	}
	return 0;
}

DWORD vaToRva(DWORD va) {
	return va - pNtHeader->OptionalHeader.ImageBase;
}

DWORD rvaToVa(DWORD rva) {
	return rva + pNtHeader->OptionalHeader.ImageBase;
}

DWORD rvaToRaw(DWORD rva) {
    return vaToRaw(rva + pNtHeader->OptionalHeader.ImageBase);
}

DWORD rawToRva(DWORD raw) { return rawToVa(raw) - pNtHeader->OptionalHeader.ImageBase; }
inline DWORD ptrToRaw(BYTE* ptr) { return (DWORD)(ptr - fileBase); }
DWORD ptrToRva(BYTE* ptr) { return rawToRva(ptrToRaw(ptr)); }
DWORD ptrToVa(BYTE* ptr) { return rawToVa(ptrToRaw(ptr)); }
inline BYTE* rawToPtr(DWORD raw) { return raw + fileBase; }
BYTE* rvaToPtr(DWORD rva) { return rawToPtr(rvaToRaw(rva)); }
BYTE* vaToPtr(DWORD va) { return rawToPtr(vaToRaw(va)); }

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

void trimLeft(std::string& str) {
    if (str.empty()) return;
	auto it = str.begin();
	while (it != str.end() && *it <= 32) ++it;
	str.erase(str.begin(), it);
}

void trimRight(std::string& str) {
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

// does not close the file, but truncates it
void overwriteWholeFile(FILE* file, const std::vector<char>& data) {
    fseek(file, 0, SEEK_SET);
    fwrite(data.data(), 1, data.size(), file);
    fflush(file);
    #ifndef FOR_LINUX
    SetEndOfFile((HANDLE)_get_osfhandle(_fileno(file)));
    #else
    ftruncate(fileno(file), data.size());
    #endif
}

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
	DWORD relocTableSize;  // remaining size
	const char* relocTableNext;
	
	RelocBlockIterator(const char* relocTable, DWORD relocTableVa, DWORD relocTableSize)
		:
		relocTableOrig(relocTable),
		relocTableVa(relocTableVa),
		relocTableSize(relocTableSize),
		relocTableNext(relocTable) { }
		
	bool getNext(FoundRelocBlock& block) {
		
		if (relocTableSize == 0) return false;
		
		const char* relocTable = relocTableNext;
		
		DWORD pageBaseRva = *(DWORD*)relocTable;
		DWORD pageBaseVa = rvaToVa(pageBaseRva);
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
	
	// Finds the file position of the start of the reloc table and its size
	void findRelocTable() {
		
		const char* peHeaderStart = (char*)fileBase + *(DWORD*)(fileBase + 0x3C);
		
	    const char* relocSectionHeader = peHeaderStart + 0xA0;
	    
	    DWORD relocRva = *(DWORD*)relocSectionHeader;
	    DWORD* relocSizePtr = (DWORD*)relocSectionHeader + 1;
	    sizeWhereRaw = (uintptr_t)((const BYTE*)relocSizePtr - fileBase) & 0xFFFFFFFF;
	    
	    va = rvaToVa(relocRva);
	    raw = rvaToRaw(relocRva);
	    relocTable = (char*)fileBase + raw;
	    size = *relocSizePtr;
	}
	
	// region specified in Virtual Address space
	std::vector<FoundReloc> findRelocsInRegion(DWORD regionStart, DWORD regionEnd) const {
		std::vector<FoundReloc> result;
		
		RelocBlockIterator blockIterator(relocTable, va, size);
		
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
		
		RelocBlockIterator blockIterator(relocTable, va, size);
		
		FoundRelocBlock block;
		while (blockIterator.getNext(block));
		return block;
	}
	
	// returns empty, unused entries that could potentially be reused for the desired vaToPatch
	std::vector<FoundReloc> findReusableRelocEntries(DWORD vaToPatch) const {
		std::vector<FoundReloc> result;
		
		RelocBlockIterator blockIterator(relocTable, va, size);
		
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
		unsigned short relocEntry = ((unsigned short)type << 12) | (vaToRva(vaToRelocate) & 0xFFF);
		
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
		
		
		DWORD rvaToRelocate = vaToRva(vaToRelocate);
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
	
} relocTable;  // RelocTable is able to modify the contents of fileBase

// you must use the returned result immediately or copy it somewhere. Do not store it as-is. This function is not thread-safe either
const char* printRelocType(char type) {
	static char printRelocTypeBuf[12];  // the maximum possible length of string printed by printf("%d", (int)value), plus null terminating character
	switch (type) {
		case IMAGE_REL_BASED_HIGH: return "IMAGE_REL_BASED_HIGH";
		case IMAGE_REL_BASED_LOW: return "IMAGE_REL_BASED_LOW";
		case IMAGE_REL_BASED_HIGHLOW: return "IMAGE_REL_BASED_HIGHLOW";
		case IMAGE_REL_BASED_HIGHADJ: return "IMAGE_REL_BASED_HIGHADJ";
		case IMAGE_REL_BASED_DIR64: return "IMAGE_REL_BASED_DIR64";
		default: SPRINTF_NARROW(printRelocTypeBuf, "%d", (int)type); return printRelocTypeBuf;
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
			const char* rdataBegin, const char* rdataEnd,
			const char* dataBegin, const char* dataEnd,
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
	strPos += (rdataBegin - (char*)fileBase) & 0xFFFFFFFF;
	CrossPlatformCout << "Found " << name << " string at file:0x" << std::hex << strPos << std::dec << ".\n";
	
	DWORD strVa = rawToVa(strPos);
	
	int strMentionPos = sigscanEveryNBytes<4>(dataBegin, dataEnd, (const char*)&strVa);
	if (strMentionPos == -1) {
		CrossPlatformCout << "Failed to find mention of " << name << " string.\n";
		return false;
	}
	strMentionPos += (dataBegin - (char*)fileBase) & 0xFFFFFFFF;
	CrossPlatformCout << "Found mention of " << name << " string at file:0x" << std::hex << strMentionPos << std::dec << ".\n";
	
	*va = *(DWORD*)((char*)fileBase + strMentionPos + 4);
	CrossPlatformCout << "Found " << name << " function at va:0x" << std::hex << *va << std::dec << ".\n";
	
	*pos = vaToRaw(*va);
	return true;
}

/// <summary>
/// Finds the address which holds a pointer to a function with the given name imported from the given DLL,
/// in a given 32-bit portable executable file.
/// For example, searching USER32.DLL, GetKeyState would return a positive value on successful find, and
/// in a running process you'd cast that value to a short (__stdcall**)(int).
/// </summary>
/// <param name="dll">Include ".DLL" in the DLL's name here. Case-insensitive.</param>
/// <param name="function">The name of the function. Case-sensitive.</param>
/// <returns>The file offset which holds a pointer to a function. -1 if not found.</returns>
int findImportedFunction(const char* dll, const char* function) {
	
	// see IMAGE_IMPORT_DESCRIPTOR
	struct ImageImportDescriptor {
		DWORD ImportLookupTableRVA;  // The RVA of the import lookup table. This table contains a name or ordinal for each import. (The name "Characteristics" is used in Winnt.h, but no longer describes this field.)
		DWORD TimeDateStamp;  // The stamp that is set to zero until the image is bound. After the image is bound, this field is set to the time/data stamp of the DLL. LIES, this field is 0 for me at runtime.
		DWORD ForwarderChain;  // The index of the first forwarder reference. 0 for me.
		DWORD NameRVA;  // The address of an ASCII string that contains the name of the DLL. This address is relative to the image base.
		DWORD ImportAddressTableRVA;  // The RVA of the import address table. The contents of this table are identical to the contents of the import lookup table until the image is bound.
	};
	DWORD importsSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	const ImageImportDescriptor* importPtrNext = (const ImageImportDescriptor*)(rvaToPtr(
		pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	));
	for (; importsSize > 0; importsSize -= sizeof (ImageImportDescriptor)) {
		const ImageImportDescriptor* importPtr = importPtrNext++;
		if (!importPtr->ImportLookupTableRVA) break;
		const char* dllName = (const char*)(rvaToPtr(importPtr->NameRVA));
		if (CrossPlatformStringCompareCaseInsensitive(dllName, dll) != 0) continue;
		DWORD* funcPtr = (DWORD*)(rvaToPtr(importPtr->ImportAddressTableRVA));
		DWORD* imageImportByNameRvaPtr = (DWORD*)(rvaToPtr(importPtr->ImportLookupTableRVA));
		struct ImageImportByName {
			short importIndex;  // if you know this index you can use it for lookup. Name is just convenience for programmers.
			char name[1];  // arbitrary length, zero-terminated ASCII string
		};
		do {
			DWORD rva = *imageImportByNameRvaPtr;
			if (!rva) break;
			const ImageImportByName* importByName = (const ImageImportByName*)(rvaToPtr(rva));
			if (strcmp(importByName->name, function) == 0) {
				return (int)((BYTE*)funcPtr - fileBase);
			}
			++funcPtr;
			++imageImportByNameRvaPtr;
		} while (true);
		return -1;
	}
	return -1;
}

int findImportedFunctionAndReport(const char* dllName, const char* functionName) {
    int found = findImportedFunction(dllName, functionName);
	if (found == -1) {
	    CrossPlatformCout << "Failed to find " << functionName << " function.\n";
	    return -1;
	}
	CrossPlatformCout << "Found " << functionName << " function at va:0x"
	    << std::hex << rawToVa(found) << std::dec << '\n';
	return found;
}

Sig FFileManagerWindows_GetFileTimestamp_Sig;
	
int FFileManagerWindows_GetFileTimestamp = -1;
int CreateFileWOff = -1;
int GetFileTimeOff = -1;
int CloseHandleOff = -1;
int GetFileAttributesWOff = -1;
	
// finds everything that's needed to run patchDaylightSaving
bool findInfoForPatchingDaylightSaving(FILE* file,
	    char* textBegin,
	    char* textEnd,
	    char* rdataBegin,
	    char* rdataEnd) {
    
    FFileManagerWindows_GetFileTimestamp_Sig = Sig{
        "6a ff 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 83 ec 60 a1 ?? ?? ?? ?? 33 c4 89 44 24 5c 53 55 56 57"
        " a1 ?? ?? ?? ?? 33 c4 50 8d 44 24 74 64 a3 00 00 00 00 8b bc 24 84 00 00 00 8b f1 8b 06 8b 50 54 57 8d 4c 24 2c 51 8b ce"
        " ff d2 33 db 89 5c 24 7c 39 58 04 74 04 8b 00 eb 05"
        #define MOV_EAX_EMPTYSTRING 0  // MOV EAX,""
        " >b8 ?? ?? ?? ??"
        " 8b 16 8b 52 58 50 8d 44 24 20 50 8b ce ff d2 39 58 04 74 04 8b 00 eb 05"
        " b8 ?? ?? ?? ?? 8b 2d 44 d5 48 01 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e"
        #define NEGATIVE_1 1  // MOVSD XMM0,qword ptr [DOUBLE_014a0db0], DOUBLE_014a0db0 says 00 00 00 00 00 00 f0 bf, which means -1.0
        " >f2 0f 10 05 ?? ?? ?? ??"
        " f2 0f 11 44 24 14 8b 44 24 1c 89 5c 24 24 89 5c 24 20 3b c3 74 0d 50"
        #define APP_FREE 2  // CALL appFree
        " >e8 ?? ?? ?? ??"
        " 83 c4 04 89 5c 24 1c 8b 44 24 28 c7 44 24 7c ff ff ff ff 89 5c 24 30 89 5c 24 2c 3b c3 74 09 50 e8 ?? ?? ?? ??"
        " 83 c4 04 f2 0f 10 44 24 14 66 0f 2e 05 ?? ?? ?? ?? 9f f6 c4 44 7a 5d 8b 16 8b 52 54 57 8d 44 24 38 50 8b ce"
        " ff d2 39 58 04 74 04 8b 00 eb 05 b8 ?? ?? ?? ?? 8d 4c 24 40 51 50 ff d5 83 c4 08 85 c0 75 0a df 6c 24 60 dd 5c 24 14 eb 0e"
        " f2 0f 10 05 ?? ?? ?? ?? f2 0f 11 44 24 14 8b 44 24 34 89 5c 24 3c 89 5c 24 38 3b c3 74 09 50 e8 ?? ?? ?? ??"
        " 83 c4 04 dd 44 24 14 8b 4c 24 74 64 89 0d 00 00 00 00 59 5f 5e 5d 5b 8b 4c 24 5c 33 cc e8 ?? ?? ?? ?? 83 c4 6c c2 04 00"
    };
	// ConvertToAbsolutePath is 0x54. Takes FString* out and wchar_t* Filename. Returns out
	// ConvertAbsolutePathToUserPath is 0x58. Takes FString* out and wchar_t* AbsolutePath. Returns out
	
	FFileManagerWindows_GetFileTimestamp = sigscan(textBegin, textEnd,
	    FFileManagerWindows_GetFileTimestamp_Sig.sig.data(),
	    FFileManagerWindows_GetFileTimestamp_Sig.mask.data());
	
	if (FFileManagerWindows_GetFileTimestamp == -1) {
	    Sig testSig{"53 55 56 57 8b f1 83 ec ?? 8b 06 8b 50 54 8B 7C 24 ?? 57"};
	    if (sigscan(textBegin, textEnd, testSig.sig.data(), testSig.mask.data()) != -1) {
	        CrossPlatformCout << "FFileManagerWindows::GetFileTimestamp function is already patched.\n";
	        return true;
	    } else {
	        CrossPlatformCout << "Failed to find FFileManagerWindows::GetFileTimestamp function.\n";
	        return false;
	    }
	}
	FFileManagerWindows_GetFileTimestamp += (int)(textBegin - (char*)fileBase);
	CrossPlatformCout << "Found FFileManagerWindows::GetFileTimestamp function at va:0x"
	    << std::hex << rawToVa(FFileManagerWindows_GetFileTimestamp) << std::dec << '\n';
	
	CreateFileWOff = findImportedFunctionAndReport("kernel32.dll", "CreateFileW");
	if (CreateFileWOff == -1) return false;
	GetFileTimeOff = findImportedFunctionAndReport("kernel32.dll", "GetFileTime");
	if (GetFileTimeOff == -1) return false;
	CloseHandleOff = findImportedFunctionAndReport("kernel32.dll", "CloseHandle");
	if (CloseHandleOff == -1) return false;
	GetFileAttributesWOff = findImportedFunctionAndReport("kernel32.dll", "GetFileAttributesW");
	if (GetFileAttributesWOff == -1) return false;
	
	return true;
}

struct DesiredEdit {
    int charOffsetStart;
    int charOffsetEnd;  // non-inclusive
    std::string newText;
};

struct SectionTracker {
    
    bool freshLine = true;
    bool dontLikeLine = false;  // used for parsing [section]s
    std::string sectionName;
    bool inSectionName = false;
    bool isInSectionOfInterest = false;
    bool isComment = false;
    std::string keyName;
    std::string value;
    bool encounteredEqualSign = false;
    CrossPlatformString redgame_Folder;  // UE3 adds one more .. at the start of BasedOn values
    bool basedOnDetected = false;
    double basedOnTimestamp = 0.0;
    int lineStartOffset = -1;
    bool lineNonEmpty = false;  // comments are considered non-empty
    // subclassing? Pff, we don't do that OOP crap here
    std::vector<double> newTimestamps;
    std::vector<DesiredEdit> desiredEdits;
    int lastSkippableMoviesEnd = -1;
    int FullScreenMovieSectionLineEnd = -1;
    int FullScreenMovieSectionLastNonEmptyLineEnd = -1;
    bool alreadyIgnoresIntro = false;
    void(SectionTracker::*onLineEnd)(int charOffset) = nullptr;
    
    void onLineEnd_BasedOn(int charOffset) {
        if (!dontLikeLine && !sectionName.empty() && !inSectionName) {
            if (CrossPlatformStringCompareCaseInsensitive(sectionName.c_str(), "Configuration") == 0) {
                isInSectionOfInterest = true;
            } else {
                isInSectionOfInterest = false;
            }
        } else if (isInSectionOfInterest && !keyName.empty() && !value.empty()) {
            trimLeft(value);
            trimRight(value);
            if (CrossPlatformStringCompareCaseInsensitive(keyName.c_str(), "BasedOn") == 0) {
                CrossPlatformString currentPath = redgame_Folder;
                CrossPlatformString currentPiece;
                for (char c : value) {
                    if (c == '\\') {
                        if (!currentPiece.empty() && CrossPlatformPathCompare(currentPiece.c_str(), CrossPlatformText("..")) == 0) {
                            currentPath = getParentDir(currentPath);
                        } else if (!currentPiece.empty()) {
                            currentPath += PATH_SEPARATOR + currentPiece;
                        }
                        currentPiece.clear();
                    } else {
                        currentPiece += (CrossPlatformChar)c;
                    }
                }
                if (!currentPiece.empty()) {
                    currentPath += PATH_SEPARATOR + currentPiece;
                }
                
                basedOnDetected = getTimestamp(currentPath, &basedOnTimestamp);
                
            }
        }
    }
    
    void onLineEnd_IniVersion(int charOffset) {
        if (!dontLikeLine && !sectionName.empty() && !inSectionName) {
            if (CrossPlatformStringCompareCaseInsensitive(sectionName.c_str(), "IniVersion") == 0) {
                isInSectionOfInterest = true;
            } else {
                isInSectionOfInterest = false;
            }
        } else if (isInSectionOfInterest && !keyName.empty() && !value.empty() && lineStartOffset != -1) {
            int parsedIndex = -1;
            if (strcmp(keyName.c_str(), "0") == 0) {
                parsedIndex = 0;
            } else if (strcmp(keyName.c_str(), "1") == 0) {
                parsedIndex = 1;
            }
            if (parsedIndex != -1 && parsedIndex < (int)newTimestamps.size()) {
                char strbuf[1024];
                SPRINTF_NARROW(strbuf, "%d=%f", parsedIndex, newTimestamps[parsedIndex]);
                
                desiredEdits.emplace_back();
                DesiredEdit& newEdit = desiredEdits.back();
                newEdit.charOffsetStart = lineStartOffset;
                newEdit.charOffsetEnd = charOffset;
                newEdit.newText = strbuf;
            }
        }
    }
    
    void onLineEnd_ignoreIntro(int charOffset) {
        if (!dontLikeLine && !sectionName.empty() && !inSectionName) {
            if (CrossPlatformStringCompareCaseInsensitive(sectionName.c_str(), "FullScreenMovie") == 0) {
                isInSectionOfInterest = true;
                FullScreenMovieSectionLineEnd = charOffset;
            } else {
                isInSectionOfInterest = false;
            }
        } else if (isInSectionOfInterest && !keyName.empty() && !value.empty() && lineStartOffset != -1) {
            int parsedIndex = -1;
            if (CrossPlatformStringCompareCaseInsensitive(keyName.c_str(), "SkippableMovies") == 0) {
                lastSkippableMoviesEnd = charOffset;
                trimLeft(value);
                trimRight(value);
                if (CrossPlatformStringCompareCaseInsensitive(value.c_str(), "Splash_Steam") == 0) {
                    alreadyIgnoresIntro = true;
                }
            }
        } else if (isInSectionOfInterest && lineStartOffset != -1 && lineNonEmpty) {
            FullScreenMovieSectionLastNonEmptyLineEnd = charOffset;
        }
    }
    
    static bool getTimestamp(const CrossPlatformString& path, double* timestamp) {
        
        if (fileExists(path)) {
            
            unsigned long long ticks = 0;
            
            #define SECS_1601_TO_1970  ((369 * 365 + 89) * (ULONGLONG)86400)
            #define TICKSPERSEC 10000000
            
            #ifndef FOR_LINUX
            CreateFileW(L"path",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            HANDLE baseFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (baseFile != INVALID_HANDLE_VALUE) {
                
                struct OwnFileCloser {
                    ~OwnFileCloser() {
                        if (file) CloseHandle(file);
                    }
                    HANDLE file = NULL;
                } ownFileCloser { baseFile };
                
                FILETIME fileTime;
                
                if (GetFileTime(baseFile, NULL, NULL, &fileTime)) {
                    ticks = *(unsigned long long*)&fileTime;
                    ticks = (ticks - SECS_1601_TO_1970 * TICKSPERSEC) / TICKSPERSEC;
                }
            }
            #else
            struct stat buf;
            int statResult = stat(path.c_str(), &buf);
            if (statResult != -1) {
                if (sizeof(time_t) == sizeof(int)) {
                    ticks = (ULONGLONG)(ULONG)buf.st_mtime;
                } else {
                    ticks = (ULONGLONG)buf.st_mtime;
                }
            }
            #endif
            
            if (ticks) {
                *timestamp = (double)ticks;
                return true;
            }
        }
        return false;
    }
    
    void reset() {
        lineStartOffset = -1;
        lineNonEmpty = false;
        keyName.clear();
        value.clear();
        freshLine = true;
        dontLikeLine = false;
        sectionName.clear();
        inSectionName = false;
        encounteredEqualSign = false;
        isComment = false;
    }
    
    void parseChar(char c, int charOffset) {
        if (c == '\r' || c == '\n') {
            (this->*onLineEnd)(charOffset);
            reset();
        } else if (freshLine && c == '[') {
            inSectionName = true;
            lineStartOffset = charOffset;
            freshLine = false;
            lineNonEmpty = true;
        } else if (inSectionName) {
            if (c == ']') {
                inSectionName = false;
            } else {
                sectionName += c;
            }
        } else if (!freshLine && (c == '\t' || c == ' ') && !sectionName.empty()) {
            // ok, allowed to have whitespace after a section ]
            // UE3 only considers '\t' and ' ' to be whitespace
        } else {
            if (freshLine) {
                if (c == ';') isComment = true;
                lineStartOffset = charOffset;
                freshLine = false;
            }
            lineNonEmpty = lineNonEmpty || c > 32;
            dontLikeLine = true;
            if (isInSectionOfInterest && !isComment) {
                if (c == '=' && !encounteredEqualSign) {
                    encounteredEqualSign = true;
                    trimLeft(keyName);
                    trimRight(keyName);
                } else if (!encounteredEqualSign) {
                    keyName += c;
                } else {
                    value += c;
                }
            }
        }
    }
    
    void runLoop(const std::vector<char>& data, void(SectionTracker::*onLineEndParam)(int charOffset)) {
        onLineEnd = onLineEndParam;
        int cOffset = 0;
        for (char c : data) {
            parseChar(c, cOffset);
            ++cOffset;
        }
        (this->*onLineEnd)(cOffset);
    }
    
    void applyEdits(std::vector<char>& data) {
        for (DesiredEdit& desiredEdit : desiredEdits) {
            data.erase(data.begin() + desiredEdit.charOffsetStart, data.begin() + desiredEdit.charOffsetEnd);
            data.insert(data.begin() + desiredEdit.charOffsetStart, desiredEdit.newText.size(), 0);
            memcpy(data.data() + desiredEdit.charOffsetStart, desiredEdit.newText.c_str(), desiredEdit.newText.size());
            int shift = (int)desiredEdit.newText.size()
                - (desiredEdit.charOffsetEnd - desiredEdit.charOffsetStart);
            for (DesiredEdit& desiredEditModif : desiredEdits) {
                if (desiredEditModif.charOffsetStart > desiredEdit.charOffsetStart) {
                    desiredEditModif.charOffsetStart += shift;
                    desiredEditModif.charOffsetEnd += shift;
                }
            }
        }
    }
    
};

// also updates RED* INI files' IniVersion timestamps.
// Closes the file
void patchDaylightSaving(FILE* file,
    const CrossPlatformString& szFile,
	char* textBegin,
	char* textEnd,
	char* rdataBegin,
	char* rdataEnd) {
    
	struct NewCode {
	    std::vector<BYTE> data;
	    void add(const Sig& sig) {
	        if (sig.mask.empty()) return;
	        if (sig.mask.front() == '\0') return;
	        data.insert(data.end(), sig.sig.begin(), sig.sig.end() - 1);
	    }
	    void add(const Sig& sig, DWORD substitute) {
	        if (sig.mask.empty()) return;
	        if (sig.mask.front() == '\0') return;
	        
	        #ifdef _DEBUG
            static bool reportedOnce = false;
	        bool broke = false;
	        #endif
	        int count = 0;
	        std::vector<char>::const_iterator maskIt;
	        std::vector<char>::const_iterator nextIt = sig.mask.begin();
	        for (int charCount = (int)sig.sig.size() - 1; charCount > 0; --charCount) {
	            maskIt = nextIt++;
	            if (*maskIt == '?') {
                    #ifdef _DEBUG
                    if (broke) {
                        if (!reportedOnce) {
                            reportedOnce = true;
                            MessageBoxW(mainWindow, L"Can't have multiple groups of '?' for substitution.", L"Error", MB_OK);
                        }
                        return;
                    }
                    #endif
	                ++count;
	            }
                #ifdef _DEBUG
	            else if (count) {
                    broke = true;
                    if (count != 4 && count != 1) {
                        if (!reportedOnce) {
                            reportedOnce = true;
                            MessageBoxW(mainWindow, L"Wrong number of '?' for substitution.", L"Error", MB_OK);
                        }
                        return;
                    }
	            }
                #endif
	        }
	        #ifdef _DEBUG
	        if (count != 4 && count != 1) {
                if (!reportedOnce) {
                    reportedOnce = true;
                    MessageBoxW(mainWindow, L"Wrong number of '?' for substitution.", L"Error", MB_OK);
                }
                return;
	        }
	        #endif
	        size_t oldSize = data.size();
	        data.resize(oldSize + sig.sig.size() - 1);
	        auto dest = data.begin() + oldSize;
	        auto src = sig.sig.begin();
	        maskIt = sig.mask.begin();
	        
	        for (int charCount = (int)sig.sig.size() - 1; charCount > 0; ) {
	            if (*maskIt == '?') {
	                if (count == 4) {
	                    *(DWORD*)&*dest = substitute;
	                    dest += 4;
                        src += 4;
                        maskIt += 4;
                        charCount -= 4;
	                } else if (count == 1) {
	                    *(BYTE*)&*dest = (BYTE)substitute;
	                    ++dest;
                        ++src;
                        ++maskIt;
                        --charCount;
	                }
	            } else {
	                *dest++ = *src++;
	                ++maskIt;
	                --charCount;
	            }
	        }
	    }
	} newCode;
	
	#define FIRST_FSTRING 0x0  // FString (12 bytes). MUST BE 0 due to using a 8B 04 24 instruction
	#define SECOND_FSTRING 0xc  // FString (12 bytes)
	#define FIRST_TEXT 0x18  // const wchar_t* (4 bytes)
	#define RESULT 0x1c  // double (8 bytes)
	#define FILETIMEVAR 0x24  // FILETIME (8 bytes)
	#define SUCCESSFUL_PATH 0x2c  // const wchar_t* (4 bytes)
	#define STACK_SPACE 0x60
	
	newCode.add(
	    "53 55 56 57"  // PUSH EBX,EBP,ESI,EDI
	    " 8b f1"  // MOV ESI,ECX
	    " 83 ec ??", STACK_SPACE);  // SUB ESP,STACK_SPACE
	    
    newCode.add("8b 06"  // MOV EAX,dword ptr [ESI]
	    " 8b 50 54"  // MOV EDX,dword ptr [EAX + 0x54]  ; ConvertToAbsolutePath. Takes FString* out and wchar_t* Filename. Returns out
	    " 8B 7C 24 ??", STACK_SPACE + 0x10 + 0x4);  // MOV EDI,dword ptr [ESP + STACK_SPACE + 0x10 (4 pushes) + 4 (Filename, first stack argument)]
    newCode.add("57");  // PUSH EDI
	newCode.add("8d 4c 24 ??", FIRST_FSTRING + 4  /* see PUSH EDI above */);  // LEA ECX,[ESP + FIRST_FSTRING + 4]
	newCode.add("51"  // PUSH ECX
	    " 8b ce" // MOV ECX,ESI
	    " ff d2"  // CALL EDX
    );
	
	DWORD baseVa = rawToVa(FFileManagerWindows_GetFileTimestamp);
	DWORD emptyStringVa = *(DWORD*)(fileBase + FFileManagerWindows_GetFileTimestamp + FFileManagerWindows_GetFileTimestamp_Sig.positions[MOV_EAX_EMPTYSTRING] + 1);
	CrossPlatformCout << "Found an empty string at va:0x" << std::hex << emptyStringVa << std::dec << '\n';
	DWORD negative1Va = *(DWORD*)(fileBase + FFileManagerWindows_GetFileTimestamp + FFileManagerWindows_GetFileTimestamp_Sig.positions[NEGATIVE_1] + 4);
	CrossPlatformCout << "Found an -1.0 at va:0x" << std::hex << negative1Va << std::dec << '\n';
	DWORD appFreeVa = baseVa
	    + (DWORD)FFileManagerWindows_GetFileTimestamp_Sig.positions[APP_FREE]
	    + 5
	    + *(int*)(fileBase + FFileManagerWindows_GetFileTimestamp + FFileManagerWindows_GetFileTimestamp_Sig.positions[APP_FREE] + 1);
	CrossPlatformCout << "Found appFree function at va:0x" << std::hex << appFreeVa << std::dec << '\n';
	
	std::vector<FoundReloc> relocs = relocTable.findRelocsInRegion(
	    baseVa,
	    baseVa + (DWORD)FFileManagerWindows_GetFileTimestamp_Sig.sig.size() - 1);
	
	for (const FoundReloc& foundReloc : relocs) {
		relocTable.removeEntry(file, foundReloc);
	}
	
	newCode.add(
	    "33 db"  // XOR EBX,EBX
	    " 39 58 04"  // CMP dword ptr [EAX + 0x4],EBX
	    " 74 04"  // JZ 0x4
	    " 8b 00"  // MOV EAX,dword ptr [EAX]  ; read Data member of FString
	    " eb 05"  // JMP 0x5
    );
	size_t newCodeSize = newCode.data.size();
	newCode.add("b8 ?? ?? ?? ??", emptyStringVa);  // MOV EAX,emptyString
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 1, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("89 44 24 ??", FIRST_TEXT);  // MOV dword ptr[ESP+FIRST_TEXT],EAX
	
	newCode.add(
	    "8b 16"  // MOV EDX,dword ptr [ESI]
	    " 8b 52 58"  // MOV EDX,dword ptr[EDX + 0x58]  ; ConvertAbsolutePathToUserPath. Takes FString* out and wchar_t* AbsolutePath. Returns out
	    " 50"  // PUSH EAX
	    " 8d 44 24 ??", SECOND_FSTRING + 4 /* see PUSH EAX above */);  // LEA EAX,[ESP + SECOND_FSTRING + 4]
	newCode.add("50"  // PUSH EAX
	    " 8b ce" // MOV ECX,ESI
	    " ff d2"  // CALL EDX
	    
	    " 39 58 04"  // CMP dword ptr [EAX + 0x4],EBX
	    " 74 04"  // JZ 0x4
	    " 8b 00"  // MOV EAX,dword ptr [EAX]  ; read Data member of FString
	    " eb 05"  // JMP 0x5
    );
	newCodeSize = newCode.data.size();
	newCode.add("b8 ?? ?? ?? ??", emptyStringVa);  // MOV EAX,emptyString
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 1, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("89 44 24 ??", SUCCESSFUL_PATH);  // MOV dword ptr[ESP + SUCCESSFUL_PATH],EAX
	newCode.add("50");  // PUSH EAX
	
	newCodeSize = newCode.data.size();
	newCode.add("8b 2d ?? ?? ?? ??", rawToVa(GetFileAttributesWOff));  // MOV EBP,dword ptr[->KERNEL32.DLL::GetFileAttributesW]
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 2, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("FF D5"  // CALL EBP
	    " 4B"  // DEC EBX
	    " 39 D8");  // CMP EAX,EBX
	size_t jmpToAfterRet1 = newCode.data.size();
	newCode.add("75 00"  // JNZ afterRet, will fill in later
	    " 8B 44 24 ??", FIRST_TEXT);  // MOV EAX,dword ptr[ESP + FIRST_TEXT]
    newCode.add("89 44 24 ??", SUCCESSFUL_PATH);  // MOV dword ptr[ESP + SUCCESSFUL_PATH],EAX
	newCode.add("50");  // PUSH EAX
	newCode.add("ff d5"  // CALL EBP
	    " 39 D8");  // CMP EAX,EBX
	size_t jmpToAfterRet2 = newCode.data.size();
	newCode.add("75 00");  // JNZ afterRet, will fill in later
	
	newCodeSize = newCode.data.size();
	size_t errorReturn = newCodeSize;
	newCode.add("f2 0f 10 05 ?? ?? ?? ??", negative1Va);  // MOVSD XMM0,qword ptr[-1.0]
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 4, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("f2 0f 11 44 24 ??", RESULT);  // MOVSD qword ptr[ESP + RESULT],XMM0
	
	size_t returnLabel = newCode.data.size();
	newCode.add("43"  // INC EBX
	    " 8B 04 24"  // MOV EAX,dword ptr[ESP]  ; read Data member of first FString
	    " 39 D8"  // CMP EAX,EBX
	    " 74 09"  // JZ 0x9
	    " 50"  // PUSH EAX
    );
	newCodeSize = newCode.data.size();
	int offset = (int)appFreeVa - (int)(baseVa + newCodeSize + 5);
	newCode.add("e8 ?? ?? ?? ??", offset);
	
	newCode.add("83 c4 04"  // ADD ESP,0x4
	    " 8b 44 24 ??", SECOND_FSTRING);  // MOV EAX,dword ptr[ESP + SECOND_FSTRING]  ; read Data member of second FString
	newCode.add("39 D8"  // CMP EAX,EBX
	    " 74 09"  // JZ 0x9
	    " 50"  // PUSH EAX
    );
	newCodeSize = newCode.data.size();
	offset = (int)appFreeVa - (int)(baseVa + newCodeSize + 5);
	newCode.add("e8 ?? ?? ?? ??", offset);
	
	newCode.add("83 c4 04"  // ADD ESP,0x4
	    " dd 44 24 ??", RESULT);  // FLD qword ptr[ESP + RESULT]
	newCode.add("83 c4 ??", STACK_SPACE);  // ADD ESP,STACK_SPACE
	newCode.add("5f 5e 5d 5b"  // POP EDI,ESI,EBP,EBX
	    " c2 04 00");  // RET 0x4
	
	int jumpDistance = (int)(newCode.data.size() - (jmpToAfterRet1 + 2));
	#ifdef _DEBUG
	if (jumpDistance > 0x7f) {
	    MessageBoxW(mainWindow, L"Jump offset 1 too long.", L"Error", MB_OK);
	    return;
	}
	#endif
	newCode.data[jmpToAfterRet1 + 1] = (BYTE)jumpDistance;
	
	jumpDistance = (int)(newCode.data.size() - (jmpToAfterRet2 + 2));
	#ifdef _DEBUG
	if (jumpDistance > 0x7f) {
	    MessageBoxW(mainWindow, L"Jump offset 2 too long.", L"Error", MB_OK);
	    return;
	}
	#endif
	newCode.data[jmpToAfterRet2 + 1] = (BYTE)jumpDistance;
	
	// CreateFileW(L"path",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	newCode.add("6A 00");  // PUSH 0
	newCode.add("68 ?? ?? ?? ??", FILE_ATTRIBUTE_NORMAL);  // PUSH FILE_ATTRIBUTE_NORMAL
	newCode.add("6A ??", OPEN_EXISTING);  // PUSH OPEN_EXISTING
	newCode.add("6A 00");  // PUSH 0
	newCode.add("6A ??", FILE_SHARE_READ);  // PUSH FILE_SHARE_READ
	newCode.add("68 ?? ?? ?? ??", GENERIC_READ);  // PUSH GENERIC_READ
	newCode.add("FF 74 24 ??", SUCCESSFUL_PATH + 6*4);  // PUSH dword ptr[ESP + SUCCESSFUL_PATH + 6pushes]
	
	newCodeSize = newCode.data.size();
	newCode.add("ff 15 ?? ?? ?? ??", rawToVa(CreateFileWOff));  // CALL dword ptr[->KERNEL32.DLL::CreateFileW]
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 2, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("8b f0"  // MOV ESI,EAX
	    " 39 DE"  // CMP ESI,EBX
    );
	#ifdef _DEBUG
	if (newCode.data.size() + 2 - errorReturn > 0x80) {
	    MessageBoxW(mainWindow, L"Can't jump from CreateFileW to error return.", L"Error", MB_OK);
	    return;
	}
	#endif
	newCode.add("74 ??", (int)errorReturn - (int)(newCode.data.size() + 2));  // JZ errorReturn
	
	// GetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
	newCode.add("8D 44 24 ??", FILETIMEVAR);  // LEA EAX,[ESP+FILETIMEVAR]
	newCode.add("50"  // PUSH EAX
	    " 6A 00"  // PUSH 0
	    " 6A 00"  // PUSH 0
	    " 56");  // PUSH ESI
	
	newCodeSize = newCode.data.size();
	newCode.add("ff 15 ?? ?? ?? ??", rawToVa(GetFileTimeOff));  // CALL dword ptr[->KERNEL32.DLL::GetFileTime]
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 2, IMAGE_REL_BASED_HIGHLOW);
	
	#ifdef _DEBUG
	if (newCode.data.size() + 4 - errorReturn > 0x80) {
	    MessageBoxW(mainWindow, L"Can't jump from GetFileTime to error return.", L"Error", MB_OK);
	    return;
	}
	#endif
	
	newCode.add("89 c5"  // MOV EBP,EAX
	    " 56");  // PUSH ESI
	
	newCodeSize = newCode.data.size();
	newCode.add("ff 15 ?? ?? ?? ??", rawToVa(CloseHandleOff));  // CALL dword ptr[->KERNEL32.DLL::CloseHandle]
	relocTable.addEntry(file, baseVa + (DWORD)newCodeSize + 2, IMAGE_REL_BASED_HIGHLOW);
	
	newCode.add("85 ed"  // TEST EBP,EBP
	    " 74 ??",  // JZ errorReturn
	    (int)errorReturn - (int)(newCode.data.size() + 4)
    );
	
	// FILETIME:
    // Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	
	long long timeDiff = (
            (1970LL - 1601LL) * 365LL
            + 24LL * 3LL  // 3 centuries worth of leap years
            + (70 - 1) / 4  // leap years between 1900 and 1970, not inclusive
        ) * 24LL  // hours
        * 60LL  // minutes
        * 60LL  // seconds
        * 1000LL  // milliseconds
        * 1000LL  // microseconds
        * 10LL;  // 100 nanosecond intervals
	
	newCode.add("81 6C 24 ??", FILETIMEVAR); // SUB dword ptr[ESP+FILETIMEVAR],...
	newCode.add("?? ?? ?? ??", (DWORD)timeDiff); // first 4 bytes of timeDiff
	newCode.add("81 5C 24 ??", FILETIMEVAR + 4); // SBB dword ptr[ESP+FILETIMEVAR + 4],...
	newCode.add("?? ?? ?? ??", (DWORD)(timeDiff >> 32)); // last 4 bytes of timeDiff
	newCode.add("b9 ?? ?? ?? ??", 10000000);  // MOV ECX,10000000
	newCode.add("8b 44 24 ??", FILETIMEVAR + 4);  // MOV EAX,dword ptr[ESP+FILETIMEVAR + 4]
	newCode.add("31 d2"  // XOR EDX,EDX
	    " F7 F1"  // DIV ECX
	    " 89 c5");  // MOV EBP,EAX
	newCode.add("8b 44 24 ??", FILETIMEVAR);  // MOV EAX,dword ptr[ESP+FILETIMEVAR]
    newCode.add("F7 F1"  // DIV ECX
        " 89 44 24 ??", RESULT);  // MOV dword ptr[ESP+RESULT],EAX
    newCode.add("89 6C 24 ??", RESULT + 4);  // MOV dword ptr[ESP+RESULT + 4],EBP
	
	newCode.add("DF 6C 24 ??", RESULT);  // FILD qword ptr[ESP+RESULT]
	newCode.add("dd 5c 24 ??", RESULT);  // FSTP qword ptr[ESP+RESULT]
	
	jumpDistance = (int)returnLabel - (int)(newCode.data.size() + 2);
	if (jumpDistance >= -0x80) {
	    newCode.add("eb ??", jumpDistance);
	} else {
	    jumpDistance = (int)returnLabel - (int)(newCode.data.size() + 5);
	    newCode.add("e9 ?? ?? ?? ??", jumpDistance);
	}
	
	#ifdef _DEBUG
	if (newCode.data.size() > FFileManagerWindows_GetFileTimestamp_Sig.sig.size() - 1) {
	    MessageBoxW(mainWindow, L"The new code is larger than the old code.", L"Error", MB_OK);
	    return;
	}
	#endif
	
	fseek(file, FFileManagerWindows_GetFileTimestamp, SEEK_SET);
	fwrite(newCode.data.data(), 1, newCode.data.size(), file);
	
    CrossPlatformCout << "Patched the daylight saving bug in GuiltyGearXrd.exe.\n";
	
    fclose(file);
	
	CrossPlatformString bin_win32_Folder = getParentDir(szFile);
	CrossPlatformString bin_Folder = getParentDir(bin_win32_Folder);
	CrossPlatformString root_Folder = getParentDir(bin_Folder);
	CrossPlatformString engine_config_Folder = root_Folder
	    + PATH_SEPARATOR + CrossPlatformText("Engine")
	    + PATH_SEPARATOR + CrossPlatformText("Config");
	CrossPlatformString redgame_Folder = root_Folder
	    + PATH_SEPARATOR + CrossPlatformText("REDGame");
	CrossPlatformString redgame_config_Folder = root_Folder
	    + PATH_SEPARATOR + CrossPlatformText("REDGame")
	    + PATH_SEPARATOR + CrossPlatformText("Config");
	
	struct ThreeNames {
	    const CrossPlatformChar* red;
	    const CrossPlatformChar* default_;
	    const CrossPlatformChar* base;
	    ThreeNames(const CrossPlatformChar* red, const CrossPlatformChar* default_, const CrossPlatformChar* base)
	        : red(red), default_(default_), base(base) { }
	};
	
	static const ThreeNames iniNames[] = {
	    { CrossPlatformText("REDDebug.ini"), CrossPlatformText("DefaultDebug.ini"), CrossPlatformText("BaseDebug.ini") },
	    { CrossPlatformText("REDEngine.ini"), CrossPlatformText("DefaultEngine.ini"), CrossPlatformText("BaseEngine.ini") },
	    { CrossPlatformText("REDGame.ini"), CrossPlatformText("DefaultGame.ini"), CrossPlatformText("BaseGame.ini") },
	    { CrossPlatformText("REDInput.ini"), CrossPlatformText("DefaultInput.ini"), CrossPlatformText("BaseInput.ini") },
	    { CrossPlatformText("REDLightmass.ini"), CrossPlatformText("DefaultLightmass.ini"), CrossPlatformText("BaseLightmass.ini") },
	    { CrossPlatformText("REDSystemSettings.ini"), CrossPlatformText("DefaultSystemSettings.ini"), CrossPlatformText("BaseSystemSettings.ini") },
	    { CrossPlatformText("REDTMS.ini"), CrossPlatformText("DefaultTMS.ini"), CrossPlatformText("BaseTMS.ini") },
	    { CrossPlatformText("REDUI.ini"), CrossPlatformText("DefaultUI.ini"), CrossPlatformText("BaseUI.ini") }
	};
	
	for (const ThreeNames& threeName : iniNames) {
	    CrossPlatformString redPath = redgame_config_Folder + PATH_SEPARATOR + threeName.red;
	    CrossPlatformString defaultPath = redgame_config_Folder + PATH_SEPARATOR + threeName.default_;
	    if (!fileExists(redPath) || !fileExists(defaultPath)) continue;
	    
	    
	    FILE* defaultFile = NULL;
	    if (!crossPlatformOpenFile(&defaultFile, defaultPath)) continue;
	    
	    struct FileCloser {
	        ~FileCloser() {
	            if (file) fclose(file);
	        }
	        FILE* file = NULL;
	    } fileCloser { defaultFile };
	    
	    std::vector<char> defaultData;
	    if (!readWholeFile(defaultFile, defaultData)) continue;
        
	    SectionTracker sectionTracker;
	    sectionTracker.redgame_Folder = redgame_Folder;
	    
	    sectionTracker.runLoop(defaultData, &SectionTracker::onLineEnd_BasedOn);
	    sectionTracker.reset();
	    
	    if (sectionTracker.basedOnDetected) {
	        sectionTracker.newTimestamps.push_back(sectionTracker.basedOnTimestamp);
	    }
	    
	    fclose(defaultFile);
	    fileCloser.file = NULL;
	    
        double defaultTimestamp;
        if (SectionTracker::getTimestamp(defaultPath, &defaultTimestamp)) {
            sectionTracker.newTimestamps.push_back(defaultTimestamp);
        }
	    
	    FILE* redFile = NULL;
	    if (crossPlatformOpenFile(&redFile, redPath)) {
	        fileCloser.file = redFile;
	        
	        std::vector<char> redData;
	        if (readWholeFile(redFile, redData)) {
	            
	            sectionTracker.runLoop(redData, &SectionTracker::onLineEnd_IniVersion);
	            
	            if (sectionTracker.desiredEdits.size() == sectionTracker.newTimestamps.size() && !sectionTracker.desiredEdits.empty()) {
	                sectionTracker.applyEdits(redData);
	                overwriteWholeFile(redFile, redData);
	                CrossPlatformCout << "Updated IniVersion timestamps in " << getFileName(redPath).c_str() << '\n';
	                fclose(redFile);
	                fileCloser.file = NULL;
	            }
	            
	        }
            
	    }
	    
	    
	}
	
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
	trimLeft(szFile);
	trimRight(szFile);
	if (!szFile.empty() && (szFile.front() == '\'' || szFile.front() == '"')) {
		szFile.erase(szFile.begin());
	}
	if (!szFile.empty() && (szFile.back() == '\'' || szFile.back() == '"')) {
		szFile.erase(szFile.begin() + (szFile.size() - 1));
	}
	trimLeft(szFile);
	trimRight(szFile);
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
		CrossPlatformCout << "'Yes' selected.\n";
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
	
    if (!crossPlatformFileCopy(backupFilePath, szFile,
	    CrossPlatformText("Backup copy created successfully.\n"),
	    CrossPlatformText("Failed to create a backup copy. Do you want to continue anyway?"
        	" You won't be able to revert the file to the original. Press Enter to agree...\n"))) return;
    
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
	fileBase = (BYTE*)wholeFile.data();
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
	pNtHeader = (nthdr)((PBYTE)fileBase + pDosHeader->e_lfanew);
    
	char* wholeFileEnd = &wholeFile.front() + wholeFile.size();
	char* textBegin = nullptr;
	char* textEnd = nullptr;
	char* rdataBegin = nullptr;
	char* rdataEnd = nullptr;
	char* dataBegin = nullptr;
	char* dataEnd = nullptr;
	
	if (pNtHeader->FileHeader.NumberOfSections == 0) {
	    CrossPlatformCout << "Failed to read sections.\n";
	    return;
	}
	
	CrossPlatformCout << "Read sections: [\n";
	CrossPlatformCout << std::hex;
	bool isFirst = true;
	{
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader) + pNtHeader->FileHeader.NumberOfSections;
        for (int sectionIndex = (int)pNtHeader->FileHeader.NumberOfSections - 1; sectionIndex >= 0; --sectionIndex) {
            --section;
		    if (!isFirst) {
			    CrossPlatformCout << ",\n";
		    }
		    isFirst = false;
		    CrossPlatformCout << "{\n\tname: \"";
		    
		    std::vector<char> sectionName(9, '\0');
		    memcpy(sectionName.data(), section->Name, 8);
		    sectionName.resize(strlen(sectionName.data()) + 1);
		    sectionName.back() = '\0';
		    
		    CrossPlatformCout << sectionName.data() << "\""
			    << ",\n\tvirtualAddress: 0x" << section->VirtualAddress + pNtHeader->OptionalHeader.ImageBase
			    << ",\n\trawSize: 0x" << section->SizeOfRawData
			    << ",\n\trawAddress: 0x" << section->PointerToRawData
			    << "\n}";
		    
		    if (strcmp(sectionName.data(), ".text") == 0) {
			    textBegin = &wholeFile.front() + section->PointerToRawData;
			    textEnd = textBegin + section->SizeOfRawData;
		    } else if (strcmp(sectionName.data(), ".rdata") == 0) {
			    rdataBegin = &wholeFile.front() + section->PointerToRawData;
			    rdataEnd = rdataBegin + section->SizeOfRawData;
		    } else if (strcmp(sectionName.data(), ".data") == 0) {
			    dataBegin = &wholeFile.front() + section->PointerToRawData;
			    dataEnd = dataBegin + section->SizeOfRawData;
		    }
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
			rdataBegin, rdataEnd,
			dataBegin, dataEnd,
			&execIsAsyncLoadingVa, &execIsAsyncLoadingPos)) return;
	
	const char* execIsAsyncLoadingPtr = (char*)fileBase + execIsAsyncLoadingPos;
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
		
		DWORD anotherGNativesExDebugInfoMentionVa = rawToVa(
			anotherGNativesExDebugInfoPos + ((uintptr_t)(textBegin - (char*)fileBase) & 0xFFFFFFFF));
		
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
	
	relocTable.findRelocTable();
	
	
	// Now find the jump that goes after the bBlocking check in UREDCharaAssetLoader::LoadAssets
	
	DWORD execLoadAssetsVa, execLoadAssetsPos;
	if (!findExec("UREDCharaAssetLoaderexecLoadAssets",
			rdataBegin, rdataEnd,
			dataBegin, dataEnd,
			&execLoadAssetsVa, &execLoadAssetsPos)) return;
	CrossPlatformCout << "Found execLoadAssets at va:0x" << std::hex << execLoadAssetsVa << std::dec << ".\n";
	
	const char* execLoadAssetsBegin = (char*)fileBase + vaToRaw(execLoadAssetsVa);
	int loadAssetsCallPlacePos = sigscanForward(execLoadAssetsBegin, textEnd, 0x130, "\x8b\xcb\xe8", "xxx");
	if (loadAssetsCallPlacePos == -1) {
		CrossPlatformCout << "Couldn't find LoadAssets calling place.\n";
		return;
	}
	loadAssetsCallPlacePos += 2 + (execLoadAssetsBegin - (char*)fileBase) & 0xFFFFFFFF;
	CrossPlatformCout << "Found LoadAssets calling place: file:0x" << std::hex << loadAssetsCallPlacePos << std::dec << ".\n";
	
	DWORD loadAssetsVa = followRelativeCall(rawToVa(loadAssetsCallPlacePos), (char*)fileBase + loadAssetsCallPlacePos);
	
	const char* loadAssetsBegin = (char*)fileBase + vaToRaw(loadAssetsVa);
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
	jmpPos += (loadAssetsBegin - (char*)fileBase) & 0xFFFFFFFF;
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
		FNameInitVa = rawToVa(((uintptr_t)(textBegin - (char*)fileBase) & 0xFFFFFFFF) + FNameInitStartPos);
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
		FNameCompareVa = rawToVa(((uintptr_t)(textBegin - (char*)fileBase) & 0xFFFFFFFF) + FNameCompareStartPos);
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
		int callOffset = calculateRelativeCall(rawToVa(execIsAsyncLoadingPos + FNameInitCallPos), FNameInitVa);
		memcpy(writeBuf + FNameInitCallPos + 1, &callOffset, 4);
		
		
		int FNameCompareCallPos = sigscan(writeBuf, writeBufEnd, "\xE8\x00\x00\x00\x00", "xxxxx");
		callOffset = calculateRelativeCall(rawToVa(execIsAsyncLoadingPos + FNameCompareCallPos), FNameCompareVa);
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
	
	int menuTimewasteCounterUsage = sigscan(textBegin, textEnd,
	    "\x75\x20\x6a\x64\xe8\x00\x00\x00\x00\x83\xc4\x04\x85\xc0\x74\x12\x8b\x0d\x00\x00\x00\x00\x51\x8b\xce\xe8\x00\x00\x00\x00\x85\xc0\x74\x38",
	    "xxxxx????xxxxxxxxx????xxxx????xxxx");
	if (menuTimewasteCounterUsage == -1) {
	    CrossPlatformCout << "Couldn't find the usage of the variable that holds the amount of time needed to waste for you on each initial game loading message.\n";
	} else {
	    DWORD menuTimewasteCounterVa = *(DWORD*)(textBegin + menuTimewasteCounterUsage + 18);
		CrossPlatformCout << "Found the variable that holds the amount of time needed to waste for you on each initial game loading message"
		    " at va:0x" << std::hex << menuTimewasteCounterVa << std::dec << "\n";
		int menuTimewasteCounterRaw = vaToRaw(menuTimewasteCounterVa);
		int currentVal = *(int*)((char*)fileBase + menuTimewasteCounterRaw);
		if (currentVal == 0x5a) {
		    fseek(file, menuTimewasteCounterRaw, SEEK_SET);
		    int newVal = 0;
		    fwrite(&newVal, 4, 1, file);
		    CrossPlatformCout << "Overwrote the amount of time to waste on each loading message with 0.\n";
		} else {
		    CrossPlatformCout << "The amount of time to waste on each loading message is already set by someone to "
		        << currentVal << ", leaving it alone...\n";
		}
	}
	
	int dlcTimewasteUsage = sigscan(textBegin, textEnd,
	    "\x6a\x00\x6a\x00\x68\xf7\x00\x00\x00\x6a\x03\x68\x00\x00\x00\x00\x6a\x00\x6a\x61\xe8\x00\x00\x00\x00\x83\xc4\x1c\xc7\x05\x00\x00\x00\x00\x3c\x00\x00\x00",
	    "xxxxxxxxxxxx????xxxxx????xxxxx????xxxx");
	if (dlcTimewasteUsage == -1) {
	    CrossPlatformCout << "Couldn't find the usage of a variable that just wastes your time on the 'Verifying downloadable content.' message.\n";
	} else {
	    DWORD dlcTimewasteVa = *(DWORD*)(textBegin + dlcTimewasteUsage + 30);
	    CrossPlatformCout << "Found the variable that just wastes your time on the 'Verifying downloadable content.' message at va:0x"
	        << std::hex << dlcTimewasteVa << std::dec << '\n';
	    char* searchStart = textBegin;
	    char searchNeedle[] = "\xc7\x05\x10\x05\xe4\x01\x3c\x00\x00\x00";
	    memcpy(searchNeedle + 2, &dlcTimewasteVa, 4);
	    bool foundAtLeastOne = false;
	    const int zerosToWrite = 0;
	    while (textEnd - searchStart >= 10) {
	        int nextFind = sigscan(searchStart, textEnd, searchNeedle, "xxxxxxxxxx");
	        if (nextFind == -1) {
	            break;
	        }
	        int foundFileOffset = nextFind + ((uintptr_t)(searchStart - (char*)fileBase) & 0xFFFFFFFF);
	        fseek(file, foundFileOffset + 6, SEEK_SET);
	        fwrite(&zerosToWrite, 4, 1, file);
	        CrossPlatformCout << "Overwrote a usage of the variable that just wastes your time on the 'Verifying downloadable content.' message at va:0x"
	            << std::hex << rawToVa(foundFileOffset) << std::dec << '\n';
	        foundAtLeastOne = true;
	        searchStart += nextFind + 10;
	    }
	    if (!foundAtLeastOne) {
	        CrossPlatformCout << "Couldn't find any uses of the variable that just wastes your time on the 'Verifying downloadable content.' message.\n";
	    }
	}
	
	CrossPlatformCout << "Patch successful!\n";
	
	CrossPlatformCout << "Remember, the backup copy has been created at: " << backupFilePath.c_str() << "\n";
	
	bool allgood = true;
	bool iniTouched = false;
	bool movieTouched = false;
	
	int userResponse;
	#ifdef FOR_LINUX
	#define IDCANCEL 0
	#define ENTER_TO_SKIP 1
	#define NOT_SEE_AT_ALL 2
	#define IDYES 3
	#define IDNO 4
	#endif
	
	const CrossPlatformChar* questionStr =
	    CrossPlatformText("Do you want to be able to skip the intro movie with ArcSys, Team RED, Unreal Engine and Autodesk logos?")
	    #ifndef FOR_LINUX
	    L" Respond 'No' to skip this."
	    #else
	    " Respond 'n' to skip this."
	    #endif
	    ;
	
	#ifndef FOR_LINUX
	userResponse = MessageBoxW(mainWindow, questionStr, L"Question", MB_YESNOCANCEL);
	#else
    std::cout << questionStr << "\n";
    while (true) {
        std::cout << "Please, enter a 'y' (without quotation marks) to answer 'Yes', 'n' to answer 'No' (nothing will be done), 'c' to cancel.\n";
        std::string line;
        GetLine(line);
        if (stricmp(line.c_str(), "y") == 0) {
            userResponse = IDYES;
            break;
        } else if (stricmp(line.c_str(), "n") == 0) {
            userResponse = IDNO;
            break;
        } else if (stricmp(line.c_str(), "c") == 0) {
            userResponse = IDCANCEL;
            break;
        } else {
            std::cout << "I don't understand what you typed.\n";
        }
    }
	#endif
	
	if (userResponse == IDCANCEL) {
	    CrossPlatformCout << "It's a bit too late to cancel, most of the patching is already done. This response is considered to be a 'No',"
	    " so I won't touch the INIs or the daylight saving bug in the EXE, or rename Splash_Steam.wmv.\n";
	    userResponse = -1;
	} else if (userResponse == IDYES) {
	    #ifndef FOR_LINUX
	    PostMessageW(mainWindow, WM_ASK_CLARIFY, (WPARAM)&userResponse, NULL);
	    extern HANDLE eventToInjectorThread;
	    WaitForSingleObject(eventToInjectorThread, INFINITE);
	    #else
        std::cout << "Do you want to not see the intro movie at all, or do you just want to be able to press Enter to skip it?\n";
        while (true) {
            std::cout <<
                "Type '1' (without quotation marks) - not see at all;\n"
                "Type '2' - be able to press Enter to skip;\n"
                "Type 'c' - cancel.\n";
            
            std::string line;
            GetLine(line);
            if (strcmp(line.c_str(), "1") == 0) {
                userResponse = NOT_SEE_AT_ALL;
                break;
            } else if (strcmp(line.c_str(), "2") == 0) {
                userResponse = ENTER_TO_SKIP;
                break;
            } else if (stricmp(line.c_str(), "c") == 0) {
                userResponse = IDCANCEL;
                break;
            } else {
                std::cout << "I don't understand what you typed.\n";
            }
        }
	    #endif
	}
	
    if (userResponse == IDCANCEL) {
        // welp
        CrossPlatformCout << "I won't touch the INIs or the daylight saving bug in the EXE then, or rename Splash_Steam.wmv.\n";
    } else if (userResponse == ENTER_TO_SKIP) {
        
        int subresponse = -1;
        
        questionStr = CrossPlatformText("Do you want to patch the GuiltyGearXrd.exe to remove"
            " a bug from it that causes RED* INI files to get overwritten twice a year"
            " due to daylight saving in countries that use daylight saving?");
        
        #ifndef FOR_LINUX
        subresponse = MessageBoxW(mainWindow, questionStr, L"More patching?", MB_YESNOCANCEL);
        #else
        std::cout << questionStr << "\n";
        while (true) {
            std::cout << "Please, enter a 'y' (without quotation marks) to answer 'Yes', 'n' to answer 'No', 'c' to cancel.\n";
            std::string line;
            GetLine(line);
            if (stricmp(line.c_str(), "y") == 0) {
                subresponse = IDYES;
                break;
            } else if (stricmp(line.c_str(), "n") == 0) {
                subresponse = IDNO;
                break;
            } else if (stricmp(line.c_str(), "c") == 0) {
                subresponse = IDCANCEL;
                break;
            } else {
                std::cout << "I don't understand what you typed.\n";
            }
        }
        #endif
        
        if (subresponse == IDCANCEL) {
            CrossPlatformCout << "Well, we were almost done anyway...\n";
        } else {
            if (subresponse == IDYES) {
                if (findInfoForPatchingDaylightSaving(file, textBegin, textEnd, rdataBegin, rdataEnd)) {
                    patchDaylightSaving(file, szFile, textBegin, textEnd, rdataBegin, rdataEnd);
                    fileCloser.file = NULL;  // the above function closes the file
                    file = NULL;
                    iniTouched = true;
                } else {
                    allgood = false;
                }
            }
            
            CrossPlatformString iniPath = getParentDir(getParentDir(getParentDir(szFile)))
                + PATH_SEPARATOR + CrossPlatformText("REDGame")
                + PATH_SEPARATOR + CrossPlatformText("Config")
                + PATH_SEPARATOR + CrossPlatformText("REDEngine.ini");
            
            FILE* iniFile = NULL;
            std::vector<char> iniData;
            if (fileExists(iniPath) && crossPlatformOpenFile(&iniFile, iniPath) && readWholeFile(iniFile, iniData)) {
                
                struct FileCloser2 {
                    ~FileCloser2() {
                        if (file) fclose(file);
                    }
                    FILE* file = NULL;
                } fileCloser2;
                
                fileCloser2.file = iniFile;
                
                SectionTracker sectionTracker;
                sectionTracker.runLoop(iniData, &SectionTracker::onLineEnd_ignoreIntro);
                if (sectionTracker.alreadyIgnoresIntro) {
                    CrossPlatformCout << "The REDGame/Config/REDEngine.ini already has the 'SkippableMovies=Splash_Steam' line. Moving on.\n";
                } else {
                    int insertPos = -1;
                    if (sectionTracker.lastSkippableMoviesEnd != -1) insertPos = sectionTracker.lastSkippableMoviesEnd;
                    else if (sectionTracker.FullScreenMovieSectionLastNonEmptyLineEnd != -1) insertPos = sectionTracker.FullScreenMovieSectionLastNonEmptyLineEnd;
                    else if (sectionTracker.FullScreenMovieSectionLineEnd != -1) insertPos = sectionTracker.FullScreenMovieSectionLineEnd;
                    
                    if (insertPos == -1) {
                        CrossPlatformCout << "Failed to insert 'SkippableMovies=Splash_Steam' line into REDGame/Config/REDEngine.ini in the [FullScreenMovie] section.\n";
                        allgood = false;
                    } else {
                        iniTouched = true;
                        
                        sectionTracker.desiredEdits.emplace_back();
                        DesiredEdit& edit = sectionTracker.desiredEdits.back();
                        edit.charOffsetStart = insertPos;
                        edit.charOffsetEnd = insertPos;
                        edit.newText = "\r\nSkippableMovies=Splash_Steam";
                        
                        sectionTracker.applyEdits(iniData);
                        overwriteWholeFile(iniFile, iniData);
                        CrossPlatformCout << "Added 'SkippableMovies=Splash_Steam' line into REDGame/Config/REDEngine.ini in the [FullScreenMovie] section.\n";
                    }
                }
            } else {
                allgood = false;
            }
        }
        
    } else if (userResponse == NOT_SEE_AT_ALL) {
        
        CrossPlatformString moviePathFrom = getParentDir(getParentDir(getParentDir(szFile)))
            + PATH_SEPARATOR + CrossPlatformText("REDGame")
            + PATH_SEPARATOR + CrossPlatformText("Movies")
            + PATH_SEPARATOR + CrossPlatformText("Splash_Steam.wmv");
        
        CrossPlatformString moviePathTo = getParentDir(getParentDir(getParentDir(szFile)))
            + PATH_SEPARATOR + CrossPlatformText("REDGame")
            + PATH_SEPARATOR + CrossPlatformText("Movies")
            + PATH_SEPARATOR + CrossPlatformText("Splash_Steam_.wmv");
        
        if (fileExists(moviePathFrom)) {
            
            CrossPlatformString errorMsg = CrossPlatformText("Failed to rename file '");
            errorMsg += moviePathFrom + CrossPlatformText("' to '") + moviePathTo + CrossPlatformText("': ");
                    
            bool success = false;
            #ifndef FOR_LINUX
            if (!MoveFileW(moviePathFrom.c_str(), moviePathTo.c_str())) {
                LPWSTR message = NULL;
                int errorCode = GetLastError();
                FormatMessageW(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    errorCode,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPWSTR)(&message),
                    0, NULL);
                errorMsg += message;
                MessageBoxW(mainWindow, errorMsg.c_str(), L"Error", MB_OK);
            } else {
                success = true;
            }
            #else
            int renameResult = rename(moviePathFrom.c_str(), moviePathTo.c_str()); 
            if (renameResult == -1) {
                perror(errorMsg.c_str());
                std::cout << '\n';
            } else {
                success = true;
            }
            #endif
            if (success) {
                movieTouched = true;
                CrossPlatformCout << "Successfully renamed '" << moviePathFrom.c_str()
                    << "' to '" << moviePathTo.c_str() << "'.\n";
            } else {
                allgood = false;
            }
        } else {
            CrossPlatformCout << "Failed to find file '" << moviePathFrom.c_str() << "'. I guess, if it's absent, intro won't play anyway,"
                " so there's no need to do anything more.\n";
        }
    }
	
	if (allgood) {
	    CrossPlatformCout << "All work completed successfully!\n";
	} else {
	    CrossPlatformCout << "All work completed, with some errors probably, but mostly everything's fine (see messages above).\n";
	}
	
	CrossPlatformCout << "Remember, the backup copy has been created at: " << backupFilePath.c_str();
	
	if (iniTouched || movieTouched) {
	    if (iniTouched && movieTouched) {
	        CrossPlatformCout << " (REDEngine.ini file and Splash_Steam.wmv do not get backed up.)";
	    } else if (iniTouched) {
	        CrossPlatformCout << " (REDEngine.ini file does not get backed up.)";
	    } else {
	        CrossPlatformCout << " (Splash_Steam.wmv file does not get backed up.)";
	    }
	}
	
	CrossPlatformCout << '\n';
	
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
