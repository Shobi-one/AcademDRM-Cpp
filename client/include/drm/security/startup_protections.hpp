#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "drm/string_obfuscation.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <intrin.h>
#include <openssl/sha.h>

namespace drm::security {

class AntiDebugDetector {
public:
    bool detectDebugger() const {
        if (IsDebuggerPresent()) {
            return true;
        }

        BOOL remote_debugger_present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger_present) && remote_debugger_present) {
            return true;
        }

        if (checkPebBeingDebugged()) {
            return true;
        }

        return checkHardwareBreakpoints();
    }

private:
    struct MinimalPeb {
        unsigned char Reserved1[2];
        unsigned char BeingDebugged;
    };

    static bool checkPebBeingDebugged() {
#if defined(_M_X64)
        const auto* peb = reinterpret_cast<const MinimalPeb*>(__readgsqword(0x60));
#elif defined(_M_IX86)
        const auto* peb = reinterpret_cast<const MinimalPeb*>(__readfsdword(0x30));
#else
        const auto* peb = static_cast<const MinimalPeb*>(nullptr);
#endif
        return peb != nullptr && peb->BeingDebugged != 0;
    }

    static bool checkHardwareBreakpoints() {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(GetCurrentThread(), &context)) {
            return false;
        }

        return context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0;
    }
};

class TextSectionIntegrityChecker {
public:
    bool verifyCurrentModuleTextIntegrity() const {
        wchar_t module_path[MAX_PATH]{};
        if (GetModuleFileNameW(nullptr, module_path, MAX_PATH) == 0) {
            return false;
        }

        const auto* loaded_base = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
        const IMAGE_SECTION_HEADER* loaded_text = findTextSection(loaded_base);
        if (loaded_text == nullptr) {
            return false;
        }

        HANDLE file = CreateFileW(
            module_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (file == INVALID_HANDLE_VALUE) {
            return false;
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
        if (mapping == nullptr) {
            CloseHandle(file);
            return false;
        }

        const auto* mapped_base = static_cast<const unsigned char*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (mapped_base == nullptr) {
            CloseHandle(mapping);
            CloseHandle(file);
            return false;
        }

        const IMAGE_SECTION_HEADER* mapped_text = findTextSection(mapped_base);
        if (mapped_text == nullptr) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping);
            CloseHandle(file);
            return false;
        }

        std::vector<unsigned char> loaded_text_bytes;
        std::vector<unsigned char> mapped_text_bytes;
        if (!copyTextSection(loaded_base, loaded_text, loaded_text_bytes) ||
            !copyTextSection(mapped_base, mapped_text, mapped_text_bytes)) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping);
            CloseHandle(file);
            return false;
        }

        const size_t comparable_size = std::min(loaded_text_bytes.size(), mapped_text_bytes.size());
        if (comparable_size == 0) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping);
            CloseHandle(file);
            return false;
        }

        loaded_text_bytes.resize(comparable_size);
        mapped_text_bytes.resize(comparable_size);

        const std::vector<RelocationPatch> patches = collectTextRelocationPatches(
            loaded_base,
            loaded_text->VirtualAddress,
            comparable_size
        );
        applyRelocationNeutralization(loaded_text_bytes, patches);
        applyRelocationNeutralization(mapped_text_bytes, patches);

        std::array<unsigned char, SHA256_DIGEST_LENGTH> loaded_hash{};
        std::array<unsigned char, SHA256_DIGEST_LENGTH> mapped_hash{};
        const bool loaded_ok = sha256Buffer(loaded_text_bytes.data(), loaded_text_bytes.size(), loaded_hash);
        const bool mapped_ok = sha256Buffer(mapped_text_bytes.data(), mapped_text_bytes.size(), mapped_hash);

        UnmapViewOfFile(mapped_base);
        CloseHandle(mapping);
        CloseHandle(file);

        if (!loaded_ok || !mapped_ok) {
            return false;
        }

        return loaded_hash == mapped_hash;
    }

private:
    struct RelocationPatch {
        size_t offset;
        size_t width;
    };

    static const IMAGE_NT_HEADERS* getNtHeaders(const unsigned char* image_base) {
        if (image_base == nullptr) {
            return nullptr;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        return nt;
    }

    static const IMAGE_SECTION_HEADER* findTextSection(const unsigned char* image_base) {
        const IMAGE_NT_HEADERS* nt = getNtHeaders(image_base);
        if (nt == nullptr) {
            return nullptr;
        }

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
        for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER* section = &sections[i];
            if (std::memcmp(section->Name, ".text", 5) == 0) {
                return section;
            }
        }

        return nullptr;
    }

    static bool copyTextSection(
        const unsigned char* image_base,
        const IMAGE_SECTION_HEADER* text,
        std::vector<unsigned char>& out_text
    ) {
        const size_t section_size = text->Misc.VirtualSize == 0
            ? static_cast<size_t>(text->SizeOfRawData)
            : static_cast<size_t>(text->Misc.VirtualSize);
        if (section_size == 0) {
            return false;
        }

        const unsigned char* section_ptr = image_base + text->VirtualAddress;
        out_text.assign(section_ptr, section_ptr + section_size);
        return true;
    }

    static std::vector<RelocationPatch> collectTextRelocationPatches(
        const unsigned char* image_base,
        uint32_t text_rva,
        size_t text_size
    ) {
        std::vector<RelocationPatch> patches;

        const IMAGE_NT_HEADERS* nt = getNtHeaders(image_base);
        if (nt == nullptr) {
            return patches;
        }

        const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size < sizeof(IMAGE_BASE_RELOCATION)) {
            return patches;
        }

        const unsigned char* reloc_ptr = image_base + reloc_dir.VirtualAddress;
        const unsigned char* reloc_end = reloc_ptr + reloc_dir.Size;

        while (reloc_ptr + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end) {
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reloc_ptr);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                break;
            }

            const size_t entries_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            const auto* entries = reinterpret_cast<const uint16_t*>(reloc_ptr + sizeof(IMAGE_BASE_RELOCATION));

            for (size_t i = 0; i < entries_count; ++i) {
                const uint16_t entry = entries[i];
                const uint16_t type = entry >> 12;
                const uint16_t offset_in_page = entry & 0x0FFF;

                size_t patch_width = 0;
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    patch_width = 4;
                } else if (type == IMAGE_REL_BASED_DIR64) {
                    patch_width = 8;
                } else {
                    continue;
                }

                const uint32_t target_rva = block->VirtualAddress + offset_in_page;
                if (target_rva < text_rva) {
                    continue;
                }

                const size_t local_offset = static_cast<size_t>(target_rva - text_rva);
                if (local_offset + patch_width > text_size) {
                    continue;
                }

                patches.push_back({ local_offset, patch_width });
            }

            reloc_ptr += block->SizeOfBlock;
        }

        return patches;
    }

    static void applyRelocationNeutralization(std::vector<unsigned char>& bytes, const std::vector<RelocationPatch>& patches) {
        for (const RelocationPatch& patch : patches) {
            for (size_t i = 0; i < patch.width; ++i) {
                bytes[patch.offset + i] = 0;
            }
        }
    }

    static bool sha256Buffer(
        const unsigned char* data,
        size_t size,
        std::array<unsigned char, SHA256_DIGEST_LENGTH>& digest
    ) {
        if (data == nullptr || size == 0) {
            return false;
        }

        return SHA256(data, size, digest.data()) != nullptr;
    }
};

class StartupProtections {
public:
    bool run(std::string& failure_reason) const {
        if (anti_debug_detector_.detectDebugger()) {
            failure_reason = drm::obf::decode(
                { 0x19, 0x0F, 0x15, 0xF1, 0xF6, 0xF9, 0xCE, 0xCA, 0xE5, 0xB6, 0xBA, 0x98, 0x9C, 0x65, 0x67, 0x45, 0x49, 0x14, 0x67, 0x11, 0x19, 0x07, 0x0F, 0xE1, 0xFB, 0xC5, 0x81 },
                0x5D
            );
            return false;
        }

        if (!text_integrity_checker_.verifyCurrentModuleTextIntegrity()) {
            failure_reason = drm::obf::decode(
                { 0x14, 0x04, 0x03, 0xE1, 0xF6, 0xEC, 0xC2, 0xCC, 0xBC, 0xF2, 0xBC, 0x84, 0x9C, 0x65, 0x78, 0x00, 0x4B, 0x5B, 0x2E, 0x38, 0x04, 0x0A, 0x5B, 0xEE, 0xFA, 0xD0, 0x8F, 0x92, 0xBD, 0xB3, 0x9B, 0x84, 0xDD, 0x79, 0x72, 0x47, 0x45, 0x57, 0x24, 0x36, 0x4B, 0x52, 0x3A, 0xF4, 0xF0, 0xD2, 0xDA, 0xAE, 0xAA, 0xF4 },
                0x5D
            );
            return false;
        }

        failure_reason.clear();
        return true;
    }

private:
    AntiDebugDetector anti_debug_detector_{};
    TextSectionIntegrityChecker text_integrity_checker_{};
};

} // namespace drm::security
