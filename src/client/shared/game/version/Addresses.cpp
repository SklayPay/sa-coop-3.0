#include "shared/game/version/Addresses.h"

#include <windows.h>

#include <cstring>
#include <string_view>

#include "common/lib/log/Log.h"
#include "shared/game/version/GameVersion.h"

namespace game::version {
namespace {

// The table is deliberately small so far. Add one row per address used by the client; keep it
// sorted by v10. v30 is the address in gta_sa.exe 3.0. The byte pattern is only for NewSteam/RGL:
// the 3.0 executable is a different build, and a pattern that matches there can point at an
// unrelated function. Public values below come from SilentPatch's MemoryMgr.GTA.h / GeneralSA.cpp
// / PedSA.cpp / SilentPatchSA.cpp, which support the new binaries.
constexpr Entry kEntries[] = {
    // name                                     1.0 US      3.0         pattern                                      kind
    {"CStreaming::RequestModel",                 0x4087E0, 0,          {"57 8D 3C 9B", -0x8},                       ResolveKind::Direct},
    {"CStreaming::LoadAllRequestedModels",       0x40EA10, 0,          {"A1 ? ? ? ? 03 C0", -0x20},                 ResolveKind::Direct},
    {"CAnimManager::GetAnimationBlockIndex",     0x4D3990, 0x4DE2F0,   {"83 C4 04 85 C0 75 05", -0xC},              ResolveKind::Direct},
    {"CWorld::Remove",                           0x563280, 0x57D370,   {"8B 06 8B 50 0C 8B CE FF D2 8A 46 36 24 07 3C 01 76 0D", -7}, ResolveKind::Direct},
    {"CClothes::RebuildPlayer",                  0x5A82C0, 0,          {"8B 8E ? ? ? ? 83 C4 04 6A 05", -0x11},     ResolveKind::Direct},
    {"CPedIntelligence::GetTaskJetPack",         0x601110, 0x620E70,   {},                                          ResolveKind::Direct},
    {"CAnimManager::GetAnimHierarchyFromSkinClump", 0x734A40, 0x7671B0, {},                                        ResolveKind::Direct},
    {"CWeaponInfo::GetWeaponInfo",               0x743C60, 0x77D940,   {},                                          ResolveKind::Direct},
    {"RwFrameGetLTM",                            0x7F0990, 0x82A950,   {},                                          ResolveKind::Direct},
};

constexpr size_t kEntryCount = sizeof(kEntries) / sizeof(kEntries[0]);

const Entry* Find(uintptr_t v10) {
    for (const auto& e : kEntries) {
        if (e.v10 == v10) return &e;
    }
    return nullptr;
}

uintptr_t FromVA(uintptr_t va) {
    return va >= 0x400000 ? GameBase() + (va - 0x400000) : va;
}

bool IsReadable(uintptr_t address, size_t size) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
    auto end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return address + size <= end;
}

// Matches one pattern in the executable sections of the game image. Returns 0 unless there is
// exactly one match: a wrong or ambiguous signature is worse than a missing one.
uintptr_t Scan(ResolveKind& kind, const Pattern& pattern) {
    if (!pattern.bytes || !*pattern.bytes) return 0;

    uint8_t bytes[256];
    uint8_t mask[256];
    size_t len = 0;
    std::string_view text(pattern.bytes);
    for (size_t i = 0; i < text.size() && len < sizeof(bytes);) {
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        if (i >= text.size()) break;
        if (text[i] == '?') {
            bytes[len] = 0;
            mask[len] = 0;
            ++len;
            while (i < text.size() && text[i] == '?') ++i;
            continue;
        }
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = i < text.size() ? hex(text[i]) : -1;
        int lo = i + 1 < text.size() ? hex(text[i + 1]) : -1;
        if (hi < 0 || lo < 0) return 0;
        bytes[len] = static_cast<uint8_t>((hi << 4) | lo);
        mask[len] = 0xFF;
        ++len;
        i += 2;
    }
    if (len == 0) return 0;

    HMODULE module = GetModuleHandleW(nullptr);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    uintptr_t found = 0;
    int matches = 0;
    for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        auto* begin = reinterpret_cast<uint8_t*>(module) + section->VirtualAddress;
        size_t size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        if (size < len) continue;
        for (size_t i = 0; i + len <= size; ++i) {
            bool equal = true;
            for (size_t j = 0; j < len; ++j) {
                if (mask[j] && begin[i + j] != bytes[j]) {
                    equal = false;
                    break;
                }
            }
            if (!equal) continue;
            if (++matches > 1) return 0;  // ambiguous
            found = reinterpret_cast<uintptr_t>(begin + i);
        }
    }
    if (matches != 1) return 0;

    uintptr_t at = found + pattern.offset;
    if (!IsReadable(at, 4)) return 0;
    switch (kind) {
        case ResolveKind::Direct:
            return at;
        case ResolveKind::Pointer: {
            uint32_t value = 0;
            std::memcpy(&value, reinterpret_cast<void*>(at), sizeof(value));
            return FromVA(value);
        }
        case ResolveKind::Rel32: {
            int32_t rel = 0;
            std::memcpy(&rel, reinterpret_cast<void*>(at), sizeof(rel));
            return at + 4 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
        }
    }
    return 0;
}

}  // namespace

uintptr_t ResolveAddress(uintptr_t v10) {
    const Entry* e = Find(v10);
    if (!e) return 0;

    if (Is1_0US()) return v10;

    // 3.0 has no stable public patterns yet: use only a verified direct address. A pattern from
    // the NewSteam builds can match the wrong function in 3.0 (e.g. the LoadAllRequestedModels
    // pattern matches an unrelated prologue there).
    if (Get().id == Id::V3_0) {
        return e->v30 ? FromVA(e->v30) : 0;
    }

    // NewSteam/RGL are close enough to each other for the published patterns.
    ResolveKind kind = e->kind;
    return Scan(kind, e->pattern);
}

size_t EntryCount() { return kEntryCount; }

size_t ResolvedCount() {
    size_t n = 0;
    for (const auto& e : kEntries) {
        if (e.v30 || e.pattern.bytes) ++n;
    }
    return n;
}

const char* NameOf(uintptr_t v10) {
    const Entry* e = Find(v10);
    return e ? e->name : nullptr;
}

}  // namespace game::version
