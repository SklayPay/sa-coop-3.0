#include "shared/game/version/GameVersion.h"

#include <windows.h>

#include <cstring>

#include "common/lib/log/Log.h"
#include "shared/game/version/Addresses.h"

namespace game::version {
namespace {

constexpr uintptr_t kGta10Base = 0x400000;
// The 1.0 US image ends with the HOODLUM section at 0x1577000. Addresses outside that range are
// heap objects, plugin code or Windows, which must not be translated.
constexpr uintptr_t kGta10End = 0x1577000;

bool Readable(uintptr_t address, size_t size) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
    auto end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return address + size <= end;
}

bool Read32(uintptr_t address, uint32_t& out) {
    if (!Readable(address, sizeof(out))) return false;
    std::memcpy(&out, reinterpret_cast<void*>(address), sizeof(out));
    return true;
}

uintptr_t ImageBase() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
}

uintptr_t At10(uintptr_t va10) {
    return ImageBase() + (va10 - kGta10Base);
}

bool Match(uintptr_t va10, uint32_t expected) {
    uint32_t value = 0;
    return Read32(At10(va10), value) && value == expected;
}

uint32_t ExeSize() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return 0;
    return fad.nFileSizeLow;
}

Info Detect() {
    Info info;
    info.exeSize = ExeSize();

    // These four signatures are shared with SilentPatch's public version detector. 0x94BF is
    // the 1.0/1.01/3.0 marker; 0x3539F633 is the NewSteam/RGL marker.
    if (Match(0x82457C, 0x94BF)) {
        info.id = Id::V1_0_US;
        info.name = "GTA SA 1.0 US";
    } else if (Match(0x8245BC, 0x94BF)) {
        info.id = Id::V1_0_EU;
        info.european = true;
        info.name = "GTA SA 1.0 EU";
    } else if (Match(0x8252FC, 0x94BF)) {
        info.id = Id::V1_01_US;
        info.name = "GTA SA 1.01 US";
    } else if (Match(0x82533C, 0x94BF)) {
        info.id = Id::V1_01_EU;
        info.european = true;
        info.name = "GTA SA 1.01 EU";
    } else if (Match(0x85EC4A, 0x94BF)) {
        info.id = Id::V3_0;
        info.name = "GTA SA 3.0 (Steam/RGL)";
    } else if (Match(0x858D21, 0x3539F633)) {
        info.id = Id::NewSteamR1;
        info.name = "GTA SA NewSteam r1";
    } else if (Match(0x858D51, 0x3539F633)) {
        info.id = Id::NewSteamR2;
        info.name = "GTA SA NewSteam r2";
    } else if (Match(0x858C61, 0x3539F633)) {
        info.id = Id::NewSteamR2LV;
        info.name = "GTA SA NewSteam r2 LV";
    } else if (Match(0x858501, 0x3539F633)) {
        info.id = Id::RGL;
        info.name = "GTA SA RGL 1.0.22.0";
    } else {
        info.id = Id::Unknown;
        info.name = "unknown gta_sa.exe";
    }
    return info;
}

}  // namespace

const Info& Get() {
    static const Info info = Detect();
    return info;
}

const char* Name(Id id) {
    switch (id) {
        case Id::V1_0_US: return "GTA SA 1.0 US";
        case Id::V1_0_EU: return "GTA SA 1.0 EU";
        case Id::V1_01_US: return "GTA SA 1.01 US";
        case Id::V1_01_EU: return "GTA SA 1.01 EU";
        case Id::V3_0: return "GTA SA 3.0 (Steam/RGL)";
        case Id::NewSteamR1: return "GTA SA NewSteam r1";
        case Id::NewSteamR2: return "GTA SA NewSteam r2";
        case Id::NewSteamR2LV: return "GTA SA NewSteam r2 LV";
        case Id::RGL: return "GTA SA RGL 1.0.22.0";
        case Id::Unknown: break;
    }
    return "unknown gta_sa.exe";
}

bool Is1_0US() { return Get().id == Id::V1_0_US; }

bool IsSteamFamily() {
    switch (Get().id) {
        case Id::V3_0:
        case Id::NewSteamR1:
        case Id::NewSteamR2:
        case Id::NewSteamR2LV:
        case Id::RGL:
            return true;
        default:
            return false;
    }
}

bool IsSupported() { return Is1_0US(); }

uintptr_t GameBase() { return ImageBase(); }

uint32_t GameImageSize() {
    HMODULE module = GetModuleHandleW(nullptr);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

bool IsGameAddress(uintptr_t address) {
    uintptr_t base = GameBase();
    uint32_t size = GameImageSize();
    return size && address >= base && address < base + size;
}

uintptr_t Resolve(uintptr_t address10) {
    // Addresses outside the 1.0 image are pointers into pools, plugin code or the system: they
    // already refer to the running process and must be left alone.
    if (address10 < kGta10Base || address10 >= kGta10End) return address10;

    if (Is1_0US()) return address10;

    if (!IsSteamFamily() && Get().id != Id::V1_0_EU && Get().id != Id::V1_01_US &&
        Get().id != Id::V1_01_EU) {
        return address10;
    }

    return ResolveAddress(address10);
}

}  // namespace game::version
