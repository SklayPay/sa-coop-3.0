#pragma once
// Game executable versions and the translation of 1.0 US addresses to the running image.
//
// The mod was written against gta_sa.exe 1.0 US: every constant in the client is a virtual
// address of that image. A port to another executable keeps those constants as the source
// language and translates them here. The translation table lives in Addresses.cpp, apart from
// the code that uses it, so a new version can be added without touching the features.
#include <cstdint>

namespace game::version {

enum class Id : uint8_t {
    Unknown = 0,
    V1_0_US,
    V1_0_EU,
    V1_01_US,
    V1_01_EU,
    V3_0,
    NewSteamR1,
    NewSteamR2,
    NewSteamR2LV,
    RGL,
};

struct Info {
    Id id = Id::Unknown;
    bool european = false;
    const char* name = "unknown";
    uint32_t exeSize = 0;
};

// Detects the running gta_sa.exe. The signatures are the public ones used by SilentPatch
// (SilentPatch/SilentPatch/MemoryMgr.GTA.h); they are kept here rather than in the feature code.
const Info& Get();
const char* Name(Id id);

bool Is1_0US();
bool IsSteamFamily();  // 3.0 / NewSteam / RGL: all use the new executable layout
bool IsSupported();    // what the client may actually run on today

uintptr_t GameBase();
uint32_t GameImageSize();
bool IsGameAddress(uintptr_t address);

// Translates a 1.0 US virtual address into the running image. Addresses outside the game
// image (heap objects, plugin code, Windows) are returned unchanged. Returns 0 when the
// address belongs to the 1.0 image but this version has no signature for it yet.
uintptr_t Resolve(uintptr_t address10);

}  // namespace game::version
