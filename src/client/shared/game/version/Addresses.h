#pragma once
// Version-specific address table. This is the only file that should need editing when adding
// support for another gta_sa.exe: the feature code keeps using the 1.0 US constants.
#include <cstddef>
#include <cstdint>

namespace game::version {

// A byte pattern for executables whose addresses are not published as constants.
// Syntax: hex bytes separated by spaces; "?" or "??" is a wildcard. Example:
//   "8B 0E 85 C9 74 ? 8B 01"
struct Pattern {
    const char* bytes = nullptr;
    int offset = 0;  // added to the match start; negative means "bytes before the match"
};

enum class ResolveKind : uint8_t {
    Direct,   // the match address (with Pattern::offset) is the value
    Pointer,  // read a 32-bit pointer at the match address
    Rel32,    // read a 32-bit relative displacement at the match address
};

struct Entry {
    const char* name;
    uintptr_t v10;     // address in gta_sa.exe 1.0 US
    uintptr_t v30;     // address in gta_sa.exe 3.0, 0 if unknown
    Pattern pattern;   // fallback for NewSteam/RGL; 3.0 uses only v30
    ResolveKind kind = ResolveKind::Direct;
};

// Looks up a 1.0 US address in the table. Returns 0 when the entry is missing or its
// signature could not be resolved in the running image.
uintptr_t ResolveAddress(uintptr_t v10);

size_t EntryCount();
size_t ResolvedCount();
const char* NameOf(uintptr_t v10);

}  // namespace game::version
