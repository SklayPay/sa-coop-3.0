#include "shared/lib/memory/Memory.h"

#include <MinHook.h>
#include <windows.h>

#include "common/lib/log/Log.h"
#include "shared/game/version/GameVersion.h"

namespace coop::mem {
namespace {

// Translate a 1.0 US address through the version table. Addresses outside the game image (pool
// objects, vtable slots, plugin code) are returned unchanged by Resolve. Returns 0 when the
// address belongs to the image but the table has no entry, so a caller can refuse to patch.
uintptr_t At(uintptr_t addr10) { return game::version::Resolve(addr10); }

// Writes to an address that is already in the running process (a translated address or a
// runtime pointer). No version lookup here: Resolve treats every address in the image range as a
// 1.0 constant, so translating twice would be wrong on 3.0.
void WriteRaw(uintptr_t at, const void* data, size_t size) {
    DWORD old;
    VirtualProtect((void*)at, size, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)at, data, size);
    VirtualProtect((void*)at, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)at, size);
}

uint8_t* NopBytes(size_t size) {
    static uint8_t buf[256];
    if (size > sizeof(buf)) size = sizeof(buf);
    memset(buf, 0x90, size);
    return buf;
}

}  // namespace

bool Init() {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        LOGE("MinHook init failed: %s", MH_StatusToString(s));
        return false;
    }
    return true;
}

void Shutdown() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

void Write(uintptr_t addr, const void* data, size_t size) {
    uintptr_t at = At(addr);
    if (!at) {
        LOGE("Write: no %08X in this game version", (unsigned)addr);
        return;
    }
    WriteRaw(at, data, size);
}

void Nop(uintptr_t addr, size_t size) {
    uintptr_t at = At(addr);
    if (!at) {
        LOGE("Nop: no %08X in this game version", (unsigned)addr);
        return;
    }
    if (size > 256) {
        LOGE("Nop: %u bytes at %08X is too long", (unsigned)size, (unsigned)at);
        return;
    }
    WriteRaw(at, NopBytes(size), size);
}

void Jump(uintptr_t addr, const void* target) {
    uintptr_t at = At(addr);
    if (!at) {
        LOGE("Jump: no %08X in this game version", (unsigned)addr);
        return;
    }
    uint8_t code[5];
    code[0] = 0xE9;
    int32_t rel = (int32_t)((uintptr_t)target - (at + 5));
    memcpy(code + 1, &rel, 4);
    WriteRaw(at, code, sizeof(code));
}

void Ret(uintptr_t addr, uint16_t popBytes) {
    if (popBytes == 0) {
        Put<uint8_t>(addr, 0xC3);
    } else {
        uint8_t code[3] = {0xC2, (uint8_t)(popBytes & 0xFF), (uint8_t)(popBytes >> 8)};
        Write(addr, code, sizeof(code));
    }
}

uintptr_t CallTarget(uintptr_t addr) {
    uintptr_t at = At(addr);
    if (!at) return 0;
    uint8_t op = *(uint8_t*)at;
    if (op != 0xE8 && op != 0xE9) return 0;
    return at + 5 + *(int32_t*)(at + 1);
}

bool RedirectCall(uintptr_t addr, const void* newTarget, void** previous) {
    uintptr_t at = At(addr);
    if (!at) {
        LOGE("RedirectCall: no %08X in this game version", (unsigned)addr);
        return false;
    }
    if (*(uint8_t*)at != 0xE8) {
        LOGE("RedirectCall: no call instruction at %08X (byte %02X)", (unsigned)at, *(uint8_t*)at);
        return false;
    }
    if (previous) *previous = (void*)CallTarget(addr);
    int32_t rel = (int32_t)((uintptr_t)newTarget - (at + 5));
    WriteRaw(at + 1, &rel, sizeof(rel));
    return true;
}

bool Hook(uintptr_t addr, void* detour, void** original, const char* name) {
    uintptr_t at = At(addr);
    if (!at) {
        LOGE("Hook %s: no %08X in this game version", name, (unsigned)addr);
        return false;
    }
    MH_STATUS s = MH_CreateHook((void*)at, detour, original);
    if (s != MH_OK) {
        LOGE("Hook %s @%08X: create failed: %s", name, (unsigned)at, MH_StatusToString(s));
        return false;
    }
    s = MH_EnableHook((void*)at);
    if (s != MH_OK) {
        LOGE("Hook %s @%08X: enable failed: %s", name, (unsigned)at, MH_StatusToString(s));
        return false;
    }
    LOGD("Hooked %s @%08X", name, (unsigned)at);
    return true;
}

void* SwapVTable(void** vtable, int index, void* fn) {
    void* old = vtable[index];
    WriteRaw((uintptr_t)&vtable[index], &fn, sizeof(fn));
    return old;
}

bool Check(uintptr_t addr, const void* expected, size_t size) {
    uintptr_t at = At(addr);
    if (!at) return false;
    return memcmp((void*)at, expected, size) == 0;
}

}  // namespace coop::mem
