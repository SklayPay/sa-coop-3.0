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
    {"src/client/features/story/missions/Missions.cpp:1123", 0x00405850, 0x004058C0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1124", 0x00405890, 0x00405900, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1125", 0x004058D0, 0x00405940, {}, ResolveKind::Direct},
    {"CStreaming::RequestModel", 0x004087E0, 0, {"57 8D 3C 9B", -0x8}, ResolveKind::Direct},
    {"CStreaming::LoadAllRequestedModels", 0x0040EA10, 0, {"A1 ? ? ? ? 03 C0", -0x20}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:337", 0x00424F80, 0x00426900, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:334", 0x004341C0, 0x00437150, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:144", 0x00437C20, 0x0043AE60, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:702", 0x00441390, 0x00444D70, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:707", 0x00441E10, 0x004459D0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:712", 0x00442020, 0x00445C10, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:72", 0x00442FCF, 0x00446CAA, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:72", 0x0044337A, 0x0044704A, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:363", 0x00444530, 0x004482D0, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:62", 0x00446F90, 0x0044AE00, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:98", 0x00448550, 0x0044C4E0, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:49", 0x004489F0, 0x0044C9A0, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:147", 0x00449760, 0x0044D7B0, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:327", 0x0044C1E1, 0x004505BD, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:908", 0x0044CE80, 0x00451210, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:178", 0x00454CF0, 0x00459A60, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:192", 0x004556C0, 0x0045A480, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3293", 0x00469FF2, 0x0046F760, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3267", 0x00485E00, 0x0048C3D0, {}, ResolveKind::Direct},
    {"src/client/features/mission-objects/Objects.cpp:83", 0x004B0A00, 0x004BA180, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:431", 0x004B27D0, 0x004BBF90, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:429", 0x004B9340, 0x004C27F0, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:362", 0x004C0BD0, 0x004CA960, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:1246", 0x004C89B0, 0x004D32D0, {}, ResolveKind::Direct},
    {"CAnimManager::GetAnimationBlockIndex", 0x004D3990, 0x004DE2F0, {"83 C4 04 85 C0 75 05", -0xC}, ResolveKind::Direct},
    {"src/client/shared/game/Anim.h:64", 0x004D4410, 0x004DEDD0, {}, ResolveKind::Direct},
    {"src/client/features/props/Props.cpp:469", 0x004D6720, 0x004E1630, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:1807", 0x004D6870, 0x004E1020, {}, ResolveKind::Direct},
    {"src/client/shared/game/Anim.h:19", 0x004D6AB0, 0x004E12A0, {}, ResolveKind::Direct},
    {"src/client/features/ped-speech/PedSpeech.cpp:159", 0x004E07A0, 0x004EBD40, {}, ResolveKind::Direct},
    {"src/client/features/ped-speech/PedSpeech.cpp:135", 0x004E4A20, 0x004F0190, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:106", 0x004E9800, 0x004F5260, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:117", 0x004EB890, 0x004F74B0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:751", 0x004F145C, 0x004FE6CF, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:753", 0x004F1461, 0x004FE6D4, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:615", 0x004F1464, 0x004FE6D7, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:618", 0x004F1466, 0x004FE6D9, {}, ResolveKind::Direct},
    {"src/client/features/story/minigames/Minigames.cpp:91", 0x004F1530, 0x004FE7B0, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:145", 0x004F61E0, 0x00502A40, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:210", 0x00507290, 0x00514C00, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:197", 0x005072A0, 0x00514C10, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:211", 0x005072B0, 0x00514C20, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:212", 0x005072F0, 0x00514C60, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:213", 0x00507300, 0x00514C70, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:214", 0x00507310, 0x00514C80, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:215", 0x00507320, 0x00514C90, {}, ResolveKind::Direct},
    {"src/client/features/story/mission-speech/MissionSpeech.cpp:216", 0x00507330, 0x00514CA0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:146", 0x0050C140, 0x0051A2D0, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:430", 0x00532010, 0x005437E0, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:342", 0x00532450, 0x00543C10, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:63", 0x00532B00, 0x005442B0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:604", 0x00535300, 0x00546D60, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:2007", 0x00536BE0, 0x00548B50, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:176", 0x005393F0, 0x0054B1A0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:631", 0x0053E981, 0x00551174, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:741", 0x0053E9F1, 0x005511FA, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/VehicleState.cpp:131", 0x0053FEE0, 0x00552D80, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:817", 0x00541190, 0x00554080, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:11", 0x0054FF60, 0x005680C0, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:12", 0x0054FF90, 0x00601920, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:13", 0x0054FFC0, 0x00568120, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:14", 0x0054FFF0, 0x0071F250, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:15", 0x00550020, 0x00568180, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.cpp:16", 0x00550050, 0x005BB1D0, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:188", 0x00558E40, 0x00571AF0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1194", 0x00561E70, 0x0057BDD0, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:299", 0x00562167, 0x0057C09E, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:300", 0x0056218E, 0x0057C0C2, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:75", 0x00562410, 0x0057C360, {}, ResolveKind::Direct},
    {"src/client/features/mission-objects/Objects.cpp:120", 0x00563220, 0x0057D310, {}, ResolveKind::Direct},
    {"CWorld::Remove", 0x00563280, 0x0057D370, {"8B 06 8B 50 0C 8B CE FF D2 8A 46 36 24 07 3C 01 76 0D", -7}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:866", 0x00565510, 0x0057F740, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:364", 0x00565C5E, 0x0057FECC, {}, ResolveKind::Direct},
    {"src/client/features/waypoint/Waypoint.cpp:45", 0x00583530, 0x005A2860, {}, ResolveKind::Direct},
    {"src/client/features/waypoint/Waypoint.cpp:79", 0x00587CE0, 0x005A76D0, {}, ResolveKind::Direct},
    {"src/client/features/waypoint/Waypoint.cpp:57", 0x00588050, 0x005A7A50, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:663", 0x0058FAE0, 0x0059E520, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:323", 0x0059690F, 0x005AE9BC, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:759", 0x005A81E0, 0x005BDEF0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:758", 0x005A8235, 0x005BDF45, {}, ResolveKind::Direct},
    {"CClothes::RebuildPlayer", 0x005A82C0, 0x005BDFE0, {"8B 8E ? ? ? ? 83 C4 04 6A 05", -0x11}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:2452", 0x005B0570, 0x005CD4E0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:2186", 0x005B1700, 0x005CE710, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1675", 0x005B187E, 0x005CE8A2, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:473", 0x005B25F0, 0x005CC190, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:666", 0x005D0880, 0x005ECFC0, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:667", 0x005D0890, 0x005ECFD0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:511", 0x005D1380, 0x005EDA90, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:668", 0x005D2D95, 0x005EF4E5, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:669", 0x005D2E07, 0x005EF54D, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:328", 0x005D3165, 0x005EF8C5, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:902", 0x005E06E0, 0x005FD0E0, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:1072", 0x005E6280, 0x006036E0, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:1088", 0x006010A0, 0x00620E00, {}, ResolveKind::Direct},
    {"CPedIntelligence::GetTaskJetPack", 0x00601110, 0x00620E70, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:1084", 0x00601230, 0x00620F90, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:1091", 0x00601390, 0x00621100, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:221", 0x00608350, 0x00628860, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:73", 0x00608A40, 0x00628F60, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:659", 0x00609FF0, 0x0062A5B0, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:863", 0x0060C840, 0x0062D400, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:633", 0x00610F20, 0x00632440, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:336", 0x00611FC0, 0x00633530, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:614", 0x00616300, 0x00637EB0, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:107", 0x006181A0, 0x00639D20, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:107", 0x00618280, 0x00639E00, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:698", 0x00619081, 0x0063AB71, {}, ResolveKind::Direct},
    {"src/client/app/diagnostics/Diag.cpp:49", 0x00619B60, 0x0063B690, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:652", 0x00644A1A, 0x0066B342, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:654", 0x00644A69, 0x0066B38F, {}, ResolveKind::Direct},
    {"src/client/features/damage/Damage.cpp:435", 0x00655F20, 0x0067D490, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:589", 0x006819D0, 0x006AD6C0, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:114", 0x00691230, 0x006BEB60, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:1089", 0x006924F0, 0x006BFF30, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3258", 0x0069E360, 0x006CAFF0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3259", 0x0069E4E0, 0x006CB170, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3262", 0x0069E5F0, 0x006CB280, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3256", 0x0069F0B0, 0x006CBD50, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3257", 0x0069F1E0, 0x006CBE80, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3261", 0x0069F370, 0x006CBFF0, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:86", 0x006B3E90, 0x006E2230, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:697", 0x006CAC20, 0x007006D0, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:698", 0x006CAC70, 0x00700720, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:85", 0x006CE340, 0x007041F0, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:38", 0x006D5D70, 0x00711320, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:335", 0x006F3F40, 0x006F5780, {}, ResolveKind::Direct},
    {"src/client/features/trains/Trains.cpp:134", 0x006F5DC0, 0x00707090, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:412", 0x00719590, 0x0073AB30, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:407", 0x007195C0, 0x0073AB60, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:409", 0x00719610, 0x0073ABC0, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:511", 0x00728CB0, 0x00760AB0, {}, ResolveKind::Direct},
    {"CAnimManager::GetAnimHierarchyFromSkinClump", 0x00734A40, 0x007671B0, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:392", 0x00734E50, 0x00767570, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:293", 0x00739A40, 0x007726D0, {}, ResolveKind::Direct},
    {"CWeaponInfo::GetWeaponInfo", 0x00743C60, 0x0077D940, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:173", 0x00745C70, 0x0077FAF0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:64", 0x00746060, 0x0077FEF0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:715", 0x007468E0, 0x00780720, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:734", 0x00748A8D, 0x00782A4C, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:734", 0x00748A8E, 0x00782A4D, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:738", 0x00748D9B, 0x00782D25, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:206", 0x00749B70, 0x00783B30, {}, ResolveKind::Direct},
    {"src/client/features/props/Props.cpp:419", 0x007C51A0, 0x007FF160, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:370", 0x007ECE20, 0x00826DE0, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:367", 0x007ECEF0, 0x00826EB0, {}, ResolveKind::Direct},
    {"RwFrameGetLTM", 0x007F0990, 0x0082A950, {}, ResolveKind::Direct},
    {"src/client/features/cheats/Cheats.cpp:27", 0x008A5CC8, 0x00913470, {}, ResolveKind::Direct},
    {"src/client/features/props/Props.cpp:256", 0x008CD57C, 0x0093CFD0, {}, ResolveKind::Direct},
    {"src/client/features/props/Props.cpp:256", 0x008CD580, 0x0093CFD4, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:176", 0x008CD5D0, 0x0093D024, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:189", 0x008CD750, 0x0093D1A8, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:186", 0x008CD754, 0x0093D1AC, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1172", 0x008CDEE4, 0x0093DA7C, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:341", 0x008E48D0, 0x00959C88, {}, ResolveKind::Direct},
    {"src/client/app/crash-handler/CrashHandler.cpp:141", 0x008E4A60, 0x00959E10, {}, ResolveKind::Direct},
    {"src/client/app/crash-handler/CrashHandler.cpp:135", 0x008E4B90, 0x00959F40, {}, ResolveKind::Direct},
    {"src/client/app/crash-handler/CrashHandler.cpp:136", 0x008E4CC0, 0x0095A060, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:77", 0x009690C0, 0x009DE3C0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:402", 0x00969110, 0x009DE3F8, {}, ResolveKind::Direct},
    {"src/client/features/cheats/Cheats.cpp:26", 0x00969130, 0x009DE418, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:591", 0x0096A7CC, 0x009DFA64, {}, ResolveKind::Direct},
    {"src/client/features/entrances/Entrances.cpp:24", 0x0096A7D8, 0x009DFA70, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:74", 0x0096AB4C, 0x009DFDAC, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:72", 0x0096AB5C, 0x009DFDBC, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:73", 0x0096AB64, 0x009DFDC4, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:167", 0x0096AB84, 0x009DFDE4, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:165", 0x0096AB8C, 0x009DFDEC, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:75", 0x0096AB90, 0x009DFDF0, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:76", 0x0096AB91, 0x009DFDF1, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:76", 0x0096AB94, 0x009DFDF4, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:36", 0x0096ABD8, 0x009DFE28, {}, ResolveKind::Direct},
    {"src/client/features/garages/Garages.cpp:35", 0x0096C048, 0x009E1280, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:33", 0x009788C0, 0x009EDA98, {}, ResolveKind::Direct},
    {"src/client/features/story/minigames/Minigames.cpp:606", 0x00A43C78, 0x00AB8DD0, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1922", 0x00A44070, 0x00AB91C0, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:1445", 0x00A444A8, 0x00AB95E8, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:427", 0x00A44B70, 0x00AB9CA0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:363", 0x00A476AC, 0x00ABC7DC, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:496", 0x00A48960, 0x00ABDA90, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:423", 0x00A49960, 0x00ABEA90, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1558", 0x00A7A6A0, 0x00AEF7D0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:542", 0x00A8B42C, 0x00B00558, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:46", 0x00A90850, 0x00B05968, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:1922", 0x00A91268, 0x00B06380, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:527", 0x00A9A8A0, 0x00B0F890, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:35", 0x00A9A8C0, 0x00B0F898, {}, ResolveKind::Direct},
    {"src/client/features/pickups/Pickups.cpp:36", 0x00A9AD70, 0x00B0FD48, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:420", 0x00A9B0C8, 0x00B0FFD8, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:113", 0x00B4EA28, 0x00BC38E0, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:404", 0x00B4EA2C, 0x00BC38E4, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:404", 0x00B4EA30, 0x00BC38E8, {}, ResolveKind::Direct},
    {"src/client/entities/ped/Peds.cpp:114", 0x00B4EA34, 0x00BC38EC, {}, ResolveKind::Direct},
    {"src/client/shared/game/Anim.h:13", 0x00B5D4A0, 0x00BD2350, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:402", 0x00B5F84C, 0x00BD46F8, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-clips/SceneMocap.cpp:402", 0x00B5F850, 0x00BD46FC, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:1047", 0x00B5F851, 0x00BD46FD, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:476", 0x00B5F878, 0x00BD470C, {}, ResolveKind::Direct},
    {"src/client/features/ped-speech/PedSpeech.cpp:161", 0x00B5F8B8, 0x00BD4720, {}, ResolveKind::Direct},
    {"src/client/features/ped-speech/PedSpeech.cpp:130", 0x00B613E6, 0x00BEE1D6, {}, ResolveKind::Direct},
    {"src/client/features/ped-speech/PedSpeech.cpp:24", 0x00B61C38, 0x00BEEA18, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:483", 0x00B6BC90, 0x00BF8868, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:478", 0x00B6EC10, 0x00BFB7E8, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:459", 0x00B6EC14, 0x00BFB7EC, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:458", 0x00B6EC2E, 0x00BFB7FB, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:409", 0x00B6F028, 0x00BFBBE0, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:475", 0x00B6F98C, 0x00BFC544, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:475", 0x00B6F994, 0x00BFC54C, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:23", 0x00B7014E, 0x00BFCC5B, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:22", 0x00B70152, 0x00BFCC5E, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:21", 0x00B70153, 0x00BFCC5F, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:24", 0x00B70158, 0x00BFCC64, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:487", 0x00B71AE0, 0x00BFE550, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:28", 0x00B71F80, 0x00BFE9E0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:522", 0x00B72910, 0x00BFF370, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:1748", 0x00B72914, 0x00BFF374, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:416", 0x00B72F20, 0x00BFFA50, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:415", 0x00B73190, 0x00BFFCC0, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:57", 0x00B7342C, 0x00BFFF5C, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:414", 0x00B73458, 0x00BFFF78, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:417", 0x00B74490, 0x00C01038, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:418", 0x00B74494, 0x00C0103C, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:419", 0x00B7449C, 0x00C01044, {}, ResolveKind::Direct},
    {"src/client/features/world-objects/WorldObjects.cpp:51", 0x00B744A0, 0x00C01048, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:3378", 0x00B78A00, 0x00C0B3E8, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:128", 0x00B793D4, 0x00C0BDBC, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:128", 0x00B793DC, 0x00C0BDC4, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:407", 0x00B7CB49, 0x00C0F4FA, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:406", 0x00B7CB4C, 0x00C0F500, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:405", 0x00B7CB5C, 0x00C0F510, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:404", 0x00B7CB84, 0x00C0F538, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:403", 0x00B7CD74, 0x00C0F87C, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:402", 0x00B7CD98, 0x00C0F890, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:128", 0x00BA3794, 0x00C3015C, {}, ResolveKind::Direct},
    {"src/client/features/zones/Zones.cpp:129", 0x00BA3798, 0x00C30160, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:52", 0x00BA6745, 0x00C330F9, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:411", 0x00BA6748, 0x00C33100, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:483", 0x00BA678C, 0x00C33144, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:116", 0x00BA67A4, 0x00C3315C, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:58", 0x00BA86F0, 0x00C36020, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:59", 0x00BAA248, 0x00C37B78, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:671", 0x00BAA7A0, 0x00C35090, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:384", 0x00BAB1FC, 0x00C35AD4, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:405", 0x00BAB22C, 0x00C35B04, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:2064", 0x00BC1C78, 0x00C49A70, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:27", 0x00BC3F0C, 0x00C50744, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:26", 0x00BC3FE4, 0x00C5081C, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:1218", 0x00BC3FE8, 0x00C50820, {}, ResolveKind::Direct},
    {"src/client/features/story/missions/Missions.cpp:62", 0x00BC4034, 0x00C50858, {}, ResolveKind::Direct},
    {"src/client/features/population/Population.cpp:76", 0x00C0EC23, 0x00C9B4EF, {}, ResolveKind::Direct},
    {"src/client/features/story/cutscene-partner/ScenePartner.cpp:100", 0x00C15448, 0x00CA19B0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:558", 0x00C16DB8, 0x00CA3320, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:412", 0x00C17040, 0x00CA357C, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:213", 0x00C17044, 0x00CA3580, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:214", 0x00C17048, 0x00CA3584, {}, ResolveKind::Direct},
    {"src/client/app/crash-handler/CrashHandler.cpp:104", 0x00C17050, 0x00CA358C, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:215", 0x00C17054, 0x00CA3590, {}, ResolveKind::Direct},
    {"src/client/features/mission-objects/Objects.cpp:297", 0x00C1B340, 0x00946CC8, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:128", 0x00C1C96C, 0x00CB8814, {}, ResolveKind::Direct},
    {"src/client/entities/vehicle/Vehicles.cpp:729", 0x00C1CB60, 0x00CB8A00, {}, ResolveKind::Direct},
    {"src/client/features/progress/Progress.cpp:164", 0x00C27AD0, 0x00CA8240, {}, ResolveKind::Direct},
    {"src/client/features/trains/Trains.cpp:27", 0x00C38010, 0x00CB8989, {}, ResolveKind::Direct},
    {"src/client/features/trains/Trains.cpp:73", 0x00C38014, 0x00CB8998, {}, ResolveKind::Direct},
    {"src/client/features/trains/Trains.cpp:74", 0x00C38024, 0x00CB89A8, {}, ResolveKind::Direct},
    {"src/client/shared/ui/renderer/Renderer.cpp:514", 0x00C71A60, 0x00CD1808, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:28", 0x00C81318, 0x00D0C838, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:27", 0x00C8131C, 0x00D0C83C, {}, ResolveKind::Direct},
    {"src/client/features/time-weather/World.cpp:26", 0x00C81320, 0x00D0C840, {}, ResolveKind::Direct},
    {"src/client/app/patches/Patches.cpp:306", 0x00C8800C, 0x00D13930, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:281", 0x00C89110, 0x00D144B0, {}, ResolveKind::Direct},
    {"src/client/features/fire/Fire.cpp:280", 0x00C891A8, 0x00D14538, {}, ResolveKind::Direct},
    {"src/client/entities/player/Players.cpp:57", 0x00C8A838, 0x00D15B90, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:410", 0x00C8D4C0, 0x00D187F0, {}, ResolveKind::Direct},
    {"src/client/app/core/Core.cpp:452", 0x00C92368, 0x00D1D680, {}, ResolveKind::Direct},
    {"src/client/shared/game/Game.h:413", 0x00C97C28, 0x00D22F38, {}, ResolveKind::Direct},
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
