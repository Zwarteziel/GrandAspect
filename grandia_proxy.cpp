// ============================================================================
//  Grand Aspect v1.3.1 - a 60 fps and display mode mod for GRANDIA HD Remaster
//  (d3d11.dll proxy)
//
//  1. Frame interpolation: in the field and in battles the game runs at
//     30 fps. After every logic tick this DLL draws an extra frame in which the
//     camera and the characters are halfway between the previous and the
//     current tick. That frame is shown before the real one, so the picture
//     runs at 60 fps.
//  2. Display modes: a hotkey (F10 by default) cycles between
//       - HD            the remaster's smoothed artwork (default)
//       - Pixel art     HD textures off: the original PS1 artwork, still in
//                       widescreen and at full resolution
//       - PS1 native    the port's built-in native-resolution PS1 renderer
//                       (4:3, experimental)
//
//  How it works:
//   - grandia.exe loads d3d11.dll from its own folder (this DLL).
//   - D3D11CreateDeviceAndSwapChain / D3D11CreateDevice are forwarded to the
//     real d3d11.dll in the system folder.
//   - On load (DllMain) a few places in grandia.exe are patched. Every patch
//     first checks that the original bytes are what we expect.
//
//  Addresses in this file are Ghidra addresses (image base 0x00400000).
//  VA() converts them to the real address, so ASLR is not a problem.
//
//  Build: see build.bat (must be 32-bit / x86, grandia.exe is 32-bit).
//
//  Copyright (C) 2026 Zwarteziel
//  SPDX-License-Identifier: GPL-3.0-or-later
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option)
//  any later version.
//
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
//  more details. You should have received a copy of the GNU General Public
//  License along with this program (the file LICENSE). If not, see
//  <https://www.gnu.org/licenses/>.
//
//  EXCEPTION: the built-in CRT shader (the pixel shader PSCrt in
//  SH_BUILTIN_SRC) is NOT covered by the GPL. It is based on the CRT effect
//  by SoftSpectrum48 (softspectrum48.weebly.com) and is included in Grand
//  Aspect with the author's permission. Anyone who wants to reuse or
//  redistribute that shader outside Grand Aspect needs the permission of its
//  author.
//
//  GRANDIA and GRANDIA HD Remaster are the property of their respective
//  owners. This project contains no game files or game code.
// ============================================================================

#ifndef _M_IX86
#error "Build this DLL as 32-bit (x86). grandia.exe is a 32-bit program."
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <d3d11shader.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef GA_DIAG
#include <intrin.h>
#endif

// Log detail.
//   1: everything, as during development (install details, first frames,
//      counters).
//   0: only what a player needs: what is installed, the hotkeys, frame rate
//      and display mode changes, problems and crash details.
// The diagnostic build (GA_DIAG) always logs everything.
#ifdef GA_DIAG
static int VERBOSE = 1;
#else
static int VERBOSE = 1;          // <- 1 = full log, 0 = short log
#endif

// Export names without __stdcall decoration, so grandia.exe finds them.
// (12 parameters x 4 bytes = 48, 10 x 4 = 40)
#pragma comment(linker, "/EXPORT:D3D11CreateDeviceAndSwapChain=_Proxy_D3D11CreateDeviceAndSwapChain@48")
#pragma comment(linker, "/EXPORT:D3D11CreateDevice=_Proxy_D3D11CreateDevice@40")
#pragma comment(lib, "user32.lib")   // GetAsyncKeyState, GetForegroundWindow

// ----------------------------------------------------------------------------
//  General
// ----------------------------------------------------------------------------

static const DWORD GHIDRA_IMAGE_BASE = 0x00400000;

static BYTE*   g_base      = nullptr;   // actual load address of grandia.exe
static DWORD   g_imageSize = 0;         // SizeOfImage from the PE header
static wchar_t g_dir[MAX_PATH];         // folder of grandia.exe, ending in '\'
static wchar_t g_ini[MAX_PATH];         // path of grandia_mod.ini

// Ghidra address -> real address in this process
static BYTE* VA(DWORD ghidraAddr)
{
    return g_base + (ghidraAddr - GHIDRA_IMAGE_BASE);
}

// Access to a global variable of the game
template <typename T> static T& G(DWORD ghidraAddr)
{
    return *reinterpret_cast<T*>(VA(ghidraAddr));
}

// Is [ghidraAddr, ghidraAddr+len) inside grandia.exe?
static bool InImage(DWORD ghidraAddr, DWORD len)
{
    DWORD rva = ghidraAddr - GHIDRA_IMAGE_BASE;
    return rva < g_imageSize && len <= g_imageSize - rva;
}

// ----------------------------------------------------------------------------
//  Log file: grandia_mod.log next to grandia.exe
// ----------------------------------------------------------------------------

static void LogPath(wchar_t* out, size_t count)
{
    swprintf_s(out, count, L"%sgrandia_mod.log", g_dir);
}

static void Log(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)strlen(buf);

    wchar_t path[MAX_PATH];
    LogPath(path, MAX_PATH);
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h, buf, (DWORD)n, &written, nullptr);
        WriteFile(h, "\r\n", 2, &written, nullptr);
        CloseHandle(h);
    }
#ifdef GA_DIAG
    OutputDebugStringA(buf);                    // only in the diagnostic build
    OutputDebugStringA("\n");
#endif
}

// ----------------------------------------------------------------------------
//  Patching code in memory
// ----------------------------------------------------------------------------

static bool WriteCode(void* dst, const void* src, size_t len)
{
    DWORD oldProtect;
    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(dst, src, len);
    VirtualProtect(dst, len, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    return true;
}

// Writes a CALL (E8) or JMP (E9) to 'to' at 'at', padded with NOPs.
static bool WriteBranch(BYTE* at, BYTE opcode, const void* to, size_t totalLen)
{
    BYTE patch[16];
    if (totalLen < 5 || totalLen > sizeof(patch)) return false;
    patch[0] = opcode;
    LONG rel = (LONG)((uintptr_t)to - (uintptr_t)(at + 5));
    memcpy(patch + 1, &rel, 4);
    for (size_t i = 5; i < totalLen; ++i) patch[i] = 0x90;
    return WriteCode(at, patch, totalLen);
}

// Is there a CALL at 'site' that goes to 'target'?
static bool IsCallTo(DWORD site, DWORD target)
{
    BYTE* c = VA(site);
    LONG rel;
    memcpy(&rel, c + 1, 4);
    return c[0] == 0xE8 && c + 5 + rel == VA(target);
}

// ----------------------------------------------------------------------------
//  Addresses in grandia.exe (Ghidra)
// ----------------------------------------------------------------------------

namespace Addr {
    // Code
    const DWORD CallEndFrameInMainLoop = 0x004514C5;  // CALL Field_EndFrame in Field_MainLoop
    const DWORD Field_EndFrame         = 0x00451680;
    const DWORD CdEmu_Tick             = 0x004072C0;  // CD emulation: read delay + reading
    const DWORD GetVBlankTick          = 0x00418860;
    const DWORD ClearOTag              = 0x00419BD0;
    const DWORD PutDispEnv             = 0x00419B70;  // (ECX = &db->disp)
    const DWORD PutDrawEnv_Flip        = 0x00419C20;  // (ECX = &db->ot[19], EDX = &db->draw)
    const DWORD FUN_00457610           = 0x00457610;
    const DWORD SortDepthList          = 0x00482480;  // quicksort (ECX=EDX=begin, [stack]=end)
    const DWORD BuildCameraMatrix      = 0x00482100;  // view matrix + camera output from camera object
    const DWORD FirstDraw              = 0x004552D0;  // first draw step in Field_Tick
    const DWORD CallCompassPrep        = 0x00456948;  // CALL FUN_0046ec50 (in Field_Tick)
    const DWORD CallCameraMatrix       = 0x004561E8;  // CALL FUN_00482100 (in Field_Tick)
    const DWORD CallFirstDraw          = 0x004564AD;  // CALL FUN_004552d0 (in Field_Tick)
    const DWORD CompassPrep            = 0x0046EC50;  // compass state (also contains logic)
    const DWORD CompassTransform       = 0x00487700;  // transform compass model via the GTE
    const DWORD CompassDraw            = 0x00488040;  // draw compass (EDX = nextpri, [stack] = ECX from 487700)
    const DWORD DrawPortrait           = 0x00456CC0;  // dialogue portrait (ECX=slot, EDX=x, [stack] y, db)
    const DWORD MarkDirty              = 0x00426C20;  // mark HD sprites in an uploaded area as 'dirty'
    const DWORD ReadHdOff_Render       = 0x00439DC4;  // mov al,[DAT_0063f052] (render thread, every frame)
    const DWORD ReadHdOff_Other        = 0x00426F90;  // mov al,[DAT_0063f052]

    // Data
    const DWORD g_cdb          = 0x00719424;  // current draw buffer (PS1-style DB struct)
    const DWORD DB0            = 0x00719480;
    const DWORD DB1            = 0x0071959C;
    const DWORD PacketHeap     = 0x00640E68;  // base of the packet buffers
    const DWORD FrameFlag      = 0x00640BBC;  // != 0: a frame is waiting for the render thread
    const DWORD LastTick       = 0x0063F888;  // 64-bit vblank tick of the last flip
    const DWORD FieldState     = 0x0071942C;  // 1 = walking around (30 fps)
    const DWORD SkipExtraWait  = 0x006C2890;
    const DWORD EncounterState = 0x0071CB10;  // byte, != 0: battle transition (swirl) running
    const DWORD SortCount      = 0x0071BD60;  // int: number of (depth, prim) pairs
    const DWORD SortListPtr    = 0x0063FB00;  // pointer to the list
    const DWORD SortListBase   = 0x006CCE38;
    const DWORD FieldPlayerPtr = 0x0071CD1C;
    const DWORD PartyTable     = 0x0071CD28;  // party: 4 x 0xA0 bytes, position at +0x68
    const DWORD NpcTable       = 0x0071CD34;  // NPCs: 80 x 0x10 bytes, position at +0x04
    const DWORD CameraObj      = 0x0071CD54;  // camera object
    const DWORD GteOfsX        = 0x00640CC0;  // GTE: screen centre X (16.16)
    const DWORD GteOfsY        = 0x00640CC4;  // GTE: screen centre Y (16.16)
    const DWORD GteH           = 0x00640CC8;  // GTE: projection distance
    const DWORD Flag_0071A5C8  = 0x0071A5C8;
    const DWORD Flag_0071CD38  = 0x0071CD38;
    const DWORD CdDelay        = 0x00640F20;  // counter in CdEmu_Tick
    const DWORD PortraitTable  = 0x006C28B4;  // 3 x 6 bytes: state (1 = shown), timer, x, y
    const DWORD PsxModeRequest = 0x0063F8A8;  // 1 = native PS1 renderer (copied at every flip)
    const DWORD HdOffFlag      = 0x0063F052;  // != 0: renderer without HD textures
    const DWORD HdListLogic    = 0x006412BC;  // HD record list the logic writes to
    const DWORD HdListRender   = 0x006412C4;  // HD record list of the render thread
    const DWORD WidescreenOfs  = 0x006186C8;  // float, 60.0 after every flip
}

// Camera output (filled by FUN_00482100 / FUN_0045b420)
static const DWORD CAM_OUT [6] = { 0x0071931C, 0x00719320, 0x00719324, 0x00719328, 0x0071932C, 0x00719330 };
static const DWORD CAM_ANG [3] = { 0x00719254, 0x00719258, 0x0071925C };

// DB struct (as in the PS1 SDK): DRAWENV at 0x00, DISPENV at 0x5C,
// ordering table of 20 entries x 8 bytes at 0x70, packet buffer end at 0x114,
// packet buffer write position at 0x118.
static const DWORD DB_DISP     = 0x5C;
static const DWORD DB_OT       = 0x70;
static const int   DB_OT_SIZE  = 20;
static const DWORD DB_OT_HEAD  = 0x108;
static const DWORD DB_PK_END   = 0x114;
static const DWORD DB_PK_NEXT  = 0x118;

// ----------------------------------------------------------------------------
//  Game functions
// ----------------------------------------------------------------------------

typedef void             (__cdecl    *VoidFn_t)(void);
typedef void             (__fastcall *Fast2_t)(DWORD ecx, DWORD edx);
typedef unsigned __int64 (__cdecl    *GetVBlankTick_t)(void);
typedef int              (__fastcall *ClearOTag_t)(void* ot, int n);
typedef void             (__fastcall *PutDispEnv_t)(void* disp);
typedef void             (__fastcall *PutDrawEnvFlip_t)(void* otHead, void* drawEnv);

static VoidFn_t         s_Field_EndFrame    = nullptr;
static VoidFn_t         s_CdEmu_Tick        = nullptr;
static GetVBlankTick_t  s_GetVBlankTick     = nullptr;
static ClearOTag_t      s_ClearOTag         = nullptr;
static PutDispEnv_t     s_PutDispEnv        = nullptr;
static PutDrawEnvFlip_t s_PutDrawEnvFlip    = nullptr;
static Fast2_t          s_FUN_00457610      = nullptr;
static void*            s_SortDepthList     = nullptr;
static VoidFn_t         s_BuildCameraMatrix = nullptr;
static VoidFn_t         s_CompassPrep       = nullptr;
static void*            s_CompassTransform  = nullptr;
static void*            s_CompassDraw       = nullptr;
static void*            s_DrawPortrait      = nullptr;

static void ResolveGameFunctions()
{
    s_Field_EndFrame    = (VoidFn_t)        VA(Addr::Field_EndFrame);
    s_CdEmu_Tick        = (VoidFn_t)        VA(Addr::CdEmu_Tick);
    s_GetVBlankTick     = (GetVBlankTick_t) VA(Addr::GetVBlankTick);
    s_ClearOTag         = (ClearOTag_t)     VA(Addr::ClearOTag);
    s_PutDispEnv        = (PutDispEnv_t)    VA(Addr::PutDispEnv);
    s_PutDrawEnvFlip    = (PutDrawEnvFlip_t)VA(Addr::PutDrawEnv_Flip);
    s_FUN_00457610      = (Fast2_t)         VA(Addr::FUN_00457610);
    s_SortDepthList     =                   VA(Addr::SortDepthList);
    s_BuildCameraMatrix = (VoidFn_t)        VA(Addr::BuildCameraMatrix);
    s_CompassPrep       = (VoidFn_t)        VA(Addr::CompassPrep);
    s_CompassTransform  =                   VA(Addr::CompassTransform);
    s_CompassDraw       =                   VA(Addr::CompassDraw);
    s_DrawPortrait      =                   VA(Addr::DrawPortrait);
}

// ============================================================================
//  PART 1: FRAME INTERPOLATION
// ============================================================================

enum TweenOpKind { OP_CALL, OP_RESETSORT, OP_SORT, OP_COND457610, OP_COMPASS, OP_PORTRAITS, OP_MAPFX };

struct TweenOp {
    TweenOpKind kind;
    Fast2_t     fn;
    DWORD       ecx, edx;     // register arguments (many game functions expect them)
    char        label[24];
};

static const int MAX_TWEEN_OPS = 64;

// For the crash logger: what was the hook doing?
static const char* volatile g_phase         = "outside the hook";
static volatile LONG        g_tweenStep     = -1;
static volatile DWORD       g_logicThreadId = 0;

// Set when Field_Tick drew the compass this tick (see Stub_CompassPrep)
static volatile bool g_compassDrawn  = false;
static bool          g_compassHooked = false;

static struct {
    bool     enabled;
    bool     compassThisTick;
    float    alpha;                  // fraction of a logic tick (0.5 = halfway)
    TweenOp  ops[MAX_TWEEN_OPS];
    int      opCount;
    unsigned framesDone;
} g_tween;

// Frame rate mode, switched with a hotkey ([Interpolation] Hotkey, default F9):
//   0 = original 30 fps, 1 = 60 fps with interpolated frames,
//   2 = 60 fps double speed (the game logic runs every frame).
enum { FM_ORIGINAL = 0, FM_INTERPOLATED = 1, FM_DOUBLE = 2 };
static volatile int g_frameMode = FM_INTERPOLATED;
static const char* const FRAME_MODE_NAMES[3] = {
    "30 fps (original)", "60 fps (interpolated)", "60 fps (double speed)" };

// ----------------------------------------------------------------------------
//  Draw buffers and flips
// ----------------------------------------------------------------------------

static void WaitFrameConsumed()
{
    while (*(volatile LONG*)VA(Addr::FrameFlag) != 0)
        YieldProcessor();
}

// Does what the end of Field_EndFrame does: PutDispEnv + PutDrawEnv/DrawOTag.
// Pacing takes care of itself: the render thread picks up at most one frame
// per vblank, and we only hand over a new frame once the previous one is taken.
static void FlipBuffer(BYTE* db)
{
    WaitFrameConsumed();
    s_PutDispEnv(db + DB_DISP);
    s_PutDrawEnvFlip(db + DB_OT_HEAD, db);
    G<unsigned __int64>(Addr::LastTick) = s_GetVBlankTick();
}

static void WaitNextVBlank()
{
    unsigned __int64 t = s_GetVBlankTick();
    while (s_GetVBlankTick() <= t)
        YieldProcessor();
    G<unsigned __int64>(Addr::LastTick) = s_GetVBlankTick();
}

// Does what Field_MainLoop does at the start of every round:
// switch draw buffer, set up the packet buffer, clear the ordering table.
static BYTE* SwapDrawBuffer()
{
    BYTE*  db0  = VA(Addr::DB0);
    BYTE*  db1  = VA(Addr::DB1);
    BYTE*& cdb  = G<BYTE*>(Addr::g_cdb);
    BYTE*  heap = G<BYTE*>(Addr::PacketHeap);
    BYTE*  pk;

    if (cdb == db0) { cdb = db1; pk = heap + 0x44200; }
    else            { cdb = db0; pk = heap + 0x64200; }

    *(BYTE**)(cdb + DB_PK_NEXT) = pk;
    *(BYTE**)(cdb + DB_PK_END)  = pk + 0x1FF00;
    s_ClearOTag(cdb + DB_OT, DB_OT_SIZE);
    return cdb;
}

// Field_Tick:
//   if (DAT_0071bd60 >= 2) FUN_00482480(ECX = EDX = list, [stack] = &list[count-1]);
// Sorts the (depth, prim) pairs. Custom calling convention, hence inline assembly.
static __declspec(noinline) void SortDepthList()
{
    int count = G<int>(Addr::SortCount);
    if (count < 2)
        return;
    DWORD list = G<DWORD>(Addr::SortListPtr);
    DWORD last = list + (DWORD)(count - 1) * 8;
    void* fn   = s_SortDepthList;
    __asm {
        mov  ecx, list
        mov  edx, ecx
        push last
        call fn
        add  esp, 4
    }
}

// ----------------------------------------------------------------------------
//  Compass
// ----------------------------------------------------------------------------

// Replaces the call of FUN_0046ec50 in Field_Tick. That function is only
// called when the compass is drawn, so this tells us whether the interpolated
// frame should draw the compass as well.
static void __cdecl Stub_CompassPrep()
{
    g_compassDrawn = true;
    s_CompassPrep();
}

// The drawing part of the compass block in Field_Tick (0x45694d-0x4569d2),
// without FUN_0046ec50 (which contains logic). FUN_00487700 returns a value in
// ECX that FUN_00488040 expects on the stack; hence inline assembly.
static __declspec(noinline) void DrawCompass()
{
    int savedH = G<int>(Addr::GteH);
    G<DWORD>(Addr::GteOfsX) = 0xB40000;
    G<DWORD>(Addr::GteOfsY) = 0x900000;
    G<DWORD>(Addr::GteH)    = 0x400;

    void* fTransform = s_CompassTransform;
    void* fDraw      = s_CompassDraw;
    DWORD cdbVar     = (DWORD)(uintptr_t)VA(Addr::g_cdb);
    __asm {
        call fTransform
        mov  eax, cdbVar
        mov  eax, [eax]             ; eax = g_cdb
        push ecx                    ; value from FUN_00487700
        mov  edx, [eax + 0x118]     ; edx = nextpri
        call fDraw
        add  esp, 4
        mov  ecx, cdbVar
        mov  ecx, [ecx]
        mov  [ecx + 0x118], eax     ; new nextpri
    }

    G<int>(Addr::GteH)      = (int)(short)savedH;
    G<DWORD>(Addr::GteOfsX) = 0;
    G<DWORD>(Addr::GteOfsY) = 0x1200000;
    SortDepthList();
}

// ----------------------------------------------------------------------------
//  Dialogue portraits
//
//  Field_Tick (0x456a7d-0x456aac):
//    for (i = 0; i < 3; i++)
//      if (DAT_006c28b4[i].state == 1)
//        FUN_00456cc0(ECX = i, EDX = x, [stack] y, g_cdb);   caller pops 8 bytes
//  FUN_00456cc0 only builds a textured quad in the packet buffer; the timers
//  in the table are handled elsewhere in Field_Tick, so this is safe to repeat.
// ----------------------------------------------------------------------------

static __declspec(noinline) void DrawPortraits()
{
    BYTE* table = VA(Addr::PortraitTable);
    void* fn    = s_DrawPortrait;
    for (DWORD i = 0; i < 3; ++i) {
        BYTE* e = table + i * 6;
        if (e[0] != 1)
            continue;
        DWORD x   = *(WORD*)(e + 2);
        DWORD y   = *(WORD*)(e + 4);
        DWORD cdb = G<DWORD>(Addr::g_cdb);
        __asm {
            push cdb
            push y
            mov  ecx, i
            mov  edx, x
            call fn
            add  esp, 8
        }
    }
}

// ----------------------------------------------------------------------------
//  Things the interpolated frame must NOT do
//
//  g_inTween is set while the draw steps of the interpolated frame run.
//
//  1. 'Mark dirty' (FUN_00426c20): the per-character draw function uploads the
//     sprite frame to video memory, and the port then marks the HD sprites in
//     that area as 'dirty'. In the real frame they are registered again later
//     in Field_Tick, in the interpolated frame they are not, and the renderer
//     falls back to PS1 pixels. The upload itself is fine (it is identical to
//     the one of the real frame).
//
//  2. CdEmu_Tick (FUN_004072c0): FUN_004836f0 calls it twice. In the
//     interpolated frame that would make the CD emulation run faster than in
//     the original game.
// ----------------------------------------------------------------------------

static volatile bool g_inTween = false;

static DWORD         g_markDirtyCont    = 0;   // 0x00426c25
static volatile LONG g_markDirtySkipped = 0;

// FUN_00426c20(ECX = HD sprite manager, [stack] x, y, w, h), ret 0x10
static __declspec(naked) void Stub_MarkDirty()
{
    __asm {
        cmp  byte ptr [g_inTween], 0
        je   do_orig
        lock inc dword ptr [g_markDirtySkipped]
        ret  0x10
    do_orig:
        push ebp
        mov  ebp, esp
        push ecx
        push ebx
        jmp  dword ptr [g_markDirtyCont]
    }
}

static DWORD         g_cdTickCont    = 0;      // 0x004072c9
static DWORD         g_pCdDelay      = 0;      // real address of DAT_00640f20
static volatile LONG g_cdTickSkipped = 0;

// FUN_004072c0(): push ebp / mov ebp,esp / mov ecx,[DAT_00640f20] / ...  ret
static __declspec(naked) void Stub_CdEmuTick()
{
    __asm {
        cmp  byte ptr [g_inTween], 0
        je   do_orig
        lock inc dword ptr [g_cdTickSkipped]
        ret
    do_orig:
        push ebp
        mov  ebp, esp
        mov  ecx, dword ptr [g_pCdDelay]
        mov  ecx, [ecx]
        jmp  dword ptr [g_cdTickCont]
    }
}

static bool Install_MarkDirtyBlock()
{
    BYTE* p = VA(Addr::MarkDirty);
    static const BYTE expect[5] = { 0x55, 0x8B, 0xEC, 0x51, 0x53 };
    if (memcmp(p, expect, 5) != 0) {
        Log("Interpolation: start of FUN_00426c20 is not as expected - not patched.");
        return false;
    }
    g_markDirtyCont = (DWORD)(uintptr_t)(p + 5);
    return WriteBranch(p, 0xE9, (void*)&Stub_MarkDirty, 5);
}

static bool Install_CdTickBlock()
{
    BYTE* p = VA(Addr::CdEmu_Tick);
    DWORD abs;
    memcpy(&abs, p + 5, 4);
    g_pCdDelay = (DWORD)(uintptr_t)VA(Addr::CdDelay);
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x8B || p[4] != 0x0D || abs != g_pCdDelay) {
        Log("Interpolation: start of CdEmu_Tick is not as expected - not patched.");
        return false;
    }
    g_cdTickCont = (DWORD)(uintptr_t)(p + 9);
    return WriteBranch(p, 0xE9, (void*)&Stub_CdEmuTick, 9);
}

// ----------------------------------------------------------------------------
//  Draw steps of the interpolated frame
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
//  Map overlay effects (mist, light beams, haze, ...)
//
//  Field_Tick (0x4564c1-0x4565d1):
//    if (DAT_00719924 != -1 && DAT_00713eec != 0x1f && DAT_00713ea0 != 0)
//      switch (player->type_0f) {
//        1,2,3,5,7: FUN_00481920()             static overlay quads (e.g. light)
//        4,13:      random offset; FUN_00481920()
//        6,8,12:    scroll timer; FUN_00481370(); FUN_004817e0()
//        9,10:      scroll timer; FUN_00481370(); FUN_004817e0()   (e.g. mist)
//        11:        FUN_00481460(0); FUN_00481460(3)   moving quads
//      }
//  FUN_00481920 and FUN_004817e0 only draw (from the state of this tick), so
//  the interpolated frame calls them as they are. FUN_00481370 (wave update)
//  and the timers are logic and are left out; so is rand() (types 4 and 13).
//  FUN_00481460 moves its quads (x + 8, y + 0x1c) and then draws them: its
//  state is saved, set back by 1 + (1 - alpha) steps so that it draws halfway,
//  and put back afterwards.
// ----------------------------------------------------------------------------
// The wave effect (FUN_004817e0) takes the x offset of each of its 224 lines
// from a table (pointer in DAT_006cce30) that FUN_00481370 fills just before.
// That memory is used for other things later in the tick, so by the time the
// interpolated frame is drawn it holds something else. The real tick's table
// is copied when the game calls FUN_004817e0 (call at 0x4565cc) and put in
// place for the interpolated frame only.
static unsigned      g_hookSeq       = 0;      // number of field ticks (Hook_Field_EndFrame)
static const DWORD   MAPFX_TABLE_PTR = 0x006CCE30;
static const DWORD   MAPFX_TABLE_LEN = 0x1C0;   // 224 x 16 bits
static BYTE          g_fxTable[MAPFX_TABLE_LEN];
static unsigned      g_fxTableSeq    = 0;      // tick of the copy (0 = none)
static DWORD         g_fxWaveTarget  = 0;

static void __cdecl OnMapWaveDraw()
{
    BYTE* t = G<BYTE*>(MAPFX_TABLE_PTR);
    if (!t || g_inTween) return;
    memcpy(g_fxTable, t, MAPFX_TABLE_LEN);
    g_fxTableSeq = g_hookSeq + 1;               // Hook_Field_EndFrame of this tick comes next
}

static __declspec(naked) void Stub_MapWaveDraw() { __asm {
    pushad
    pushfd
    call OnMapWaveDraw
    popfd
    popad
    jmp  dword ptr [g_fxWaveTarget]
} }

static void DrawMapEffects()
{
    if (G<int>(0x00719924) == -1 || G<BYTE>(0x00713EEC) == 0x1F || G<WORD>(0x00713EA0) == 0)
        return;
    BYTE* player = G<BYTE*>(Addr::FieldPlayerPtr);
    if (!player) return;
    const int type = player[0x0F];
    switch (type) {
    case 1: case 2: case 3: case 4: case 5: case 7: case 13:
        ((Fast2_t)VA(0x00481920))(0, 0);
        break;
    case 6: case 8: case 9: case 10: case 12: {
        BYTE* t = G<BYTE*>(MAPFX_TABLE_PTR);
        if (!t || g_fxTableSeq != g_hookSeq) break;      // no copy of this tick: leave it out
        BYTE now[MAPFX_TABLE_LEN];
        memcpy(now, t, MAPFX_TABLE_LEN);
        memcpy(t, g_fxTable, MAPFX_TABLE_LEN);
        ((Fast2_t)VA(0x004817E0))(0, 0);
        memcpy(t, now, MAPFX_TABLE_LEN);
        break;
    }
    case 11: {
        BYTE saved[0x60];
        memcpy(saved, VA(0x00713EA0), sizeof(saved));
        float t = g_tween.alpha < 0.0f ? 0.0f : (g_tween.alpha > 1.0f ? 1.0f : g_tween.alpha);
        const short backX = (short)(8    + 8    * (1.0f - t) + 0.5f);
        const short backY = (short)(0x1C + 0x1C * (1.0f - t) + 0.5f);
        static const DWORD IDX[2] = { 0, 3 };
        for (DWORD i : IDX) {
            G<short>(0x00713EB8 + i * 8) -= backX;
            G<short>(0x00713EBA + i * 8) -= backY;
        }
        for (DWORD i : IDX)
            ((Fast2_t)VA(0x00481460))(i, 0);
        memcpy(VA(0x00713EA0), saved, sizeof(saved));
        break;
    }
    default:
        break;
    }
}

static bool RunTweenOps(bool verbose)
{
    for (int i = 0; i < g_tween.opCount; ++i) {
        const TweenOp& op = g_tween.ops[i];
        g_tweenStep = i + 1;
        if (verbose)
            Log("  draw step %d: %s", i + 1, op.label);

        switch (op.kind) {
        case OP_CALL:
            op.fn(op.ecx, op.edx);
            break;
        case OP_RESETSORT:
            // Field_Tick: DAT_0071bd60 = 0; DAT_0063fb00 = &DAT_006cce38;
            G<int>(Addr::SortCount) = 0;
            G<DWORD>(Addr::SortListPtr) = (DWORD)(uintptr_t)VA(Addr::SortListBase);
            break;
        case OP_SORT:
            SortDepthList();
            break;
        case OP_COMPASS:
            if (g_tween.compassThisTick)
                DrawCompass();
            break;
        case OP_PORTRAITS:
            DrawPortraits();
            break;
        case OP_MAPFX:
            DrawMapEffects();
            break;
        case OP_COND457610:
            // Field_Tick: if (DAT_0071a5c8 == 0 && DAT_0071cd38 == 0)
            //                 FUN_00457610(DX = *(u16*)(DAT_0071cd1c + 0x22));
            if (G<BYTE>(Addr::Flag_0071A5C8) == 0 && G<BYTE>(Addr::Flag_0071CD38) == 0) {
                BYTE* player = G<BYTE*>(Addr::FieldPlayerPtr);
                s_FUN_00457610(0, *(WORD*)(player + 0x22));
            }
            break;
        }

        // The game never checks the end of the packet buffer. If a step went
        // past it, stop and drop this interpolated frame.
        BYTE* cdb = G<BYTE*>(Addr::g_cdb);
        if (*(BYTE**)(cdb + DB_PK_NEXT) > *(BYTE**)(cdb + DB_PK_END)) {
            static int s_fullLogs = 0;
            if (s_fullLogs < 5) {
                ++s_fullLogs;
                Log("Field: packet buffer full after draw step %d (%s) - interpolated frame dropped.", i + 1, op.label);
            }
            g_tweenStep = -1;
            return false;
        }
    }
    g_tweenStep = -1;
    if (verbose)
        Log("  all draw steps done.");
    return true;
}

// ----------------------------------------------------------------------------
//  State per logic tick
//
//  Field_Tick first builds the view matrix (0x4561E8), then handles movement
//  and input, and only then draws (0x4564AD). We capture the camera and the
//  positions at exactly those two moments, so the interpolated frame lies
//  between two REAL frames.
// ----------------------------------------------------------------------------

static const int   NUM_PARTY    = 4;
static const DWORD PARTY_STRIDE = 0xA0;
static const int   NUM_NPC      = 80;
static const DWORD NPC_STRIDE   = 0x10;
static const LONG  TELEPORT     = 0x400000;
static const LONG  FULL_TURN    = 0x1680000;   // 360 degrees in 16.16

struct TickSnap {
    bool     valid;
    unsigned seq;
    int      camOut[6];          // 0x71931c..0x719330
    int      camObj[7];          // camera object +0x28 (zoom), +0x44/+0x48/+0x4c (rotation),
                                 // +0x2c/+0x30/+0x34 (point the camera follows)
    BYTE     camRaw[0x50];       // the whole camera object as FUN_00482100 saw it
    BYTE     partyOn[NUM_PARTY];
    int      party[NUM_PARTY][3];
    BYTE     npcOn[NUM_NPC];
    int      npc[NUM_NPC][3];
    BYTE     sprSet[NUM_PARTY];      // sprite set of every party member (+0x15) ...
    DWORD    sprTab[NUM_PARTY][2];   // ... and that set's frame table and part table
};

// Party sprites (drawn by FUN_00470ee0, inside draw step 004825d0)
static const DWORD SPR_FRAME_TABLES = 0x0071A6A8;  // per sprite set: frames, 4 bytes each (first part, count)
static const DWORD SPR_PART_TABLES  = 0x0071AA20;  // per sprite set: parts, 16 bytes each
static const DWORD SPR_SLOTS        = 0x006CC70C;  // per member, 10 bytes; count at +4 (used when [0x71cd58] >= 3)
static const DWORD SPR_MODE         = 0x0071CD58;  // word
static const int   SPR_MAX_PARTS    = 31;          // all members together: the part list at 0x6ccbc0
                                                   // (20 bytes each) ends at 0x6cce38

static const DWORD CAM_OBJ_OFS[7] = { 0x28, 0x44, 0x48, 0x4C, 0x2C, 0x30, 0x34 };

static TickSnap g_prevSnap, g_curSnap, g_drawSnap;
static bool     g_camSnapTaken   = false;
static bool     g_drawSnapTaken  = false;
static DWORD    g_camHookTarget  = 0;
static DWORD    g_drawHookTarget = 0;

static void SnapCamObj(TickSnap& s)
{
    BYTE* cam = G<BYTE*>(Addr::CameraObj);
    for (int i = 0; i < 7; ++i) s.camObj[i] = cam ? *(int*)(cam + CAM_OBJ_OFS[i]) : 0;
    if (cam) memcpy(s.camRaw, cam, sizeof(s.camRaw)); else memset(s.camRaw, 0, sizeof(s.camRaw));
}

static void SnapScene(TickSnap& s)
{
    for (int i = 0; i < 6; ++i) s.camOut[i] = G<int>(CAM_OUT[i]);
    BYTE* party = G<BYTE*>(Addr::PartyTable);
    for (int i = 0; i < NUM_PARTY; ++i) {
        BYTE* e = party ? party + i * PARTY_STRIDE : nullptr;
        s.partyOn[i] = e ? e[1] : 0;
        for (int k = 0; k < 3; ++k) s.party[i][k] = e ? *(int*)(e + 0x68 + 4 * k) : 0;
        s.sprSet[i]    = e ? e[0x15] : 0;
        s.sprTab[i][0] = G<DWORD>(SPR_FRAME_TABLES + 4 * s.sprSet[i]);
        s.sprTab[i][1] = G<DWORD>(SPR_PART_TABLES  + 4 * s.sprSet[i]);
    }
    BYTE* npc = G<BYTE*>(Addr::NpcTable);
    for (int i = 0; i < NUM_NPC; ++i) {
        BYTE* e = npc ? npc + i * NPC_STRIDE : nullptr;
        s.npcOn[i] = e ? e[0] : 0;
        for (int k = 0; k < 3; ++k) s.npc[i][k] = e ? *(int*)(e + 4 + 4 * k) : 0;
    }
}

static void __cdecl OnBeforeCamMatrix()
{
    SnapCamObj(g_drawSnap);
    g_camSnapTaken = true;
}

static void __cdecl OnBeforeFirstDraw()
{
    SnapScene(g_drawSnap);
    g_drawSnapTaken = g_camSnapTaken;
}

static __declspec(naked) void Stub_BeforeCamMatrix() { __asm {
    pushad
    pushfd
    call OnBeforeCamMatrix
    popfd
    popad
    jmp dword ptr [g_camHookTarget]
} }

static __declspec(naked) void Stub_BeforeFirstDraw() { __asm {
    pushad
    pushfd
    call OnBeforeFirstDraw
    popfd
    popad
    jmp dword ptr [g_drawHookTarget]
} }

static bool InstallDrawSnapHooks()
{
    if (!IsCallTo(Addr::CallCameraMatrix, Addr::BuildCameraMatrix) ||
        !IsCallTo(Addr::CallFirstDraw, Addr::FirstDraw)) {
        Log("Interpolation: calls in Field_Tick are not as expected - not patched.");
        return false;
    }
    g_camHookTarget  = (DWORD)(uintptr_t)VA(Addr::BuildCameraMatrix);
    g_drawHookTarget = (DWORD)(uintptr_t)VA(Addr::FirstDraw);
    return WriteBranch(VA(Addr::CallCameraMatrix), 0xE8, (void*)&Stub_BeforeCamMatrix, 5)
        && WriteBranch(VA(Addr::CallFirstDraw),    0xE8, (void*)&Stub_BeforeFirstDraw, 5);
}

// ----------------------------------------------------------------------------
//  Interpolating, and restoring everything exactly afterwards
// ----------------------------------------------------------------------------

static int LerpI(int a, int b, int t16)
{
    int d = (int)((unsigned)b - (unsigned)a);
    return a + (int)(((long long)d * t16) >> 16);
}

static int LerpAngle(int a, int b, int t16)
{
    int d = (int)((unsigned)b - (unsigned)a);
    if (d >  FULL_TURN / 2) d -= FULL_TURN;
    if (d < -FULL_TURN / 2) d += FULL_TURN;
    return a + (int)(((long long)d * t16) >> 16);
}

static bool IsJump(const int* a, const int* b)
{
    for (int k = 0; k < 3; ++k) {
        LONG d = (LONG)((unsigned)b[k] - (unsigned)a[k]);
        if (d > TELEPORT || d < -TELEPORT) return true;
    }
    return false;
}

// Memory changed by FUN_00482100 / FUN_0045b420 and the draw steps
struct SavedRange { DWORD addr; DWORD len; };
static const SavedRange SAVE_RANGES[] = {
    { 0x007191C4, 0x04 }, { 0x007191E0, 0x20 }, { 0x00719254, 0x10 }, { 0x007192A0, 0x0C },
    { 0x00719300, 0x3C }, { 0x00640CC8, 0x04 }, { 0x00713E40, 0x01 }, { 0x00713E80, 0x01 },
    { 0x0071A9D8, 0x04 },
};
static BYTE g_saveBuf[0x200];
static BYTE g_saveCam[0x50];
static int  g_saveParty[NUM_PARTY][3];
static int  g_saveNpc[NUM_NPC][3];

static void SaveTweenState()
{
    BYTE* p = g_saveBuf;
    for (const SavedRange& r : SAVE_RANGES) { memcpy(p, VA(r.addr), r.len); p += r.len; }
    BYTE* cam = G<BYTE*>(Addr::CameraObj);
    if (cam) memcpy(g_saveCam, cam, sizeof(g_saveCam));
    BYTE* party = G<BYTE*>(Addr::PartyTable);
    if (party)
        for (int i = 0; i < NUM_PARTY; ++i)
            memcpy(g_saveParty[i], party + i * PARTY_STRIDE + 0x68, 12);
    BYTE* npc = G<BYTE*>(Addr::NpcTable);
    if (npc)
        for (int i = 0; i < NUM_NPC; ++i)
            memcpy(g_saveNpc[i], npc + i * NPC_STRIDE + 4, 12);
}

static void RestoreTweenState()
{
    BYTE* p = g_saveBuf;
    for (const SavedRange& r : SAVE_RANGES) { memcpy(VA(r.addr), p, r.len); p += r.len; }
    BYTE* cam = G<BYTE*>(Addr::CameraObj);
    if (cam) memcpy(cam, g_saveCam, sizeof(g_saveCam));
    BYTE* party = G<BYTE*>(Addr::PartyTable);
    if (party)
        for (int i = 0; i < NUM_PARTY; ++i)
            memcpy(party + i * PARTY_STRIDE + 0x68, g_saveParty[i], 12);
    BYTE* npc = G<BYTE*>(Addr::NpcTable);
    if (npc)
        for (int i = 0; i < NUM_NPC; ++i)
            memcpy(npc + i * NPC_STRIDE + 4, g_saveNpc[i], 12);
}

static void ApplyTweenState(const TickSnap& a, const TickSnap& b, int t16)
{
    for (int i = 0; i < 6; ++i)
        G<int>(CAM_OUT[i]) = LerpI(a.camOut[i], b.camOut[i], t16);

    BYTE* cam = G<BYTE*>(Addr::CameraObj);
    if (cam) {
        memcpy(cam, b.camRaw, sizeof(b.camRaw));
        *(int*)(cam + 0x28) = LerpI(a.camObj[0], b.camObj[0], t16);
        for (int i = 1; i < 4; ++i)
            *(int*)(cam + CAM_OBJ_OFS[i]) = LerpAngle(a.camObj[i], b.camObj[i], t16);
        // The point the camera follows: FUN_00482100 copies it to 0x71931c..
        if (!IsJump(&a.camObj[4], &b.camObj[4]))
            for (int i = 4; i < 7; ++i)
                *(int*)(cam + CAM_OBJ_OFS[i]) = LerpI(a.camObj[i], b.camObj[i], t16);
    }

    BYTE* party = G<BYTE*>(Addr::PartyTable);
    if (party)
        for (int i = 0; i < NUM_PARTY; ++i) {
            int* pos = (int*)(party + i * PARTY_STRIDE + 0x68);
            bool lerp = a.partyOn[i] && b.partyOn[i] && !IsJump(a.party[i], b.party[i]);
            for (int k = 0; k < 3; ++k)
                pos[k] = lerp ? LerpI(a.party[i][k], b.party[i][k], t16) : b.party[i][k];
        }

    BYTE* npc = G<BYTE*>(Addr::NpcTable);
    if (npc)
        for (int i = 0; i < NUM_NPC; ++i) {
            int* pos = (int*)(npc + i * NPC_STRIDE + 4);
            bool lerp = a.npcOn[i] && b.npcOn[i] && !IsJump(a.npc[i], b.npc[i]);
            for (int k = 0; k < 3; ++k)
                pos[k] = lerp ? LerpI(a.npc[i][k], b.npc[i][k], t16) : b.npc[i][k];
        }

    // Let the game itself recompute the view matrix and the camera output.
    s_BuildCameraMatrix();

    // Same formula as in Field_Tick (0x456471)
    for (int i = 0; i < 3; ++i)
        G<int>(CAM_ANG[i]) = -((G<int>(CAM_OUT[i]) + 0x8000) >> 13);
}

// ----------------------------------------------------------------------------
//  HD record list
//
//  Everything drawn in HD gets a record (0x5C bytes) in the list
//  *DAT_006412bc; the prim carries the record number. PutDrawEnv_Flip hands
//  that list to the render thread and starts an empty one. The interpolated
//  frame is handed over before the real frame, so we put the records of the
//  real frame aside and restore them after the interpolated frame's flip.
// ----------------------------------------------------------------------------

static const DWORD HD_REC_SIZE = 0x5C;
static const DWORD HD_SAVE_CAP = 4000 * HD_REC_SIZE;   // the lists themselves hold 1000
static BYTE   g_hdSave[HD_SAVE_CAP];
static DWORD  g_hdSaveLen  = 0;
static DWORD  g_hdSaveWide = 0;
static bool   g_hdWarned   = false;

static bool HdRecordsFit()
{
    DWORD* cur = G<DWORD*>(Addr::HdListLogic);
    DWORD* nxt = G<DWORD*>(Addr::HdListRender);
    if (!cur || !nxt || !cur[0] || !nxt[0]) return false;
    DWORD n = cur[1] - cur[0];
    return n <= HD_SAVE_CAP && (nxt[2] - nxt[0]) >= n;
}

static void HdStashReal()
{
    DWORD* v = G<DWORD*>(Addr::HdListLogic);
    DWORD n = v[1] - v[0];
    if (n) memcpy(g_hdSave, (void*)(uintptr_t)v[0], n);
    g_hdSaveLen = n;
    v[1] = v[0];                                   // interpolated frame starts at record 1

    g_hdSaveWide = G<DWORD>(Addr::WidescreenOfs);
    G<DWORD>(Addr::WidescreenOfs) = 0x42700000;     // 60.0f, as right after a flip
}

static void HdRestoreReal()
{
    DWORD* v = G<DWORD*>(Addr::HdListLogic);       // after the flip: the empty list
    if (v && (v[2] - v[0]) >= g_hdSaveLen) {
        if (g_hdSaveLen) memcpy((void*)(uintptr_t)v[0], g_hdSave, g_hdSaveLen);
        v[1] = v[0] + g_hdSaveLen;
    } else if (!g_hdWarned) {
        g_hdWarned = true;
        Log("Warning: the HD records of the real frame do not fit back (%lu bytes).", g_hdSaveLen);
    }
    G<DWORD>(Addr::WidescreenOfs) = g_hdSaveWide;
}

// ----------------------------------------------------------------------------
//  Drawing the interpolated frame, and the hook
// ----------------------------------------------------------------------------

// Draws an interpolated frame between tick 'a' and tick 'b' into the other draw buffer.
static volatile bool g_fixStrips = false;      // pixel art mode (display mode 1): see FixSolidStrips
static void FixSolidStrips(BYTE* db);

static BYTE* DrawTween(const TickSnap& a, const TickSnap& b)
{
    const bool first = VERBOSE && g_tween.framesDone == 0;
    if (first)
        Log("First interpolated frame (TweenAlpha=%.2f, %d draw steps):", g_tween.alpha, g_tween.opCount);

    float t = g_tween.alpha;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    int t16 = (int)(t * 65536.0f);

    g_phase = "interpolated frame: switching buffer";
    WaitFrameConsumed();                 // the other buffer may still hold the previous real frame
    BYTE* db = SwapDrawBuffer();

    g_phase = "interpolated frame: interpolating state";
    SaveTweenState();
    ApplyTweenState(a, b, t16);

    g_phase = "interpolated frame: draw steps";
    g_inTween = true;
    const bool complete = RunTweenOps(first);
    if (complete && g_fixStrips) FixSolidStrips(db);
    g_inTween = false;

    g_phase = "interpolated frame: restoring state";
    RestoreTweenState();
    if (!complete)
        return nullptr;                  // packet buffer full: do not show this frame

    ++g_tween.framesDone;
    if (first)
        Log("First interpolated frame drawn.");
    if (VERBOSE && (g_tween.framesDone == 600 || (g_tween.framesDone % 36000) == 0))
        Log("Interpolated frames: %u (skipped during interpolated frames: 'mark dirty' %ld, CD ticks %ld)",
            g_tween.framesDone, g_markDirtySkipped, g_cdTickSkipped);
    return db;
}

// Replaces the call of Field_EndFrame in Field_MainLoop.
// ----------------------------------------------------------------------------
//  Solid-color strips in pixel art mode
//
//  The PS1 game draws some big flat areas (such as the black void around
//  walkways) as textured polygons whose uv coordinates all lie on one row (or
//  column) of texels of a single color, e.g. tpage 0012 row 93, u 240-247 in
//  black, with a white row just above it. The PS1 GPU samples exactly that row.
//  The port's PS1-texture renderer (only used in pixel art mode) samples with
//  a little rounding error, so here and there it picks the neighbouring row,
//  which shows up as white or grey speckles. For such polygons the uv
//  coordinates are moved to a texel of the same color whose neighbours all
//  have that color too, so the rounding no longer matters.
// ----------------------------------------------------------------------------

static WORD TexelColor(const WORD* vram, WORD tpage, WORD clut, int u, int v)
{
    const int bx = (tpage & 15) * 64, by = ((tpage >> 4) & 1) * 256, bpp = (tpage >> 7) & 3;
    const int y = (by + (v & 255)) & 511;
    u &= 255;
    if (bpp == 0) {
        const WORD hw = vram[y * 1024 + ((bx + u / 4) & 1023)];
        const int idx = (hw >> ((u & 3) * 4)) & 15;
        return vram[((clut >> 6) & 511) * 1024 + (((clut & 63) * 16 + idx) & 1023)];
    }
    if (bpp == 1) {
        const WORD hw = vram[y * 1024 + ((bx + u / 2) & 1023)];
        const int idx = (hw >> ((u & 1) * 8)) & 255;
        return vram[((clut >> 6) & 511) * 1024 + (((clut & 63) * 16 + idx) & 1023)];
    }
    return vram[y * 1024 + ((bx + u) & 1023)];
}

// True if the texels in [u0,u1] x [v0,v1] all have color c.
static bool TexelsAre(const WORD* vram, WORD tpage, WORD clut, int u0, int u1, int v0, int v1, WORD c)
{
    if (u0 < 0 || v0 < 0 || u1 > 255 || v1 > 255) return false;
    for (int v = v0; v <= v1; ++v)
        for (int u = u0; u <= u1; ++u)
            if (TexelColor(vram, tpage, clut, u, v) != c) return false;
    return true;
}

// Search results per strip (texture page, CLUT, uv range), so the search runs
// once instead of every frame. A result is checked again before every use
// (9 texels), so a change in video memory (another map) is noticed; a strip
// for which nothing was found is searched again after STRIP_RETRY field ticks.
struct StripCache { DWORD key1, key2; bool used, found; BYTE fu, fv; unsigned tick; };
static StripCache   g_stripCache[256];
static const unsigned STRIP_RETRY = 300;       // about 10 seconds

static bool FindSafeTexel(const WORD* vram, WORD tpage, WORD clut, int u0, int v0, WORD c, int* fu, int* fv)
{
    for (int r = 0; r <= 48; ++r)
        for (int dv = -r; dv <= r; ++dv)
            for (int du = -r; du <= r; ++du) {
                if (du != -r && du != r && dv != -r && dv != r) continue;   // ring only
                const int cu = u0 + du, cv = v0 + dv;
                if (cu < 1 || cv < 1 || cu > 254 || cv > 254) continue;
                if (TexelsAre(vram, tpage, clut, cu - 1, cu + 1, cv - 1, cv + 1, c)) {
                    *fu = cu; *fv = cv;
                    return true;
                }
            }
    return false;
}

static void FixSolidStrips(BYTE* db)
{
    const WORD* vram = G<const WORD*>(0x0063F884);
    if (!db || !vram) return;
    const DWORD otA = (DWORD)(uintptr_t)(db + DB_OT), otB = otA + DB_OT_SIZE * 8;
    for (DWORD e = otA; e < otB; e += 8) {
        DWORD p = *(DWORD*)(uintptr_t)e;
        for (int guard = 0; guard < 20000 && p != 0xFFFFFFFF && !(p >= otA && p < otB); ++guard) {
            BYTE* q = (BYTE*)(uintptr_t)p;
            const BYTE code = q[0x0B];
            if (q[7] >= 6 && (code & 0xE4) == 0x24) {          // textured polygon
                const int stride = (code & 0x10) ? 12 : 8;     // gouraud: color per vertex
                const int nv = (code & 0x08) ? 4 : 3;
                const WORD clut  = *(const WORD*)(q + 0x10 + 2);
                const WORD tpage = *(const WORD*)(q + 0x10 + stride + 2);
                int u0 = 255, u1 = 0, v0 = 255, v1 = 0;
                for (int k = 0; k < nv; ++k) {
                    const BYTE u = q[0x10 + k * stride], v = q[0x10 + k * stride + 1];
                    if (u < u0) u0 = u; if (u > u1) u1 = u;
                    if (v < v0) v0 = v; if (v > v1) v1 = v;
                }
                const bool strip = (v0 == v1 && u1 - u0 <= 32) || (u0 == u1 && v1 - v0 <= 32);
                if (strip) {
                    const WORD c = TexelColor(vram, tpage, clut, u0, v0);
                    if (TexelsAre(vram, tpage, clut, u0, u1, v0, v1, c) &&
                        !TexelsAre(vram, tpage, clut, u0 - 1, u1 + 1, v0 - 1, v1 + 1, c)) {
                        // A texel of color c with 8 neighbours of color c, near the strip (cached).
                        const DWORD key1 = ((DWORD)tpage << 16) | clut;
                        const DWORD key2 = ((DWORD)u0 << 24) | ((DWORD)u1 << 16) | ((DWORD)v0 << 8) | (DWORD)v1;
                        StripCache& sc = g_stripCache[(key1 * 2654435761u ^ key2 * 40503u) >> 24];
                        const bool same = sc.used && sc.key1 == key1 && sc.key2 == key2;
                        bool found = false;
                        int fu = 0, fv = 0;
                        if (same && sc.found &&
                            TexelsAre(vram, tpage, clut, sc.fu - 1, sc.fu + 1, sc.fv - 1, sc.fv + 1, c)) {
                            found = true; fu = sc.fu; fv = sc.fv;                 // still valid
                        } else if (same && !sc.found && g_hookSeq - sc.tick < STRIP_RETRY) {
                            found = false;                                       // nothing there, not yet retrying
                        } else {
                            found = FindSafeTexel(vram, tpage, clut, u0, v0, c, &fu, &fv);
                            sc.used = true; sc.key1 = key1; sc.key2 = key2; sc.found = found;
                            sc.fu = (BYTE)fu; sc.fv = (BYTE)fv; sc.tick = g_hookSeq;
                        }
                        if (found)
                            for (int k = 0; k < nv; ++k) {
                                q[0x10 + k * stride]     = (BYTE)fu;
                                q[0x10 + k * stride + 1] = (BYTE)fv;
                            }
                    }
                }
            }
            p = *(const DWORD*)q;
        }
    }
}

#ifdef GA_DIAG
static volatile bool g_dumpRequest = false;   // F4: dump video memory and the big textured prims
static void DiagDumpField();
#endif

// ----------------------------------------------------------------------------
//  Party sprites that changed after the real frame
//
//  The interpolated frame is drawn at the end of the tick, after the rest of
//  the tick's logic. When an event changes the party in that part (for example
//  a member who leaves), FUN_00470ee0 can find a sprite set or frame number
//  that no longer belongs together. The part count it then reads is garbage
//  (thousands), and the loop writes packets past the end of the packet buffer
//  and part records over the game's data, until it crashes (seen at
//  0x4712ca). The game itself never draws in that state: the next tick first
//  sorts things out. So before an interpolated frame, the same values are read
//  here; if they do not fit, this tick shows only the real frame.
// ----------------------------------------------------------------------------

// Can n bytes at p be read? Tried with a structured exception handler (one
// byte per 4 KB page plus the last byte). The crash logger ignores exceptions
// of the probing thread, so a failed probe does not show up as a crash.
static volatile DWORD g_probeThread = 0;

static bool Readable(const void* p, DWORD n)
{
    if (!p)
        return false;
    const volatile BYTE* b = (const volatile BYTE*)p;
    bool ok = true;
    g_probeThread = GetCurrentThreadId();
    __try {
        for (DWORD i = 0; i < n; i += 0x1000)
            (void)b[i];
        if (n)
            (void)b[n - 1];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    g_probeThread = 0;
    return ok;
}

// Returns nullptr if FUN_00470ee0 can safely draw the party now, else the reason.
static const char* PartySpritesProblem(const TickSnap& s)
{
    // The checks at the start of FUN_00470ee0: nothing is drawn
    if (G<BYTE>(Addr::Flag_0071CD38) >= 3 || G<BYTE>(0x00713F3C) != 0 || G<BYTE>(0x00713F5C) == 0
        || (G<BYTE>(0x0071A6E4) & 1) != 0)
        return nullptr;
    BYTE* party = G<BYTE*>(Addr::PartyTable);
    if (!party)
        return "no party table";
    const bool fromTables = G<WORD>(SPR_MODE) < 3;
    int total = 0;
    for (int i = 0; i < NUM_PARTY; ++i) {
        const BYTE* e = party + i * PARTY_STRIDE;
        if (e[1] == 0 || (e[0] & 0x43) != 3 || (e[0] & 0x20) != 0 || (e[0x1C] & 1) != 0
            || (signed char)e[6] < 0)
            continue;                                   // this member is not drawn
        int count;
        if (fromTables) {
            const BYTE  set    = e[0x15];
            const DWORD frames = G<DWORD>(SPR_FRAME_TABLES + 4 * set);
            const DWORD parts  = G<DWORD>(SPR_PART_TABLES  + 4 * set);
            if (set != s.sprSet[i] || frames != s.sprTab[i][0] || parts != s.sprTab[i][1])
                return "sprite set changed";
            const BYTE* f = (const BYTE*)(uintptr_t)frames + 4 * (*(const WORD*)(e + 0x1E) & 0x3FFF);
            if (!Readable(f, 4))
                return "frame outside the table";
            const int first = *(const WORD*)f;
            count = *(const WORD*)(f + 2);
            if (count > SPR_MAX_PARTS)
                return "too many sprite parts";
            if (count > 0 && !Readable((const BYTE*)(uintptr_t)parts + 16 * first, 16 * count))
                return "parts outside the table";
        } else {
            count = *(const WORD*)VA(SPR_SLOTS + 10 * i + 4);
        }
        total += count;
    }
    return total > SPR_MAX_PARTS ? "too many sprite parts" : nullptr;
}

static void __cdecl Hook_Field_EndFrame()
{
    g_tween.compassThisTick = g_compassDrawn;
    g_compassDrawn = false;
    const unsigned seq = ++g_hookSeq;
    if (g_fixStrips) FixSolidStrips(G<BYTE*>(Addr::g_cdb));   // pixel art mode: the real frame

    static int s_encounterLogs = 0;
    static bool s_inEncounter = false;
    const bool encounter = G<BYTE>(Addr::EncounterState) != 0;
    if (VERBOSE && encounter && !s_inEncounter && g_tween.enabled && s_encounterLogs < 3) {
        ++s_encounterLogs;
        Log("Field: battle transition - real frames only until the battle starts.");
    }
    s_inEncounter = encounter;
#ifdef GA_DIAG
    if (g_dumpRequest) { g_dumpRequest = false; DiagDumpField(); }
#endif

    const int frameMode = g_frameMode;
    if (!g_tween.enabled
        || frameMode == FM_ORIGINAL
        || G<int>(Addr::FieldState) != 1
        || G<int>(Addr::SkipExtraWait) != 0
        || encounter                             // battle transition: its animation lives in draw step 1
        || G<BYTE*>(Addr::PacketHeap) == nullptr
        || !g_drawSnapTaken)
    {
        g_prevSnap.valid = false;
        g_camSnapTaken = g_drawSnapTaken = false;
        s_Field_EndFrame();     // original behaviour (menus, cutscenes, 60 fps states)
        return;
    }

    g_logicThreadId = GetCurrentThreadId();

    g_curSnap = g_drawSnap;                      // state at the draw moment of the real frame
    g_camSnapTaken = g_drawSnapTaken = false;
    g_curSnap.seq   = seq;
    g_curSnap.valid = true;
    const bool canTween = g_prevSnap.valid && g_prevSnap.seq + 1 == seq;

    g_phase = "CdEmu_Tick";
    s_CdEmu_Tick();                              // as in the original

    BYTE* realDb = G<BYTE*>(Addr::g_cdb);        // drawn by Field_Tick

    if (frameMode == FM_DOUBLE) {
        // One real frame per vblank: the game logic runs at 60 ticks per second.
        g_phase = "handing over real frame (double speed)";
        FlipBuffer(realDb);
        g_prevSnap = g_curSnap;
        g_phase = "outside the hook";
        return;
    }

    // Party changed after the real frame (see PartySpritesProblem): real frame only.
    const char* sprProblem = canTween ? PartySpritesProblem(g_curSnap) : nullptr;
    if (sprProblem) {
        static int s_sprLogs = 0;
        if (s_sprLogs < 5) {
            ++s_sprLogs;
            Log("Field: party sprites changed after the real frame (%s) - real frame only for this tick.", sprProblem);
        }
    }

    BYTE* tweenDb = nullptr;
    if (canTween && !sprProblem && HdRecordsFit()) {
        HdStashReal();                           // put the real frame's HD records aside
        tweenDb = DrawTween(g_prevSnap, g_curSnap);
        if (!tweenDb) {                          // packet buffer full: the interpolated frame is dropped
            HdRestoreReal();
            G<BYTE*>(Addr::g_cdb) = realDb;
        }
    }

    if (!tweenDb) {
        // No interpolated frame (e.g. the first tick in the field): only the real frame.
        g_phase = "handing over real frame";
        FlipBuffer(realDb);
        WaitFrameConsumed();
        WaitNextVBlank();
    } else {
        g_phase = "handing over interpolated frame";
        FlipBuffer(tweenDb);                     // first the interpolated frame
        HdRestoreReal();                         // records back into the (now empty) logic list
        G<BYTE*>(Addr::g_cdb) = realDb;          // Field_MainLoop will switch to the other buffer
        g_phase = "handing over real frame";
        FlipBuffer(realDb);                      // then the real frame
    }

    g_prevSnap = g_curSnap;
    g_phase = "outside the hook";
}

// ============================================================================
//  PART 1b: FRAME INTERPOLATION IN BATTLE  ([Interpolation] Battle=1)
//
//  The battle main loop FUN_00491eb0 does per tick:
//      FUN_00498c20   battle tick: logic, then drawing
//      FUN_004927f0   extra drawing, then depth sort + linking into the OT
//      wait 2 vblanks, flip (FUN_00419c20 at 0x4924d2)
//  Inside FUN_00498c20 the drawing part is:
//      FUN_00499100            camera matrix (fixed angles, zoom = work+0x04)
//      FUN_00537830            project the camera target (work+0x08, work+0x10)
//      FUN_004994f0            sky / background model
//      FUN_00499100            camera matrix again
//      (FUN_0052da20 per object: logic, not repeated)
//      FUN_0052f500            collect object positions (+0x64/+0x68/+0x6c)
//      FUN_00537830            project them (work+0xb5f8 -> work+0xcdf8)
//      FUN_0052f990, FUN_0052fc70   draw the objects
//  The battle work area is *DAT_006d1a98. Battle draw buffers are at 0x713cc0
//  and 0x713d54 (current one in DAT_00713c64): +0x00 packet cursor, +0x04 OT
//  (4 entries of 8 bytes), +0x24 DRAWENV, +0x80 DISPENV.
//
//  Like in the field, the interpolated frame lies between the previous and the
//  current tick and is shown before the real frame.
// ============================================================================

namespace BAddr {
    const DWORD CurDB        = 0x00713C64;
    const DWORD DB0          = 0x00713CC0;
    const DWORD DB1          = 0x00713D54;
    const DWORD SortCount    = 0x00713C60;
    const DWORD SortListPtr  = 0x0063FB00;
    const DWORD Work         = 0x006D1A98;
    const DWORD PointCount   = 0x0070F118;
    const DWORD CallFlip     = 0x004924D2;   // CALL FUN_00419c20 in the battle loop
    const DWORD CallCamera   = 0x00498DD8;   // CALL FUN_00499100 (first)
    const DWORD CallCollect  = 0x00498F69;   // CALL FUN_0052f500
    const DWORD CallTasks    = 0x00498DD3;   // CALL FUN_00496a60 (task runner)
    const DWORD TaskRunner   = 0x00496A60;
    const DWORD RingCursor   = 0x006D2DB8;   // ring buffer for text prims (start in 0x6d2dbc)
    const DWORD SecondWait   = 0x0049245B;   // add eax,1 (second vblank wait)
    const DWORD CamMatrix    = 0x00499100;
    const DWORD Project      = 0x00537830;
    const DWORD DrawSky      = 0x004994F0;
    const DWORD Collect      = 0x0052F500;
    const DWORD DrawObjA     = 0x0052F990;
    const DWORD DrawObjB     = 0x0052FC70;
    const DWORD PostDraw     = 0x004927F0;
}

#ifdef GA_DIAG
static long g_bLastPk[64];      // diagnostic build: packet bytes per battle call site, last tick
static long g_bLastSort = 0;
static void LogRealTickSites();
#endif

struct ObjTable { DWORD addr; int count; };
static const ObjTable BATTLE_TABLES[] = {
    { 0x0070F8E0, 248 }, { 0x007117E0, 8 }, { 0x00711FA0, 16 }, { 0x00712760, 32 },
};
static const int BNUM_OBJ = 248 + 8 + 16 + 32;

struct BattleSnap {
    bool     valid;
    unsigned seq;
    int      cam[3];                 // work+0x04 (zoom), +0x08, +0x10 (camera target)
    BYTE*    obj[BNUM_OBJ];
    int      pos[BNUM_OBJ][3];       // object +0x64, +0x68, +0x6c
};

static BattleSnap g_bPrev, g_bCur, g_bDraw;
static BattleSnap g_bPrev2;                     // two ticks back: to recognise objects that toggle
static bool       g_bCamTaken = false, g_bObjTaken = false;
static bool       g_bEnabled  = false;
static float      g_bAlpha    = 0.5f;
static unsigned   g_bSeq      = 0;
static unsigned   g_bFrames   = 0;
static DWORD      g_bCamTarget = 0, g_bCollectTarget = 0;

static VoidFn_t s_BCamMatrix, s_BDrawSky, s_BCollect, s_BDrawObjA, s_BDrawObjB, s_BPostDraw;
static void*    s_BProject;

static BYTE* BWork() { return G<BYTE*>(BAddr::Work); }

static void BSnapCam(BattleSnap& s)
{
    BYTE* w = BWork();
    s.cam[0] = w ? *(int*)(w + 0x04) : 0;
    s.cam[1] = w ? *(int*)(w + 0x08) : 0;
    s.cam[2] = w ? *(int*)(w + 0x10) : 0;
}

static void BSnapObjects(BattleSnap& s)
{
    int n = 0;
    for (const ObjTable& t : BATTLE_TABLES)
        for (int i = 0; i < t.count; ++i, ++n) {
            BYTE* e = VA(t.addr + i * 8);
            BYTE* o = (e[0] != 0) ? *(BYTE**)(e + 4) : nullptr;
            s.obj[n] = o;
            for (int k = 0; k < 3; ++k) s.pos[n][k] = o ? *(int*)(o + 0x64 + 4 * k) : 0;
        }
}

#ifdef GA_DIAG
enum { CK_CAM, CK_SKY, CK_COLLECT, CK_OBJA, CK_OBJB, CK_AFTER, CK_N };
static void BChkCapture(int k);
#endif

static void __cdecl OnBattleCamera()
{
#ifdef GA_DIAG
    BChkCapture(CK_CAM);
#endif
    BSnapCam(g_bDraw);
    g_bCamTaken = true;
}
static void BCaptureDrawStart();
static void __cdecl OnBattleCollect()
{
#ifdef GA_DIAG
    BChkCapture(CK_COLLECT);
#endif
    BSnapObjects(g_bDraw);
    g_bObjTaken = g_bCamTaken;
    if (g_bObjTaken) BCaptureDrawStart();
}

static __declspec(naked) void Stub_BattleCamera() { __asm {
    pushad
    pushfd
    call OnBattleCamera
    popfd
    popad
    jmp dword ptr [g_bCamTarget]
} }

static __declspec(naked) void Stub_BattleCollect() { __asm {
    pushad
    pushfd
    call OnBattleCollect
    popfd
    popad
    jmp dword ptr [g_bCollectTarget]
} }

// ---- battle state: draw-start copy (D) and end-of-tick copy (E) ----
//
//  The interpolated frame must start from exactly the state the real frame was
//  drawn from, not from the state at the end of the tick. So at the draw moment
//  (0x498f69, before FUN_0052f500) we copy the battle work area and the battle
//  globals (D). For the interpolated frame we save the current state (E), load
//  D, interpolate camera and positions, draw, and put E back.
struct BRange { DWORD addr; DWORD len; };
static const BRange BSTATE_RANGES[] = {
    { 0x0070F000, 0x00713C60 - 0x0070F000 },   // battle globals, object tables, camera matrix
    { 0x00713DF0, 0x00714000 - 0x00713DF0 },   // (skips sort count, current DB, pad, draw buffers)
    { 0x00640A80, 0x50 },                      // battle camera angles / mode
    { 0x00640C40, 0x160 },                     // GTE registers
    { 0x006D2E00, 0x100 },                     // battle draw scratch values
    { 0x00618A24, 0x04 },                      // counter in FUN_004927f0
};
static const DWORD BSTATE_GLOBALS_LEN = 0x6000;
static const DWORD BWORK_LEN = 0x27F00;              // work area up to the sort list
static const DWORD BOBJ_SAVE_OFS = 0x60, BOBJ_SAVE_LEN = 0x34;

struct BState {
    BYTE  globals[BSTATE_GLOBALS_LEN];
    BYTE  work[BWORK_LEN];
    BYTE* objPtr[BNUM_OBJ];
    BYTE  obj[BNUM_OBJ][BOBJ_SAVE_LEN];
};
static BState g_bD, g_bE;
static void BCaptureDrawStart();

static void BCapture(BState& st)
{
    BYTE* p = st.globals;
    for (const BRange& r : BSTATE_RANGES) { memcpy(p, VA(r.addr), r.len); p += r.len; }
    memcpy(st.work, BWork(), BWORK_LEN);
    BattleSnap tmp;
    BSnapObjects(tmp);
    for (int i = 0; i < BNUM_OBJ; ++i) {
        st.objPtr[i] = tmp.obj[i];
        if (tmp.obj[i]) memcpy(st.obj[i], tmp.obj[i] + BOBJ_SAVE_OFS, BOBJ_SAVE_LEN);
    }
}

static void BLoad(const BState& st)
{
    const BYTE* p = st.globals;
    for (const BRange& r : BSTATE_RANGES) { memcpy(VA(r.addr), p, r.len); p += r.len; }
    memcpy(BWork(), st.work, BWORK_LEN);
    for (int i = 0; i < BNUM_OBJ; ++i)
        if (st.objPtr[i]) memcpy(st.objPtr[i] + BOBJ_SAVE_OFS, st.obj[i], BOBJ_SAVE_LEN);
}

static void BCaptureDrawStart() { BCapture(g_bD); }

#ifdef GA_DIAG
// ---- Checkpoint comparison (diagnostic build) ----
//  Now and then, the real battle tick copies the complete battle state at six
//  points of its drawing part. The interpolated frame that follows compares
//  its own state with those copies at the same six points, and compares its
//  object packets and depth-sort entries with those of the real frame. With
//  BattleTweenAlpha=1.0 both should be identical; the log shows where they are not.
static const char* const CK_NAME[CK_N] = {
    "before camera (0x498dd8)", "before sky (0x498e64)", "before collect (0x498f69)",
    "before objects A (0x498fb5)", "before objects B (0x498fba)", "after objects B (0x498fbf)",
};
static const DWORD CK_WORK_LEN = 0x163A00;         // whole battle work area
static const DWORD CK_PK_FROM  = 0x27F00;           // sort list and both packet areas...
static const DWORD CK_PK_TO    = 0x3AF00;           // ...are not compared as state
static const DWORD CK_OBJ_LEN  = 0x200;
static const int   CK_MAX_REPORTS = 6;

struct BCheck {
    bool  taken;
    DWORD pk, pkBase;
    BYTE* glob;
    BYTE* work;
    BYTE* obj;
    BYTE* objPtr[BNUM_OBJ];
};
static BCheck        g_ck[CK_N];
static volatile bool g_ckArmed = false;
static bool          g_ckReady = false;
static int           g_ckReports = 0, g_ckCountdown = 0;
static BYTE          g_ckPk[0x10000];
static long          g_ckPkLen = 0;
static BYTE          g_ckSort[0x4000];
static long          g_ckSortN = 0;
static BattleSnap    g_ckObjs;

static bool BChkInWork(const BYTE* p)
{
    BYTE* w = BWork();
    return w && p >= w && p < w + CK_WORK_LEN;
}

static bool BChkSafeCopy(BYTE* dst, const BYTE* src, DWORD len)
{
    __try { memcpy(dst, src, len); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { memset(dst, 0, len); return false; }
}

static bool BChkAlloc()
{
    const DWORD one = BSTATE_GLOBALS_LEN + CK_WORK_LEN + BNUM_OBJ * CK_OBJ_LEN;
    BYTE* m = (BYTE*)VirtualAlloc(nullptr, one * CK_N, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) return false;
    for (int k = 0; k < CK_N; ++k) {
        g_ck[k].glob = m;                       m += BSTATE_GLOBALS_LEN;
        g_ck[k].work = m;                       m += CK_WORK_LEN;
        g_ck[k].obj  = m;                       m += BNUM_OBJ * CK_OBJ_LEN;
    }
    return true;
}

static DWORD BChkCursor()
{
    BYTE* db = G<BYTE*>(BAddr::CurDB);
    return db ? *(DWORD*)db : 0;
}

static DWORD BChkPkBase()
{
    BYTE* db = G<BYTE*>(BAddr::CurDB);
    return (DWORD)(uintptr_t)(BWork() + (db == VA(BAddr::DB0) ? 0x2BF00 : 0x33700));
}

// Called in the real battle tick (never in the interpolated frame)
static void BChkCapture(int k)
{
    if (!g_ckArmed || g_inTween || !g_ck[0].work) return;
    BYTE* w = BWork();
    if (!w) return;
    BCheck& c = g_ck[k];
    BYTE* p = c.glob;
    for (const BRange& r : BSTATE_RANGES) { memcpy(p, VA(r.addr), r.len); p += r.len; }
    memcpy(c.work, w, CK_WORK_LEN);
    BSnapObjects(g_ckObjs);
    for (int i = 0; i < BNUM_OBJ; ++i) {
        c.objPtr[i] = g_ckObjs.obj[i];
        if (c.objPtr[i] && !BChkInWork(c.objPtr[i]))
            BChkSafeCopy(c.obj + i * CK_OBJ_LEN, c.objPtr[i], CK_OBJ_LEN);
    }
    c.pk     = BChkCursor();
    c.pkBase = BChkPkBase();
    c.taken  = true;
    if (k == CK_AFTER && g_ck[CK_OBJB].taken) {
        long n = (long)(c.pk - g_ck[CK_OBJB].pk);
        g_ckPkLen = (n < 0) ? 0 : (n > (long)sizeof(g_ckPk) ? (long)sizeof(g_ckPk) : n);
        if (g_ckPkLen) memcpy(g_ckPk, (void*)(uintptr_t)g_ck[CK_OBJB].pk, g_ckPkLen);
        g_ckSortN = G<int>(BAddr::SortCount);
        if (g_ckSortN > (long)sizeof(g_ckSort) / 8) g_ckSortN = sizeof(g_ckSort) / 8;
        if (g_ckSortN > 0) memcpy(g_ckSort, G<BYTE*>(BAddr::SortListPtr), g_ckSortN * 8);
    }
}

static void BChkHex(char* out, const BYTE* p, DWORD n)
{
    char* o = out;
    for (DWORD i = 0; i < n; ++i) o += _snprintf_s(o, 4, _TRUNCATE, "%02X%s", p[i], (i % 4 == 3 && i + 1 < n) ? " " : "");
    *o = 0;
}

static void BChkDiff(const char* label, DWORD base, const BYTE* real, const BYTE* now, DWORD len,
                     int& budget, long& total)
{
    DWORD i = 0;
    while (i < len) {
        if ((i & 63) == 0 && i + 64 <= len && memcmp(real + i, now + i, 64) == 0) { i += 64; continue; }
        if (real[i] == now[i]) { ++i; continue; }
        DWORD s = i, last = i;
        long cnt = 0;
        while (i < len && i - last <= 8) { if (real[i] != now[i]) { last = i; ++cnt; } ++i; }
        total += cnt;
        if (budget > 0) {
            --budget;
            DWORD n = last - s + 1, shown = n > 16 ? 16 : n;
            char a[64] = "", b[64] = "";
            BChkHex(a, real + s, shown);
            BChkHex(b, now + s, shown);
            if (label) Log("      %s+%05lX (%lu bytes): real %s | interpolated %s%s", label, s + base, n, a, b, n > shown ? " ..." : "");
            else       Log("      %08lX (%lu bytes): real %s | interpolated %s%s", s + base, n, a, b, n > shown ? " ..." : "");
        }
        i = last + 1;
    }
}

// Called in the interpolated frame at the same point as checkpoint k
static void BChkCompare(int k)
{
    if (!g_ckReady) return;
    const BCheck& c = g_ck[k];
    if (!c.taken) { Log("   -- %s: not captured --", CK_NAME[k]); return; }
    BYTE* w = BWork();
    int budget = 16;
    long total = 0;
    const BYTE* p = c.glob;
    for (const BRange& r : BSTATE_RANGES) { BChkDiff(nullptr, r.addr, p, VA(r.addr), r.len, budget, total); p += r.len; }
    BChkDiff("work", 0, c.work, w, CK_PK_FROM, budget, total);
    BChkDiff("work", CK_PK_TO, c.work + CK_PK_TO, w + CK_PK_TO, CK_WORK_LEN - CK_PK_TO, budget, total);
    BSnapObjects(g_ckObjs);
    static BYTE tmp[CK_OBJ_LEN];
    int objMoved = 0;
    for (int i = 0; i < BNUM_OBJ; ++i) {
        if (c.objPtr[i] != g_ckObjs.obj[i]) { ++objMoved; continue; }
        if (!c.objPtr[i] || BChkInWork(c.objPtr[i])) continue;
        BChkSafeCopy(tmp, c.objPtr[i], CK_OBJ_LEN);
        char label[16];
        _snprintf_s(label, sizeof(label), _TRUNCATE, "obj%d", i);
        BChkDiff(label, 0, c.obj + i * CK_OBJ_LEN, tmp, CK_OBJ_LEN, budget, total);
    }
    Log("   -- %s: %ld bytes differ%s; %d object slots differ --", CK_NAME[k], total,
        budget <= 0 ? " (first 16 runs shown above)" : "", objMoved);
}

static DWORD BChkNorm(DWORD v, DWORD base)
{
    if (v >= base && v < base + 0x7800) return 0xA0000000u + (v - base);
    DWORD lo = v & 0xFFFFFF, b = base & 0xFFFFFF;          // tag word: size << 24 | address
    if (lo >= b && lo < b + 0x7800) return (v & 0xFF000000u) | 0x00A00000u | (lo - b);
    return v;
}

// Objects B: packets and depth-sort entries of the interpolated frame vs the real frame
static void BChkComparePackets(DWORD twStart, DWORD twEnd, DWORD twBase)
{
    if (!g_ckReady) return;
    long twLen = (long)(twEnd - twStart);
    long n = (twLen < g_ckPkLen ? twLen : g_ckPkLen) / 4;
    const DWORD* r = (const DWORD*)g_ckPk;
    const DWORD* t = (const DWORD*)(uintptr_t)twStart;
    DWORD realBase = g_ck[CK_AFTER].pkBase;
    long diff = 0, shown = 0;
    for (long i = 0; i < n; ++i) {
        DWORD a = BChkNorm(r[i], realBase), b = BChkNorm(t[i], twBase);
        if (a == b) continue;
        ++diff;
        if (shown < 24) { ++shown; Log("      packet +%04lX: real %08lX | interpolated %08lX", i * 4, a, b); }
    }
    Log("   -- objects B packets: real %ld bytes, interpolated %ld bytes; %ld of %ld dwords differ "
        "(pointers into the packet area shown as A0000000+offset, tags as xxA0....) --", g_ckPkLen, twLen, diff, n);

    long twSortN = G<int>(BAddr::SortCount);
    const DWORD* ts = G<const DWORD*>(BAddr::SortListPtr);
    Log("   -- depth-sort entries: real %ld, interpolated %ld (key, prim) --", g_ckSortN, twSortN);
    long m = g_ckSortN > twSortN ? g_ckSortN : twSortN;
    if (m > 48) m = 48;
    const DWORD* rs = (const DWORD*)g_ckSort;
    for (long i = 0; i < m; ++i) {
        char a[40] = "-", b[40] = "-";
        if (i < g_ckSortN) _snprintf_s(a, sizeof(a), _TRUNCATE, "%08lX %08lX", rs[i * 2], BChkNorm(rs[i * 2 + 1], realBase));
        if (i < twSortN)   _snprintf_s(b, sizeof(b), _TRUNCATE, "%08lX %08lX", ts[i * 2], BChkNorm(ts[i * 2 + 1], twBase));
        Log("      [%2ld] real %-18s | interpolated %s%s", i, a, b, strcmp(a, b) ? "   <>" : "");
    }
}

static void BChkEnvs(BYTE* realDb, BYTE* twDb)
{
    const DWORD* a = (const DWORD*)(realDb + 0x24);
    const DWORD* b = (const DWORD*)(twDb + 0x24);
    Log("   real DB %08lX: DRAWENV %08lX %08lX %08lX %08lX %08lX %08lX, DISPENV %08lX %08lX %08lX %08lX %08lX",
        (DWORD)(uintptr_t)realDb, a[0], a[1], a[2], a[3], a[4], a[5],
        ((DWORD*)(realDb + 0x80))[0], ((DWORD*)(realDb + 0x80))[1], ((DWORD*)(realDb + 0x80))[2],
        ((DWORD*)(realDb + 0x80))[3], ((DWORD*)(realDb + 0x80))[4]);
    Log("   interp. DB %08lX: DRAWENV %08lX %08lX %08lX %08lX %08lX %08lX, DISPENV %08lX %08lX %08lX %08lX %08lX",
        (DWORD)(uintptr_t)twDb, b[0], b[1], b[2], b[3], b[4], b[5],
        ((DWORD*)(twDb + 0x80))[0], ((DWORD*)(twDb + 0x80))[1], ((DWORD*)(twDb + 0x80))[2],
        ((DWORD*)(twDb + 0x80))[3], ((DWORD*)(twDb + 0x80))[4]);
    BYTE* w = BWork();
    int inWork = 0, outside = 0;
    for (int i = 0; i < BNUM_OBJ; ++i) if (g_ckObjs.obj[i]) (BChkInWork(g_ckObjs.obj[i]) ? inWork : outside)++;
    Log("   work area %08lX; active objects: %d inside the work area, %d outside", (DWORD)(uintptr_t)w, inWork, outside);
}
#endif

#ifdef GA_DIAG
// ----------------------------------------------------------------------------
//  HD record appender calls (diagnostic build): every call site of an HD
//  record appender (ECX = prim) goes through a small stub, for the draw origin
//  tracer (F5) and the text watch (F6).
// ----------------------------------------------------------------------------
struct CallSite { DWORD site, target; };
static const CallSite APPEND_CALLS[] = {
    { 0x0040D8B0, 0x004207E0 }, { 0x0040E089, 0x004207E0 }, { 0x00455992, 0x004202D0 },
    { 0x00456E9A, 0x004202D0 }, { 0x00456F72, 0x004202D0 }, { 0x004580B0, 0x004207E0 },
    { 0x0045856A, 0x004207E0 }, { 0x00458679, 0x004207E0 }, { 0x00458734, 0x004207E0 },
    { 0x0045973B, 0x004202D0 }, { 0x004597E8, 0x004202D0 }, { 0x00459E46, 0x004207E0 },
    { 0x00469E51, 0x0041FBE0 }, { 0x0046A177, 0x0041FBE0 }, { 0x0046A5D4, 0x0041FBE0 },
    { 0x0046ABD1, 0x0041FE80 }, { 0x0046B292, 0x0041FBE0 }, { 0x0046B6FE, 0x0041FBE0 },
    { 0x0046BCD6, 0x0041FE80 }, { 0x0046BFA8, 0x0041FBE0 }, { 0x0046C729, 0x0041FBE0 },
    { 0x0046EB5E, 0x004202D0 }, { 0x0046EC23, 0x004202D0 }, { 0x00470BB8, 0x004202D0 },
    { 0x00470C44, 0x004202D0 }, { 0x00471C50, 0x0041FBE0 }, { 0x00471DDD, 0x0041FBE0 },
    { 0x0047B6CC, 0x0041FE80 }, { 0x0047DD79, 0x00421160 }, { 0x00488951, 0x0041F9C0 },
    { 0x00488A5A, 0x00420C50 }, { 0x0048D643, 0x00420C50 }, { 0x0048D896, 0x00420C50 },
    { 0x0048DB3F, 0x00420C50 }, { 0x0048DCAC, 0x0041F9C0 }, { 0x0048DE79, 0x0041F9C0 },
    { 0x0048E376, 0x0041FBE0 }, { 0x0048EA0E, 0x00420EC0 }, { 0x0048EEFE, 0x0041FBE0 },
    { 0x0048F572, 0x00420EC0 }, { 0x00492A4B, 0x004202D0 }, { 0x00492B36, 0x004202D0 },
    { 0x00530BC2, 0x00420A30 }, { 0x00530C61, 0x00420A30 }, { 0x00530EC2, 0x00420560 },
    { 0x00531892, 0x00420560 }, { 0x00532200, 0x00420560 }, { 0x0053238D, 0x00420560 },
    { 0x00532F80, 0x00420A30 }, { 0x00533050, 0x00420560 }, { 0x00534D92, 0x004202D0 },
    { 0x00534FF2, 0x004200A0 }, { 0x00535480, 0x004213A0 }, { 0x00535901, 0x00421160 },
    { 0x00535E47, 0x004202D0 }, { 0x00536D2B, 0x004202D0 }, { 0x00554DC9, 0x00420A30 },
    { 0x005C1113, 0x004202D0 }, { 0x005F3475, 0x00420A30 }, { 0x005F3806, 0x00420560 },
    { 0x005F38D4, 0x00420560 }, { 0x005F4B58, 0x004202D0 }, { 0x005F4BFD, 0x004202D0 },
    { 0x005F6E34, 0x004207E0 }, { 0x005F6E50, 0x004207E0 }, { 0x005F70F7, 0x004202D0 },
};
static const int NUM_ASITES = sizeof(APPEND_CALLS) / sizeof(APPEND_CALLS[0]);

static bool          g_asMoves[NUM_ASITES];      // the appender moves the prim (widescreen offset)
static bool          g_appendHooks = false;

static bool OnStack(DWORD p)
{
    DWORD base  = __readfsdword(4);
    DWORD limit = __readfsdword(8);
    return p >= limit && p + 8 <= base;
}

// 0: memory that is fresh or restored in every frame, 1: prim that stays
static int PrimArea(DWORD p)
{
    const DWORD w = (DWORD)(uintptr_t)BWork();
    if (!w) return 0;
    if (p >= w && p < w + BWORK_LEN)              return 0;   // restored by BLoad
    if (p >= w + 0x2BF00 && p < w + 0x3AF00)     return 0;   // both packet areas
    if (p >= w + 0x134A00 && p < w + 0x13DA00)   return 0;   // ring buffer, reset every loop
    if (OnStack(p))                              return 0;
    return 1;
}

static void __cdecl TraceHit(int idx, DWORD ebp);
static void TwAppend(int idx, DWORD prim, int area);

static void __cdecl OnAppend(int idx, DWORD ebp, DWORD prim)
{
    TraceHit(idx, ebp);
    if (g_asMoves[idx]) TwAppend(idx, prim, PrimArea(prim));
}

static void Emit8 (BYTE*& p, BYTE v)  { *p++ = v; }
static void Emit32(BYTE*& p, DWORD v) { memcpy(p, &v, 4); p += 4; }
static void EmitRel(BYTE*& p, BYTE op, const void* target)
{
    *p++ = op;
    DWORD rel = (DWORD)((uintptr_t)target - ((uintptr_t)p + 4));
    Emit32(p, rel);
}

static void Install_AppendHooks()
{
    if (g_appendHooks) return;
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, NUM_ASITES * 48, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!mem) { Log("Battle interpolation: no memory for the appender hooks."); return; }
    int ok = 0;
    for (int i = 0; i < NUM_ASITES; ++i) {
        switch (APPEND_CALLS[i].target) {
        case 0x0041FBE0: case 0x004200A0: case 0x004202D0: case 0x00420560: case 0x004207E0:
        case 0x00420A30: case 0x00420EC0: case 0x00421160: case 0x004213A0:
            g_asMoves[i] = true; break;
        default:
            g_asMoves[i] = false; break;
        }
        if (!IsCallTo(APPEND_CALLS[i].site, APPEND_CALLS[i].target)) continue;
        BYTE* t = mem + i * 48;
        BYTE* p = t;
        Emit8(p, 0x60); Emit8(p, 0x9C);                       // pushad; pushfd
        Emit8(p, 0x51);                                       // push ecx (prim)
        Emit8(p, 0x55);                                       // push ebp
        Emit8(p, 0x68); Emit32(p, (DWORD)i);                  // push i
        EmitRel(p, 0xE8, (void*)&OnAppend);                   // call OnAppend
        Emit8(p, 0x83); Emit8(p, 0xC4); Emit8(p, 0x0C);       // add esp,12
        Emit8(p, 0x9D); Emit8(p, 0x61);                       // popfd; popad
        EmitRel(p, 0xE9, VA(APPEND_CALLS[i].target));         // jmp target
        if (WriteBranch(VA(APPEND_CALLS[i].site), 0xE8, t, 5)) ++ok;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, NUM_ASITES * 48);
    g_appendHooks = true;
    if (ok != NUM_ASITES) Log("Battle interpolation: %d of %d appender calls hooked.", ok, NUM_ASITES);
}
#endif // GA_DIAG

// ---- Drawing done by the task runner ----
//
// Menus, the victory screens and similar things are drawn by tasks, which the
// task runner FUN_00496a60 (called at 0x498dd3) runs in the logic part of the
// tick. The interpolated frame does not run the logic, so it would miss those
// prims. Instead we take a copy of everything the task runner draws in the
// real tick (packets, links into the ordering table, depth-sort entries and HD
// records) and put that copy at the start of the interpolated frame, with its
// pointers moved to the other draw buffer. Text prims are not in the packet
// buffer but in a ring buffer in the work area (cursor DAT_006d2db8, reset every
// loop at 0x4922c7, end work+0x13da00); what the task runner put there is
// copied to a fresh spot in the ring as well, otherwise both frames would link
// the same prims. The task runner is the first thing
// in the tick that draws, so the copy lands on the same spot as in the real
// frame (HD record numbers and sort keys stay valid).
struct LogicCapture {
    bool  armed, valid;
    int   bad;                       // why the capture is not valid (diagnostics)
    BYTE* db;                        // real draw buffer
    DWORD pkA, pkLen;                // packets drawn by the task runner
    DWORD otBefore[8], otAfter[8];   // OT entries 0..3 (8 bytes each)
    DWORD sortA, sortN;
    DWORD hdA, hdLen;                // HD records (bytes)
    DWORD rA, rLen;                  // ring buffer (text prims)
    BYTE  pk[0x10000];
    BYTE  ring[0x9000];
    DWORD sort[2 * 1024];
    BYTE  hd[600 * 0x5C];
};
static LogicCapture g_lc[2];
static int          g_lcFill = 0, g_lcUse = 1;
static DWORD        g_taskTarget = 0;
static unsigned     g_lcSkipped = 0, g_lcUsed = 0;
static int          g_lcApplyCode = 0;   // result of the last ApplyLogicCapture (0 = copied)

static DWORD HdBytesNow()
{
    DWORD* v = G<DWORD*>(Addr::HdListLogic);
    return v ? v[1] - v[0] : 0xFFFFFFFF;
}

static void __cdecl OnTaskRunnerBefore()
{
    LogicCapture& c = g_lc[g_lcFill];
    c.armed = c.valid = false;
    c.bad   = 1;
    if (g_inTween) return;
    BYTE* db = G<BYTE*>(BAddr::CurDB);
    if (!db) return;
    c.db    = db;
    c.pkA   = *(DWORD*)db;
    memcpy(c.otBefore, db + 4, sizeof(c.otBefore));
    c.sortA = G<DWORD>(BAddr::SortCount);
    c.hdA   = HdBytesNow();
    c.rA    = G<DWORD>(BAddr::RingCursor);
    c.armed = true;
}

static void __cdecl OnTaskRunnerAfter()
{
    LogicCapture& c = g_lc[g_lcFill];
    if (!c.armed || g_inTween) return;
    c.armed = false;
    BYTE* db = c.db;
    c.bad = 2;
    if (G<BYTE*>(BAddr::CurDB) != db) return;
    c.pkLen = *(DWORD*)db - c.pkA;
    DWORD sortB = G<DWORD>(BAddr::SortCount);
    DWORD hdB   = HdBytesNow();
    DWORD rB    = G<DWORD>(BAddr::RingCursor);
    c.bad = c.pkLen > sizeof(c.pk) ? 3 :
            (sortB < c.sortA || sortB - c.sortA > 1024) ? 4 :
            (hdB < c.hdA || hdB - c.hdA > sizeof(c.hd)) ? 5 :
            (rB < c.rA || rB - c.rA > sizeof(c.ring)) ? 6 : 0;   // 6: the ring wrapped, not copied
    if (c.bad) return;
    c.rLen = rB - c.rA;
    if (c.rLen) memcpy(c.ring, (void*)(uintptr_t)c.rA, c.rLen);
    c.sortN = sortB - c.sortA;
    c.hdLen = hdB - c.hdA;
    if (c.pkLen) memcpy(c.pk, (void*)(uintptr_t)c.pkA, c.pkLen);
    memcpy(c.otAfter, db + 4, sizeof(c.otAfter));
    if (c.sortN) memcpy(c.sort, G<BYTE*>(BAddr::SortListPtr) + c.sortA * 8, c.sortN * 8);
    if (c.hdLen) {
        DWORD* v = G<DWORD*>(Addr::HdListLogic);
        memcpy(c.hd, (void*)(uintptr_t)(v[0] + c.hdA), c.hdLen);
    }
    c.valid = true;
}

static __declspec(naked) void Stub_TaskRunner() { __asm {
    pushad
    call OnTaskRunnerBefore
    popad
    call dword ptr [g_taskTarget]
    pushad
    call OnTaskRunnerAfter
    popad
    ret
} }

// Called at the flip: the capture of this tick becomes the one to use.
static void LogicCaptureFlip()
{
    g_lcUse  = g_lcFill;
    g_lcFill ^= 1;
    g_lc[g_lcFill].armed = g_lc[g_lcFill].valid = false;
    g_lc[g_lcFill].bad = 1;
}

// Puts the captured prims into the (freshly cleared) interpolated draw buffer 'db'.
static void ApplyLogicCapture(BYTE* db)
{
    const LogicCapture& c = g_lc[g_lcUse];
    g_lcApplyCode = !c.valid ? 1 : 2;
    if (!c.valid || (c.pkLen == 0 && c.sortN == 0 && c.hdLen == 0)) return;

    // Only when the interpolated frame is at the same point as the real frame
    // was when the task runner started, and nothing was linked before it.
    g_lcApplyCode = 3;
    bool ok = G<DWORD>(BAddr::SortCount) == c.sortA && HdBytesNow() == c.hdA;
    const DWORD rdb = (DWORD)(uintptr_t)c.db, tdb = (DWORD)(uintptr_t)db;
    if (ok) g_lcApplyCode = 4;
    for (int k = 0; k < 4 && ok; ++k) {
        DWORD h = c.otBefore[k * 2];
        ok = (h == 0xFFFFFFFF) || (h >= rdb && h < rdb + 0x24);
    }
    DWORD* v = G<DWORD*>(Addr::HdListLogic);
    if (ok) g_lcApplyCode = 5;
    if (ok && c.hdLen) ok = v && (v[2] - v[1]) >= c.hdLen;
    BYTE* dst = *(BYTE**)db;
    if (ok) { g_lcApplyCode = 6; ok = c.pkLen <= 0x7000; }
    const DWORD rdst = G<DWORD>(BAddr::RingCursor);
    if (ok) g_lcApplyCode = 7;
    if (ok && c.rLen) ok = rdst + c.rLen <= (DWORD)(uintptr_t)BWork() + 0x13DA00;
    if (ok) g_lcApplyCode = 0;
    if (!ok) {
        if (++g_lcSkipped <= 3 && VERBOSE) Log("Battle: task drawing not copied into an interpolated frame (state differs).");
        return;
    }

    const DWORD pkA = c.pkA, pkB = c.pkA + c.pkLen, delta = (DWORD)(uintptr_t)dst - pkA;
    const DWORD rA = c.rA, rB = c.rA + c.rLen, rDelta = rdst - rA;
    auto reloc = [&](DWORD x) -> DWORD {
        if (x >= pkA && x < pkB) return x + delta;
        if (x >= rA && x < rB) return x + rDelta;
        if (x >= rdb && x < rdb + 0x24) return x - rdb + tdb;
        return x;
    };

    // Packets, with their pointers moved
    memcpy(dst, c.pk, c.pkLen);
    for (DWORD i = 0; i + 4 <= c.pkLen; i += 4) {
        DWORD* d = (DWORD*)(dst + i);
        *d = reloc(*d);
    }
    *(BYTE**)db = dst + c.pkLen;

    // Ring buffer part, with its pointers moved
    if (c.rLen) {
        BYTE* r = (BYTE*)(uintptr_t)rdst;
        memcpy(r, c.ring, c.rLen);
        for (DWORD i = 0; i + 4 <= c.rLen; i += 4) {
            DWORD* d = (DWORD*)(r + i);
            *d = reloc(*d);
        }
        G<DWORD>(BAddr::RingCursor) = rdst + c.rLen;
    }

    // Ordering table entries that the task runner linked prims into
    for (int k = 0; k < 4; ++k) {
        if (c.otAfter[k * 2] == c.otBefore[k * 2]) continue;
        DWORD* ot = (DWORD*)(db + 4 + k * 8);
        ot[0] = reloc(c.otAfter[k * 2]);
        ot[1] = c.otAfter[k * 2 + 1];
    }

    // Depth-sort entries
    DWORD* list = G<DWORD*>(BAddr::SortListPtr) + c.sortA * 2;
    for (DWORD i = 0; i < c.sortN; ++i) {
        list[i * 2]     = c.sort[i * 2];
        list[i * 2 + 1] = reloc(c.sort[i * 2 + 1]);
    }
    G<DWORD>(BAddr::SortCount) = c.sortA + c.sortN;

    // HD records. A record holds a pointer to its prim (FUN_004202d0 stores it),
    // so that pointer has to move along with the prim.
    if (c.hdLen) {
        BYTE* rec = (BYTE*)(uintptr_t)v[1];
        memcpy(rec, c.hd, c.hdLen);
        for (DWORD i = 0; i + 4 <= c.hdLen; i += 4) {
            DWORD* d = (DWORD*)(rec + i);
            *d = reloc(*d);
        }
        v[1] += c.hdLen;
    }
    if (++g_lcUsed == 1 && VERBOSE)
        Log("Battle: task drawing copied into the interpolated frame (%lu + %lu bytes, %lu sort entries, %lu HD records).",
            c.pkLen, c.rLen, c.sortN, c.hdLen / HD_REC_SIZE);
}

// An object that goes back to the position it had two ticks ago is not moving
// but toggling between two places (menu items do this, e.g. in Sue's tactics
// menu). Halfway between those places is wrong, so such an object is drawn
// where the real frame draws it.
static bool BToggles(int i, const BattleSnap& a, const BattleSnap& b)
{
    const BattleSnap& p = g_bPrev2;
    if (!p.valid || p.seq + 1 != a.seq || p.obj[i] != b.obj[i]) return false;
    return p.pos[i][0] == b.pos[i][0] && p.pos[i][1] == b.pos[i][1] && p.pos[i][2] == b.pos[i][2];
}

static void BApplyState(const BattleSnap& a, const BattleSnap& b, int t16)
{
    BYTE* w = BWork();
    *(int*)(w + 0x04) = LerpI(a.cam[0], b.cam[0], t16);
    if (!IsJump(a.cam, b.cam)) {
        *(int*)(w + 0x08) = LerpI(a.cam[1], b.cam[1], t16);
        *(int*)(w + 0x10) = LerpI(a.cam[2], b.cam[2], t16);
    } else {
        *(int*)(w + 0x08) = b.cam[1];
        *(int*)(w + 0x10) = b.cam[2];
    }
    for (int i = 0; i < BNUM_OBJ; ++i) {
        BYTE* o = b.obj[i];
        if (!o) continue;
        int* pos = (int*)(o + 0x64);
        bool lerp = a.obj[i] == o && !IsJump(a.pos[i], b.pos[i]) && !BToggles(i, a, b);
        for (int k = 0; k < 3; ++k)
            pos[k] = lerp ? LerpI(a.pos[i][k], b.pos[i][k], t16) : b.pos[i][k];
    }
}

// FUN_00537830(ECX = input vectors, EDX = output, [stack] count), caller pops.
// noinline: when this was inlined, the optimizer did not see that the assembly
// writes to the caller's output buffer, and used the buffer's initial zeros.
static __declspec(noinline) void BProject(void* src, void* dst, DWORD count)
{
    void* fn = s_BProject;
    __asm {
        push count
        mov  ecx, src
        mov  edx, dst
        call fn
        add  esp, 4
    }
}

// Adds a prim at the front of an OT entry (8-byte headers: next pointer, flags)
static void BAddPrim(BYTE* ot, BYTE* prim)
{
    *(DWORD*)prim       = *(DWORD*)ot;
    *(DWORD*)(prim + 4) &= 0xFFFFFF00;
    *(DWORD*)(ot + 4)   &= 0xFFFFFF00;
    *(DWORD*)ot         = (DWORD)(uintptr_t)prim;
}

#ifdef GA_DIAG
static void TwTweenBegin();
static void TwAfterApply();
static void TwTweenEnd();
static void TwFrameDone(long realPk, long twPk, long realHd, long twHd);
static void TwObjects(const BattleSnap& a, const BattleSnap& b);
#endif

// The drawing part of FUN_00498c20, FUN_004927f0 and the rest of the loop
// until the flip, into the other battle draw buffer. Returns that buffer.
static BYTE* DrawBattleTween(const BattleSnap& a, const BattleSnap& b, int t16)
{
    BYTE* realDb = G<BYTE*>(BAddr::CurDB);
    BYTE* db     = (realDb == VA(BAddr::DB0)) ? VA(BAddr::DB1) : VA(BAddr::DB0);
    BYTE* w      = BWork();

    g_phase = "battle: switching buffer";
    WaitFrameConsumed();
    *(BYTE**)db = w + (db == VA(BAddr::DB0) ? 0x2BF00 : 0x33700);
    s_ClearOTag(db + 4, 4);
    G<BYTE*>(BAddr::CurDB) = db;
    G<int>(BAddr::SortCount) = 0;
    G<DWORD>(BAddr::SortListPtr) = (DWORD)(uintptr_t)(w + 0x27F00);

    g_phase = "battle: interpolating state";
    BCapture(g_bE);                              // end-of-tick state
    BLoad(g_bD);                                 // state at the draw moment of the real frame
    BApplyState(a, b, t16);

    g_phase = "battle: draw steps";
    g_inTween = true;
#ifdef GA_DIAG
    TwTweenBegin();
    TwObjects(a, b);
#endif
    ApplyLogicCapture(db);                       // menus etc.: drawn by the task runner before the draw part
#ifdef GA_DIAG
    TwAfterApply();
    if (g_ckReady) {
        Log("=== Battle checkpoint comparison %d (interpolated frame %u, alpha %.2f; only meaningful at 1.00) ===",
            g_ckReports + 1, g_bFrames, g_bAlpha);
        BChkCompare(CK_CAM);
        BChkEnvs(realDb, db);
    }
#endif
    s_BCamMatrix();
    {
        // Camera target -> screen offset of the whole 3D scene (0x498df5-0x498e61)
        static volatile int in[3], out[4];
        in[0] = *(int*)(w + 0x08); in[1] = 0; in[2] = *(int*)(w + 0x10);
        out[0] = out[1] = out[2] = out[3] = 0;
        BProject((void*)in, (void*)out, 1);
        *(short*)(w + 0x15E) = (short)-((out[0] + 0x8000) >> 16);
        *(short*)(w + 0x160) = (short)-((out[1] + 0x8000) >> 16);
        *(int*)(w + 0x68) = *(int*)(w + 0x04);
    }
    long stepPk[5];
    BYTE* pk0 = *(BYTE**)db;
#ifdef GA_DIAG
    BChkCompare(CK_SKY);
#endif
    s_BDrawSky();
    stepPk[0] = (long)(*(BYTE**)db - pk0); pk0 = *(BYTE**)db;
    s_BCamMatrix();
#ifdef GA_DIAG
    BChkCompare(CK_COLLECT);
#endif
    s_BCollect();
    BProject(w + 0xB5F8, w + 0xCDF8, G<DWORD>(BAddr::PointCount));
#ifdef GA_DIAG
    BChkCompare(CK_OBJA);
#endif
    s_BDrawObjA();
    stepPk[1] = (long)(*(BYTE**)db - pk0); pk0 = *(BYTE**)db;
#ifdef GA_DIAG
    BChkCompare(CK_OBJB);
#endif
    s_BDrawObjB();
    stepPk[2] = (long)(*(BYTE**)db - pk0);
#ifdef GA_DIAG
    BChkCompare(CK_AFTER);
    BChkComparePackets((DWORD)(uintptr_t)pk0, (DWORD)(uintptr_t)*(BYTE**)db,
                       (DWORD)(uintptr_t)(w + (db == VA(BAddr::DB0) ? 0x2BF00 : 0x33700)));
    if (g_ckReady) Log("=== end of checkpoint comparison ===");
#endif
    pk0 = *(BYTE**)db;
    s_BPostDraw();
    stepPk[3] = (long)(*(BYTE**)db - pk0);
    stepPk[4] = G<int>(BAddr::SortCount);

    // Depth sort + linking into OT entry 3 (0x4922db-0x4923a3)
    int count = G<int>(BAddr::SortCount);
    if (count >= 2) {
        DWORD list = G<DWORD>(BAddr::SortListPtr);
        DWORD last = list + (DWORD)(count - 1) * 8;
        void* fn   = s_SortDepthList;
        __asm {
            mov  ecx, list
            mov  edx, ecx
            push last
            call fn
            add  esp, 4
        }
    }
    BYTE* ot3 = db + 0x1C;
    BYTE* list = G<BYTE*>(BAddr::SortListPtr);
    for (int i = 0; i < count; ++i) {
        BYTE* p = *(BYTE**)(list + i * 8 + 4);
        for (;;) {
            DWORD nxt = *(DWORD*)p;
            DWORD w1  = *(DWORD*)(p + 4);
            BAddPrim(ot3, p);
            if (nxt == 0xFFFFFFFF && (w1 & 0xFF) == 0) break;
            p = (BYTE*)(uintptr_t)nxt;
        }
    }

    // Two draw-mode prims (0x4923f0 into OT entry 2, 0x49248e into OT entry 0)
    for (int k = 0; k < 2; ++k) {
        BYTE* ot = db + (k == 0 ? 0x14 : 0x04);
        BYTE* pk = *(BYTE**)db;
        *(BYTE**)db = pk + 0x0C;
        pk[7] = 1;
        *(DWORD*)(pk + 8) = 0xE100000F;
        BAddPrim(ot, pk);
    }
#ifdef GA_DIAG
    TwTweenEnd();
#endif
    g_inTween = false;

    g_phase = "battle: restoring state";
    BLoad(g_bE);

#ifdef GA_DIAG
    // Compare with the real frame: packet bytes, HD records, sort entries
    {
        static int logged = 0;
        BYTE* realBase = w + (realDb == VA(BAddr::DB0) ? 0x2BF00 : 0x33700);
        BYTE* twBase   = w + (db     == VA(BAddr::DB0) ? 0x2BF00 : 0x33700);
        long realPk = (long)(*(BYTE**)realDb - realBase), twPk = (long)(*(BYTE**)db - twBase);
        DWORD* v = G<DWORD*>(Addr::HdListLogic);
        long realHd = (long)(g_hdSaveLen / HD_REC_SIZE), twHd = v ? (long)((v[1] - v[0]) / HD_REC_SIZE) : -1;
        static long lastDiff = 0;
        const long diff = realPk - twPk;
        TwFrameDone(realPk, twPk, realHd, twHd);
        if ((realPk != twPk || realHd != twHd) && (logged < 12 || (diff != lastDiff && logged < 40))) {
            ++logged;
            lastDiff = diff;
            Log("Battle frame %u: real %ld bytes / %ld HD records, interpolated %ld bytes / %ld HD records",
                g_bFrames, realPk, realHd, twPk, twHd);
            Log("   interpolated steps: sky %ld, objects A %ld, objects B %ld, post %ld bytes; sort entries %ld",
                stepPk[0], stepPk[1], stepPk[2], stepPk[3], stepPk[4]);
            Log("   real frame:         sky %ld, objects A %ld, objects B %ld, post %ld bytes; sort entries %ld; whole tick %ld",
                g_bLastPk[10], g_bLastPk[18], g_bLastPk[19], g_bLastPk[2], g_bLastSort, g_bLastPk[1]);
            LogRealTickSites();
        }
    }
#else
    (void)realDb; (void)stepPk;
#endif
    ++g_bFrames;
    if (g_bFrames == 1 && VERBOSE)
        Log("Battle: first interpolated frame drawn (alpha %.2f).", g_bAlpha);
    return db;
}

// Replaces the call of FUN_00419c20 (flip) in the battle loop.
static void __cdecl BattleFlipHook(DWORD otHead, DWORD drawEnv)
{
    const unsigned seq = ++g_bSeq;
    g_logicThreadId = GetCurrentThreadId();
#ifdef GA_DIAG
    g_ckReady = g_ckArmed && g_ck[CK_AFTER].taken;
    g_ckArmed = false;
#endif

    bool haveCur = g_bCamTaken && g_bObjTaken;
    g_bCamTaken = g_bObjTaken = false;
    LogicCaptureFlip();
    if (haveCur) {
        g_bCur = g_bDraw;
        g_bCur.seq = seq;
        g_bCur.valid = true;
    } else {
        g_bCur.valid = false;
    }
    const int  frameMode = g_frameMode;
    const bool canTween  = frameMode == FM_INTERPOLATED &&
                           haveCur && g_bPrev.valid && g_bPrev.seq + 1 == seq && HdRecordsFit();

    if (!canTween) {
        g_phase = "battle: handing over real frame";
        s_PutDrawEnvFlip((void*)(uintptr_t)otHead, (void*)(uintptr_t)drawEnv);
        WaitFrameConsumed();
        if (frameMode != FM_DOUBLE)
            WaitNextVBlank();                    // the second vblank wait is patched out
    } else {
        float t = g_bAlpha < 0.0f ? 0.0f : (g_bAlpha > 1.0f ? 1.0f : g_bAlpha);
        BYTE* realDb = G<BYTE*>(BAddr::CurDB);
        HdStashReal();
        BYTE* tdb = DrawBattleTween(g_bPrev, g_bCur, (int)(t * 65536.0f));
        g_phase = "battle: handing over interpolated frame";
        WaitFrameConsumed();
        s_PutDispEnv(tdb + 0x80);
        s_PutDrawEnvFlip(tdb + 0x1C, tdb + 0x24);
        HdRestoreReal();
        G<BYTE*>(BAddr::CurDB) = realDb;
        g_phase = "battle: handing over real frame";
        WaitFrameConsumed();                     // the render thread must have taken the interpolated frame
        s_PutDispEnv(realDb + 0x80);
        s_PutDrawEnvFlip((void*)(uintptr_t)otHead, (void*)(uintptr_t)drawEnv);
    }
    G<unsigned __int64>(Addr::LastTick) = s_GetVBlankTick();
    g_bPrev2 = g_bPrev;
    g_bPrev = g_bCur;
#ifdef GA_DIAG
    for (BCheck& c : g_ck) c.taken = false;
    if (g_ckReady) { ++g_ckReports; g_ckReady = false; }
    if (canTween && g_ck[0].work && g_ckReports < CK_MAX_REPORTS && ++g_ckCountdown >= 90) {
        g_ckCountdown = 0;
        g_ckArmed = true;                        // compare the next tick
    }
#endif
    g_phase = "outside the hook";
}

static __declspec(naked) void Stub_BattleFlip() { __asm {
    push edx
    push ecx
    call BattleFlipHook
    add  esp, 8
    ret
} }

static bool Install_TweenBlocks();

static void Install_BattleTween()
{
    // Same alpha as in the field; BattleTweenAlpha (not in the ini) overrides it for tests.
    wchar_t fieldAlpha[32], alphaStr[32];
    GetPrivateProfileStringW(L"Interpolation", L"TweenAlpha", L"0.5", fieldAlpha, 32, g_ini);
    GetPrivateProfileStringW(L"Interpolation", L"BattleTweenAlpha", fieldAlpha, alphaStr, 32, g_ini);
    g_bAlpha = (float)_wtof(alphaStr);

    BYTE* w = VA(BAddr::SecondWait);
    if (!IsCallTo(BAddr::CallFlip, Addr::PutDrawEnv_Flip) ||
        !IsCallTo(BAddr::CallCamera, BAddr::CamMatrix) ||
        !IsCallTo(BAddr::CallCollect, BAddr::Collect) ||
        !IsCallTo(0x00492456, Addr::GetVBlankTick) || w[0] != 0x83 || w[1] != 0xC0 || w[2] != 0x01) {
        Log("Battle interpolation: code is not as expected - not installed.");
        return;
    }
    s_BCamMatrix = (VoidFn_t)VA(BAddr::CamMatrix);
    s_BProject   =           VA(BAddr::Project);
    s_BDrawSky   = (VoidFn_t)VA(BAddr::DrawSky);
    s_BCollect   = (VoidFn_t)VA(BAddr::Collect);
    s_BDrawObjA  = (VoidFn_t)VA(BAddr::DrawObjA);
    s_BDrawObjB  = (VoidFn_t)VA(BAddr::DrawObjB);
    s_BPostDraw  = (VoidFn_t)VA(BAddr::PostDraw);
    g_bCamTarget     = (DWORD)(uintptr_t)VA(BAddr::CamMatrix);
    g_bCollectTarget = (DWORD)(uintptr_t)VA(BAddr::Collect);

    Install_TweenBlocks();
    if (!IsCallTo(BAddr::CallTasks, BAddr::TaskRunner)) {
        Log("Battle interpolation: call of the task runner not as expected - not installed.");
        return;
    }
    g_taskTarget = (DWORD)(uintptr_t)VA(BAddr::TaskRunner);
    const BYTE zero = 0x00;
    bool ok = WriteBranch(VA(BAddr::CallCamera),  0xE8, (void*)&Stub_BattleCamera, 5)
           && WriteBranch(VA(BAddr::CallCollect), 0xE8, (void*)&Stub_BattleCollect, 5)
           && WriteCode(w + 2, &zero, 1)
           && WriteBranch(VA(BAddr::CallTasks),   0xE8, (void*)&Stub_TaskRunner, 5)
           && WriteBranch(VA(BAddr::CallFlip),    0xE8, (void*)&Stub_BattleFlip, 5);
#ifdef GA_DIAG
    if (ok) Install_AppendHooks();              // only the diagnostic build needs these (no such prims found)
#endif
    g_bEnabled = ok;
    if (!ok)          Log("Battle interpolation: patching failed.");
    else if (VERBOSE) Log("Battle interpolation: installed. TweenAlpha=%.2f.", g_bAlpha);
    else              Log("Battle interpolation: installed.");
#ifdef GA_DIAG
    if (ok) Log(BChkAlloc() ? "DIAGNOSTIC BUILD: battle checkpoint comparison active (%d reports per game start)."
                            : "DIAGNOSTIC BUILD: no memory for the battle checkpoint comparison.", CK_MAX_REPORTS);
#endif
}

// ============================================================================
//  PART 2: DISPLAY MODES
//
//  The port has two switches left over from development:
//   - The HD texture manager has a flag (+0x117) that turns all HD textures
//     off; the renderer then falls back to the PS1 pixels in video memory.
//     The render thread sets that flag every frame from DAT_0063f052.
//   - DAT_0063f8a8 requests the native PS1 renderer. At every flip it is
//     copied to DAT_00640e7e (logic side: no widescreen shift) and then to
//     DAT_0063f052 (render side: back buffer at the PS1 display resolution,
//     no HD textures).
//  Both are always 0 in the Steam version.
//
//  Mode 0 = HD, 1 = pixel art (HD textures off, widescreen, full resolution),
//  2 = PS1 native resolution (via DAT_0063f8a8, 4:3).
// ============================================================================

static const char* const MODE_NAMES[3] = { "HD", "pixel art", "PS1 native resolution" };

static volatile int  g_mode        = 0;
static volatile BYTE g_hdOffExtra  = 0;        // 1 in mode 1
static DWORD         g_pHdOffFlag  = 0;        // real address of DAT_0063f052
static int           g_modeKey     = VK_F10;
static int           g_cycle[3]    = { 0, 1, 2 };
static int           g_cycleCount  = 3;

// Replaces 'mov al, [DAT_0063f052]' (5 bytes) with 'call Stub_ReadHdOff'.
// Only changes AL (and the flags); the code after it only uses AL.
static __declspec(naked) void Stub_ReadHdOff()
{
    __asm {
        mov  eax, dword ptr [g_pHdOffFlag]
        mov  al, byte ptr [eax]
        or   al, byte ptr [g_hdOffExtra]
        ret
    }
}

static bool PatchReadHdOff(DWORD site)
{
    BYTE* p = VA(site);
    DWORD abs;
    memcpy(&abs, p + 1, 4);
    if (p[0] != 0xA0 || abs != g_pHdOffFlag) {
        Log("Display modes: code at %08lX is not as expected - not patched.", site);
        return false;
    }
    return WriteBranch(p, 0xE8, (void*)&Stub_ReadHdOff, 5);
}

static void ApplyMode(int mode)
{
    g_mode       = mode;
    g_hdOffExtra = (BYTE)(mode == 1 ? 1 : 0);
    g_fixStrips  = mode == 1;
    G<BYTE>(Addr::PsxModeRequest) = (BYTE)(mode == 2 ? 1 : 0);
}

static int ParseKeyName(const wchar_t* s)
{
    if ((s[0] == L'F' || s[0] == L'f') && s[1] >= L'1' && s[1] <= L'9') {
        int n = _wtoi(s + 1);
        if (n >= 1 && n <= 24) return VK_F1 + n - 1;
    }
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) {
        int v = (int)wcstoul(s + 2, nullptr, 16);
        if (v > 0 && v < 256) return v;
    }
    return 0;
}

static bool GameHasFocus()
{
    HWND w = GetForegroundWindow();
    DWORD pid = 0;
    if (w) GetWindowThreadProcessId(w, &pid);
    return pid == GetCurrentProcessId();
}

static DWORD WINAPI ModeKeyThread(LPVOID)
{
    bool wasDown = false;
    for (;;) {
        Sleep(30);
        bool down = (GetAsyncKeyState(g_modeKey) & 0x8000) != 0;
        if (down && !wasDown && GameHasFocus()) {
            int pos = 0;
            for (int i = 0; i < g_cycleCount; ++i)
                if (g_cycle[i] == g_mode) pos = i;
            int next = g_cycle[(pos + 1) % g_cycleCount];
            ApplyMode(next);
            wchar_t v[4];
            swprintf_s(v, 4, L"%d", next);
            WritePrivateProfileStringW(L"Display", L"Mode", v, g_ini);
            Log("Display mode: %s.", MODE_NAMES[next]);
        }
        wasDown = down;
        // The game never writes this byte itself, but keep it in line with the mode anyway.
        BYTE want = (BYTE)(g_mode == 2 ? 1 : 0);
        if (G<BYTE>(Addr::PsxModeRequest) != want)
            G<BYTE>(Addr::PsxModeRequest) = want;
    }
}

static void Install_DisplayModes()
{
    // Which modes the hotkey cycles through, e.g. "0,1,2" or "0,1"
    wchar_t cycleStr[32];
    GetPrivateProfileStringW(L"Display", L"Cycle", L"0,1,2", cycleStr, 32, g_ini);
    g_cycleCount = 0;
    for (const wchar_t* c = cycleStr; *c && g_cycleCount < 3; ++c)
        if (*c >= L'0' && *c <= L'2') {
            int m = *c - L'0';
            bool dup = false;
            for (int i = 0; i < g_cycleCount; ++i) dup |= (g_cycle[i] == m);
            if (!dup) g_cycle[g_cycleCount++] = m;
        }
    if (g_cycleCount < 2) {
        g_cycle[0] = 0; g_cycle[1] = 1; g_cycleCount = 2;
        Log("Display modes: invalid Cycle '%ls', using 0,1.", cycleStr);
    }

    wchar_t keyStr[32];
    GetPrivateProfileStringW(L"Display", L"Hotkey", L"F10", keyStr, 32, g_ini);
    int key = ParseKeyName(keyStr);
    if (key) g_modeKey = key;
    else     Log("Display modes: unknown hotkey '%ls', using F10.", keyStr);

    g_pHdOffFlag = (DWORD)(uintptr_t)VA(Addr::HdOffFlag);
    if (!PatchReadHdOff(Addr::ReadHdOff_Render)) {
        Log("Display modes NOT installed.");
        return;
    }
    PatchReadHdOff(Addr::ReadHdOff_Other);

    int mode = (int)GetPrivateProfileIntW(L"Display", L"Mode", 0, g_ini);
    if (mode < 0 || mode > 2) mode = 0;
    ApplyMode(mode);

    HANDLE h = CreateThread(nullptr, 0, ModeKeyThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
    Log(VERBOSE ? "Display modes: installed, hotkey %ls, cycle %ls, starting in %s."
                : "Display modes: hotkey %ls, cycle %ls, starting in %s.",
        keyStr, cycleStr, MODE_NAMES[mode]);
}

// ============================================================================
//  Frame rate mode hotkey ([Interpolation] Hotkey / Cycle / Mode)
// ============================================================================

static int g_fmKey = VK_F9;
static int g_fmCycle[3] = { 0, 1, 2 };
static int g_fmCycleCount = 3;

static DWORD WINAPI FrameModeKeyThread(LPVOID)
{
    bool wasDown = false;
    for (;;) {
        Sleep(30);
        bool down = (GetAsyncKeyState(g_fmKey) & 0x8000) != 0;
        if (down && !wasDown && GameHasFocus()) {
            int pos = 0;
            for (int i = 0; i < g_fmCycleCount; ++i)
                if (g_fmCycle[i] == g_frameMode) pos = i;
            int next = g_fmCycle[(pos + 1) % g_fmCycleCount];
            g_frameMode = next;
            wchar_t v[4];
            swprintf_s(v, 4, L"%d", next);
            WritePrivateProfileStringW(L"Interpolation", L"Mode", v, g_ini);
            Log("Frame rate: %s.", FRAME_MODE_NAMES[next]);
        }
        wasDown = down;
    }
}

static void Install_FrameModeKey()
{
    wchar_t cycleStr[32];
    GetPrivateProfileStringW(L"Interpolation", L"Cycle", L"0,1,2", cycleStr, 32, g_ini);
    g_fmCycleCount = 0;
    for (const wchar_t* c = cycleStr; *c && g_fmCycleCount < 3; ++c)
        if (*c >= L'0' && *c <= L'2') {
            int m = *c - L'0';
            bool dup = false;
            for (int i = 0; i < g_fmCycleCount; ++i) dup |= (g_fmCycle[i] == m);
            if (!dup) g_fmCycle[g_fmCycleCount++] = m;
        }

    int mode = (int)GetPrivateProfileIntW(L"Interpolation", L"Mode", FM_INTERPOLATED, g_ini);
    if (mode < 0 || mode > 2) mode = FM_INTERPOLATED;
    g_frameMode = mode;

    wchar_t keyStr[32];
    GetPrivateProfileStringW(L"Interpolation", L"Hotkey", L"F9", keyStr, 32, g_ini);
    int key = ParseKeyName(keyStr);
    if (key) g_fmKey = key;
    else     Log("Frame rate: unknown hotkey '%ls', using F9.", keyStr);

    if (g_fmCycleCount >= 2) {
        HANDLE h = CreateThread(nullptr, 0, FrameModeKeyThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
        Log("Frame rate: hotkey %ls, cycle %ls, starting in %s.", key ? keyStr : L"F9", cycleStr,
            FRAME_MODE_NAMES[mode]);
    } else {
        Log("Frame rate: %s (no hotkey: Cycle '%ls' has fewer than two modes).", FRAME_MODE_NAMES[mode], cycleStr);
    }
}

// ============================================================================
//  Picture shader ([Shader] in the ini): a filter over every finished frame
// ============================================================================
//  The game's call of IDXGISwapChain::Present (0x43a653) is redirected to
//  Hook_Present; nothing outside grandia.exe is changed. Just before a frame
//  goes to the screen, the picture is copied and drawn back over the whole
//  back buffer with a pixel shader: the built-in CRT shader, or an external
//  HLSL shader (not documented in the ini: [Shader] Path/Filename/Entry,
//  settings in [ShaderParameters]). The game's pipeline state is saved before and put
//  back after. The game calls Present with its render mutex (0x640da8) held,
//  so nothing else uses the device context in the meantime.

enum { SH_OFF = 0, SH_CRT = 1, SH_EXTERNAL = 2, SH_MODES = 3 };
static const char* const SHADER_NAMES[SH_MODES] = {
    "off", "CRT", "external shader",
};

static volatile int  g_shMode      = SH_OFF;
static bool          g_shEnabled   = false;
static int           g_shKey       = VK_F8;
static int           g_shCycle[SH_MODES];
static int           g_shCycleCount = 0;
// CRT shader settings ([Shader] in the ini)
static float         g_crtRow2     = 0.8f;     // brightness of the 2nd row of every group of three
static float         g_crtRow3     = 0.6f;     // brightness of the 3rd row
static float         g_crtOverspill = 0.8f;    // share of the other two primaries in each mask pixel
static float         g_crtDiagonal = 0.0f;     // 1 = diagonal RGB pattern, 0 = vertical stripes
static float         g_crtSizeW    = 0.0f;     // size of the mask grid (0 = screen size)
static float         g_crtSizeH    = 0.0f;
static wchar_t       g_shExtPath[MAX_PATH];
static char          g_shExtPathA[MAX_PATH];   // the same, for the compiler and the log
static char          g_shExtEntry[64] = "main";
static bool          g_shExtFound  = false;
static volatile LONG g_shExtReload = 1;         // (re)compile the external shader when it is used next
static unsigned      g_shFrames    = 0;

typedef HRESULT (WINAPI *D3DCompile_t)(LPCVOID, SIZE_T, LPCSTR, const D3D_SHADER_MACRO*, ID3DInclude*,
                                       LPCSTR, LPCSTR, UINT, UINT, ID3DBlob**, ID3DBlob**);
typedef HRESULT (WINAPI *D3DReflect_t)(LPCVOID, SIZE_T, REFIID, void**);
typedef HRESULT (STDMETHODCALLTYPE *Present_t)(IDXGISwapChain*, UINT, UINT);

static D3DCompile_t s_D3DCompile = nullptr;
static D3DReflect_t s_D3DReflect = nullptr;

// IID_ID3D11ShaderReflection of d3dcompiler_47.dll
static const GUID IID_ShaderReflection47 =
    { 0x8d536ca1, 0x0cca, 0x4956, { 0xa8, 0x37, 0x78, 0x69, 0x63, 0x75, 0x55, 0x84 } };

// D3DCompile flags (d3dcompiler.h)
static const UINT SH_OPTIMIZE        = (1 << 15);   // D3DCOMPILE_OPTIMIZATION_LEVEL3
static const UINT SH_BACKWARDS_COMPAT = (1 << 12);  // D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY

// Built-in shaders: a full-screen triangle, and the CRT shader.
// The CRT shader lays a pattern of red, green and blue pixels over the picture
// (each takes that primary from the picture, plus 'Overspill' of the other
// two), in groups of three rows of which the 2nd and 3rd are darker. Based on
// the CRT effect by SoftSpectrum48 (softspectrum48.weebly.com), after an
// article by Svyatoslav Cherkasov; written anew for Direct3D 11.
// LICENSE NOTE: PSCrt is not covered by the GPL; it is included with the
// permission of SoftSpectrum48 (see the top of this file and README).
static const char SH_BUILTIN_SRC[] =
    "struct VSOut { float2 uv : TEXCOORD0; float4 pos : SV_Position; };\n"
    "VSOut VSMain(uint id : SV_VertexID)\n"
    "{\n"
    "    VSOut o;\n"
    "    float2 t = float2((id << 1) & 2, id & 2);\n"
    "    o.uv  = t;\n"
    "    o.pos = float4(t.x * 2.0 - 1.0, 1.0 - t.y * 2.0, 0.0, 1.0);\n"
    "    return o;\n"
    "}\n"
    "Texture2D    Source : register(t0);\n"
    "SamplerState Smp    : register(s0);\n"
    "cbuffer Params : register(b0)\n"
    "{\n"
    "    float4 Grid;     // mask grid width, height (in cells over the whole screen)\n"
    "    float4 Crt;      // row 2 brightness, row 3 brightness, overspill, 1 = diagonal\n"
    "};\n"
    "float4 PSCrt(float2 uv : TEXCOORD0, float4 pos : SV_Position) : SV_Target\n"
    "{\n"
    "    int row = (int)(uv.y * Grid.y) % 3;\n"
    "    int col = (int)(uv.x * Grid.x) % 3;\n"
    "    int ch  = (Crt.w > 0.5) ? (col - row + 3) % 3 : col;   // 0 = red, 1 = green, 2 = blue\n"
    "    float3 m = float3(ch == 0 ? 1.0 : Crt.z, ch == 1 ? 1.0 : Crt.z, ch == 2 ? 1.0 : Crt.z);\n"
    "    if (row == 1) m *= Crt.x;\n"
    "    if (row == 2) m *= Crt.y;\n"
    "    float3 c = Source.Sample(Smp, uv).rgb + 0.1;\n"
    "    return float4(saturate(c * m), 1.0);\n"
    "}\n";

template <class T> static void SafeRelease(T*& p) { if (p) { p->Release(); p = nullptr; } }

// A setting of the external shader
enum { SV_ZERO, SV_DEFAULT, SV_INI, SV_AUTO_SCREEN, SV_AUTO_SOURCE, SV_AUTO_FRAME };
struct ExtVar {
    char  name[64];
    int   cb;             // index in g_sh.extCb
    UINT  offset, size;
    int   isInt;          // 0 float, 1 int/uint/bool
    int   count;          // number of components (1..16)
    int   source;         // SV_*
};
struct ExtCB {
    UINT          slot, size;
    ID3D11Buffer* buf;
    BYTE          data[4096];
};

static struct ShaderRes {
    ID3D11Device*             dev;
    bool                      broken;        // setting up failed on this device: no more attempts
    D3D_FEATURE_LEVEL         level;
    ID3D11VertexShader*       vs;
    ID3D11PixelShader*        psCrt;
    ID3D11Buffer*             cbCrt;
    ID3D11SamplerState*       sampler;
    ID3D11Texture2D*          copy;
    ID3D11ShaderResourceView* copySrv;
    UINT                      copyW, copyH;
    DXGI_FORMAT               copyFmt;
    ID3D11PixelShader*        psExt;
    UINT                      extTex, extSmp;
    ExtCB                     extCb[4];
    int                       extCbCount;
    ExtVar                    extVar[48];
    int                       extVarCount;
} g_sh;

static void ShReleaseExternal()
{
    SafeRelease(g_sh.psExt);
    for (int i = 0; i < g_sh.extCbCount; ++i) SafeRelease(g_sh.extCb[i].buf);
    g_sh.extCbCount = g_sh.extVarCount = 0;
}

static void ShReleaseAll()
{
    ShReleaseExternal();
    SafeRelease(g_sh.copySrv);
    SafeRelease(g_sh.copy);
    SafeRelease(g_sh.sampler);
    SafeRelease(g_sh.cbCrt);
    SafeRelease(g_sh.psCrt);
    SafeRelease(g_sh.vs);
    SafeRelease(g_sh.dev);
    g_sh.copyW = g_sh.copyH = 0;
    g_sh.broken = false;
    InterlockedExchange(&g_shExtReload, 1);
}

// Writes the compiler messages to the log, one line at a time.
static void ShLogMessages(ID3DBlob* msg)
{
    if (!msg) return;
    const char* p   = (const char*)msg->GetBufferPointer();
    const char* end = p + msg->GetBufferSize();
    int lines = 0;
    while (p < end && *p && lines < 20) {
        const char* e = p;
        while (e < end && *e && *e != '\n' && *e != '\r') ++e;
        if (e > p) { Log("   %.*s", (int)(e - p), p); ++lines; }
        p = e;
        while (p < end && (*p == '\n' || *p == '\r')) ++p;
    }
}

static ID3DBlob* ShCompile(const char* src, size_t len, const char* name, const char* entry,
                           const char* target, UINT flags)
{
    ID3DBlob* code = nullptr;
    ID3DBlob* msg  = nullptr;
    // (ID3DInclude*)1 = D3D_COMPILE_STANDARD_FILE_INCLUDE: #include next to the file
    HRESULT hr = s_D3DCompile(src, len, name, nullptr, (ID3DInclude*)(uintptr_t)1, entry, target,
                              flags, 0, &code, &msg);
    if (hr < 0 || !code) {
        Log("Shader: %s (%s) could not be compiled (0x%08lX).", name, entry, (DWORD)hr);
        ShLogMessages(msg);
        SafeRelease(msg);
        SafeRelease(code);
        return nullptr;
    }
    SafeRelease(msg);
    return code;
}

static bool ShLoadCompiler()
{
    if (s_D3DCompile) return true;
    HMODULE h = LoadLibraryW(L"d3dcompiler_47.dll");
    if (h) {
        s_D3DCompile = (D3DCompile_t)GetProcAddress(h, "D3DCompile");
        s_D3DReflect = (D3DReflect_t)GetProcAddress(h, "D3DReflect");
    }
    if (!s_D3DCompile || !s_D3DReflect) {
        s_D3DCompile = nullptr;
        Log("Shader: d3dcompiler_47.dll not found - shaders are off.");
        return false;
    }
    return true;
}

// Built-in shaders and the fixed resources, for this device.
static bool ShInitDevice(ID3D11Device* dev)
{
    ShReleaseAll();
    g_sh.dev = dev;
    dev->AddRef();
    g_sh.level = dev->GetFeatureLevel();
    if (!ShLoadCompiler()) return false;

    ID3DBlob* vsCode = ShCompile(SH_BUILTIN_SRC, sizeof(SH_BUILTIN_SRC) - 1, "built-in", "VSMain", "vs_4_0", SH_OPTIMIZE);
    ID3DBlob* psCode = ShCompile(SH_BUILTIN_SRC, sizeof(SH_BUILTIN_SRC) - 1, "built-in", "PSCrt", "ps_4_0", SH_OPTIMIZE);
    bool ok = vsCode && psCode &&
        dev->CreateVertexShader(vsCode->GetBufferPointer(), vsCode->GetBufferSize(), nullptr, &g_sh.vs) >= 0 &&
        dev->CreatePixelShader(psCode->GetBufferPointer(), psCode->GetBufferSize(), nullptr, &g_sh.psCrt) >= 0;
    SafeRelease(vsCode);
    SafeRelease(psCode);

    if (ok) {
        D3D11_BUFFER_DESC bd = {};
        bd.ByteWidth = 32;
        bd.Usage     = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        ok = dev->CreateBuffer(&bd, nullptr, &g_sh.cbCrt) >= 0;
    }
    if (ok) {
        D3D11_SAMPLER_DESC sd = {};
        sd.Filter   = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.ComparisonFunc = D3D11_COMPARISON_NEVER;
        sd.MaxLOD   = D3D11_FLOAT32_MAX;
        ok = dev->CreateSamplerState(&sd, &g_sh.sampler) >= 0;
    }
    if (!ok) Log("Shader: setting up the shaders failed - shaders are off.");
    return ok;
}

static DXGI_FORMAT ShTypedFormat(DXGI_FORMAT f)
{
    switch (f) {
    case DXGI_FORMAT_R8G8B8A8_TYPELESS:    return DXGI_FORMAT_R8G8B8A8_UNORM;
    case DXGI_FORMAT_B8G8R8A8_TYPELESS:    return DXGI_FORMAT_B8G8R8A8_UNORM;
    case DXGI_FORMAT_B8G8R8X8_TYPELESS:    return DXGI_FORMAT_B8G8R8X8_UNORM;
    case DXGI_FORMAT_R10G10B10A2_TYPELESS: return DXGI_FORMAT_R10G10B10A2_UNORM;
    case DXGI_FORMAT_R16G16B16A16_TYPELESS: return DXGI_FORMAT_R16G16B16A16_FLOAT;
    default:                               return f;
    }
}

// Texture that receives a copy of the back buffer (same size and format).
static bool ShEnsureCopy(const D3D11_TEXTURE2D_DESC& bd)
{
    if (g_sh.copy && g_sh.copyW == bd.Width && g_sh.copyH == bd.Height && g_sh.copyFmt == bd.Format)
        return true;
    SafeRelease(g_sh.copySrv);
    SafeRelease(g_sh.copy);
    D3D11_TEXTURE2D_DESC td = {};
    td.Width            = bd.Width;
    td.Height           = bd.Height;
    td.MipLevels        = 1;
    td.ArraySize        = 1;
    td.Format           = bd.Format;
    td.SampleDesc.Count = 1;
    td.Usage            = D3D11_USAGE_DEFAULT;
    td.BindFlags        = D3D11_BIND_SHADER_RESOURCE;
    if (g_sh.dev->CreateTexture2D(&td, nullptr, &g_sh.copy) < 0) return false;
    D3D11_SHADER_RESOURCE_VIEW_DESC vd = {};
    vd.Format              = ShTypedFormat(bd.Format);
    vd.ViewDimension       = D3D11_SRV_DIMENSION_TEXTURE2D;
    vd.Texture2D.MipLevels = 1;
    if (g_sh.dev->CreateShaderResourceView(g_sh.copy, &vd, &g_sh.copySrv) < 0) {
        SafeRelease(g_sh.copy);
        return false;
    }
    g_sh.copyW = bd.Width; g_sh.copyH = bd.Height; g_sh.copyFmt = bd.Format;
    return true;
}

static bool ShNameIs(const char* a, const char* const* names)
{
    for (; *names; ++names) if (_stricmp(a, *names) == 0) return true;
    return false;
}

static const char* const SH_AUTO_SCREEN[] = { "TextureSize", "OutputSize", "ScreenSize", "ViewportSize", "Resolution", nullptr };
static const char* const SH_AUTO_SOURCE[] = { "SourceSize", "InputSize", "VideoSize", "GameSize", nullptr };
static const char* const SH_AUTO_FRAME[]  = { "FrameCount", "Frame", "FrameCounter", nullptr };

// Writes up to 'count' values into a variable of the external shader.
static void ShSetVar(const ExtVar& v, const float* val, int n)
{
    BYTE* p = g_sh.extCb[v.cb].data + v.offset;
    const int count = n < v.count ? n : v.count;
    for (int i = 0; i < count && (UINT)(i + 1) * 4 <= v.size; ++i) {
        if (v.isInt) { int x = (int)val[i]; memcpy(p + i * 4, &x, 4); }
        else         memcpy(p + i * 4, &val[i], 4);
    }
}

// Reads 'name' from [ShaderParameters]: up to 16 numbers separated by commas.
static int ShReadIniValues(const char* name, float* out)
{
    wchar_t key[64], str[256];
    for (int i = 0; i < 63 && (key[i] = (wchar_t)(unsigned char)name[i]) != 0; ++i) key[i + 1] = 0;
    key[63] = 0;
    GetPrivateProfileStringW(L"ShaderParameters", key, L"", str, 256, g_ini);
    int n = 0;
    const wchar_t* s = str;
    while (*s && n < 16) {
        while (*s == L' ' || *s == L'\t' || *s == L',') ++s;
        if (!*s) break;
        wchar_t* e = nullptr;
        double d = wcstod(s, &e);
        if (e == s) break;
        out[n++] = (float)d;
        s = e;
    }
    return n;
}

// Compiles the external shader and looks up its settings.
static void ShLoadExternal()
{
    ShReleaseExternal();

    HANDLE f = CreateFileW(g_shExtPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        Log("Shader: external shader %s not found.", g_shExtPathA);
        return;
    }
    DWORD size = GetFileSize(f, nullptr), got = 0;
    char* src = (size > 0 && size < (1u << 20)) ? (char*)VirtualAlloc(nullptr, size + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) : nullptr;
    bool read = src && ReadFile(f, src, size, &got, nullptr) && got == size;
    CloseHandle(f);
    if (!read) {
        Log("Shader: external shader %s could not be read.", g_shExtPathA);
        if (src) VirtualFree(src, 0, MEM_RELEASE);
        return;
    }
    src[size] = 0;

    // Older (Direct3D 9 style) shaders with sampler2D/tex2D/COLOR compile with backwards compatibility.
    const char* target = g_sh.level >= D3D_FEATURE_LEVEL_11_0 ? "ps_5_0" : "ps_4_0";
    ID3DBlob* code = ShCompile(src, size, g_shExtPathA, g_shExtEntry, target, SH_OPTIMIZE | SH_BACKWARDS_COMPAT);
    VirtualFree(src, 0, MEM_RELEASE);
    if (!code) return;

    ID3D11ShaderReflection* refl = nullptr;
    bool ok = g_sh.dev->CreatePixelShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &g_sh.psExt) >= 0 &&
              s_D3DReflect(code->GetBufferPointer(), code->GetBufferSize(), IID_ShaderReflection47, (void**)&refl) >= 0 && refl;
    SafeRelease(code);
    if (!ok) {
        Log("Shader: external shader %s could not be set up.", g_shExtPathA);
        SafeRelease(refl);
        ShReleaseExternal();
        return;
    }

    D3D11_SHADER_DESC sd;
    refl->GetDesc(&sd);
    bool haveTex = false, haveSmp = false;
    g_sh.extTex = g_sh.extSmp = 0;
    for (UINT i = 0; i < sd.BoundResources; ++i) {
        D3D11_SHADER_INPUT_BIND_DESC b;
        if (refl->GetResourceBindingDesc(i, &b) < 0) continue;
        if (b.Type == D3D_SIT_TEXTURE && !haveTex) { g_sh.extTex = b.BindPoint; haveTex = true; }
        if (b.Type == D3D_SIT_SAMPLER && !haveSmp) { g_sh.extSmp = b.BindPoint; haveSmp = true; }
    }

    for (UINT c = 0; c < sd.ConstantBuffers && g_sh.extCbCount < 4; ++c) {
        ID3D11ShaderReflectionConstantBuffer* cb = refl->GetConstantBufferByIndex(c);
        D3D11_SHADER_BUFFER_DESC cd;
        if (!cb || cb->GetDesc(&cd) < 0 || cd.Type != D3D_CT_CBUFFER) continue;
        D3D11_SHADER_INPUT_BIND_DESC b;
        if (refl->GetResourceBindingDescByName(cd.Name, &b) < 0) continue;
        const int ci = g_sh.extCbCount;
        ExtCB& e = g_sh.extCb[ci];
        e.slot = b.BindPoint;
        e.size = (cd.Size + 15) & ~15u;
        if (e.size > sizeof(e.data)) e.size = sizeof(e.data);
        memset(e.data, 0, sizeof(e.data));
        D3D11_BUFFER_DESC bd = {};
        bd.ByteWidth = e.size;
        bd.Usage     = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        e.buf = nullptr;
        if (g_sh.dev->CreateBuffer(&bd, nullptr, &e.buf) < 0) continue;
        ++g_sh.extCbCount;

        for (UINT v = 0; v < cd.Variables && g_sh.extVarCount < 48; ++v) {
            ID3D11ShaderReflectionVariable* var = cb->GetVariableByIndex(v);
            D3D11_SHADER_VARIABLE_DESC vd;
            D3D11_SHADER_TYPE_DESC     td;
            if (!var || var->GetDesc(&vd) < 0 || var->GetType()->GetDesc(&td) < 0) continue;
            if (vd.StartOffset + vd.Size > e.size) continue;
            if (vd.DefaultValue) memcpy(e.data + vd.StartOffset, vd.DefaultValue, vd.Size);
            if ((td.Class != D3D_SVC_SCALAR && td.Class != D3D_SVC_VECTOR) ||
                (td.Type != D3D_SVT_FLOAT && td.Type != D3D_SVT_INT && td.Type != D3D_SVT_UINT && td.Type != D3D_SVT_BOOL))
                continue;
            ExtVar& x = g_sh.extVar[g_sh.extVarCount++];
            strncpy_s(x.name, sizeof(x.name), vd.Name, _TRUNCATE);
            x.cb     = ci;
            x.offset = vd.StartOffset;
            x.size   = vd.Size;
            x.isInt  = td.Type != D3D_SVT_FLOAT;
            x.count  = (int)(td.Rows * td.Columns);
            if (x.count < 1) x.count = 1;
            if (x.count > 16) x.count = 16;
            float val[16];
            const int n = ShReadIniValues(x.name, val);
            if (n > 0)                                 { ShSetVar(x, val, n); x.source = SV_INI; }
            else if (ShNameIs(x.name, SH_AUTO_SCREEN)) x.source = SV_AUTO_SCREEN;
            else if (ShNameIs(x.name, SH_AUTO_SOURCE)) x.source = SV_AUTO_SOURCE;
            else if (ShNameIs(x.name, SH_AUTO_FRAME))  x.source = SV_AUTO_FRAME;
            else x.source = vd.DefaultValue ? SV_DEFAULT : SV_ZERO;
        }
    }
    SafeRelease(refl);

    const char* slash = strrchr(g_shExtPathA, '\\');
    Log("Shader: external shader %s loaded.", slash ? slash + 1 : g_shExtPathA);
    for (int i = 0; i < g_sh.extVarCount; ++i) {
        const ExtVar& x = g_sh.extVar[i];
        const BYTE* p = g_sh.extCb[x.cb].data + x.offset;
        char vals[128] = "";
        int n = 0;
        for (int k = 0; k < x.count && k < 4 && n >= 0 && n < 100; ++k) {
            float fv; int iv;
            if (x.isInt) { memcpy(&iv, p + k * 4, 4); n += _snprintf_s(vals + n, sizeof(vals) - n, _TRUNCATE, "%s%d", k ? "," : "", iv); }
            else         { memcpy(&fv, p + k * 4, 4); n += _snprintf_s(vals + n, sizeof(vals) - n, _TRUNCATE, "%s%g", k ? "," : "", fv); }
        }
        switch (x.source) {
        case SV_INI:         Log("   %s = %s (from the ini)", x.name, vals); break;
        case SV_DEFAULT:     Log("   %s = %s (default of the shader)", x.name, vals); break;
        case SV_AUTO_SCREEN: Log("   %s = screen size (automatic)", x.name); break;
        case SV_AUTO_SOURCE: Log("   %s = size of the original picture (automatic)", x.name); break;
        case SV_AUTO_FRAME:  Log("   %s = frame counter (automatic)", x.name); break;
        default:             Log("   %s = 0 (not set: add %s=... to [ShaderParameters])", x.name, x.name); break;
        }
    }
}

// Saved pipeline state of the game (what the shader pass changes).
struct ShState {
    D3D11_VIEWPORT            vp[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
    D3D11_RECT                sc[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
    UINT                      vpCount, scCount;
    ID3D11RasterizerState*    rs;
    ID3D11BlendState*         blend;
    FLOAT                     blendFactor[4];
    UINT                      sampleMask;
    ID3D11DepthStencilState*  depth;
    UINT                      stencilRef;
    ID3D11RenderTargetView*   rtv[D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT];
    ID3D11DepthStencilView*   dsv;
    ID3D11ShaderResourceView* psSrv[8];
    ID3D11SamplerState*       psSmp[8];
    ID3D11Buffer*             psCb[8];
    ID3D11PixelShader*        ps;    ID3D11ClassInstance* psInst[256]; UINT psInstN;
    ID3D11VertexShader*       vs;    ID3D11ClassInstance* vsInst[256]; UINT vsInstN;
    ID3D11GeometryShader*     gs;    ID3D11ClassInstance* gsInst[256]; UINT gsInstN;
    ID3D11HullShader*         hs;    ID3D11ClassInstance* hsInst[256]; UINT hsInstN;
    ID3D11DomainShader*       ds;    ID3D11ClassInstance* dsInst[256]; UINT dsInstN;
    D3D11_PRIMITIVE_TOPOLOGY  topology;
    ID3D11InputLayout*        layout;

    void Save(ID3D11DeviceContext* c)
    {
        vpCount = scCount = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
        c->RSGetViewports(&vpCount, vp);
        c->RSGetScissorRects(&scCount, sc);
        c->RSGetState(&rs);
        c->OMGetBlendState(&blend, blendFactor, &sampleMask);
        c->OMGetDepthStencilState(&depth, &stencilRef);
        c->OMGetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, rtv, &dsv);
        c->PSGetShaderResources(0, 8, psSrv);
        c->PSGetSamplers(0, 8, psSmp);
        c->PSGetConstantBuffers(0, 8, psCb);
        psInstN = vsInstN = gsInstN = hsInstN = dsInstN = 256;
        c->PSGetShader(&ps, psInst, &psInstN);
        c->VSGetShader(&vs, vsInst, &vsInstN);
        c->GSGetShader(&gs, gsInst, &gsInstN);
        c->HSGetShader(&hs, hsInst, &hsInstN);
        c->DSGetShader(&ds, dsInst, &dsInstN);
        c->IAGetPrimitiveTopology(&topology);
        c->IAGetInputLayout(&layout);
    }

    template <class T> static void ReleaseAll(T** p, UINT n) { for (UINT i = 0; i < n; ++i) SafeRelease(p[i]); }

    void Restore(ID3D11DeviceContext* c)
    {
        c->RSSetViewports(vpCount, vp);
        c->RSSetScissorRects(scCount, sc);
        c->RSSetState(rs);                              SafeRelease(rs);
        c->OMSetBlendState(blend, blendFactor, sampleMask); SafeRelease(blend);
        c->OMSetDepthStencilState(depth, stencilRef);   SafeRelease(depth);
        c->OMSetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, rtv, dsv);
        ReleaseAll(rtv, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT); SafeRelease(dsv);
        c->PSSetShaderResources(0, 8, psSrv);           ReleaseAll(psSrv, 8);
        c->PSSetSamplers(0, 8, psSmp);                  ReleaseAll(psSmp, 8);
        c->PSSetConstantBuffers(0, 8, psCb);            ReleaseAll(psCb, 8);
        c->PSSetShader(ps, psInst, psInstN);            SafeRelease(ps); ReleaseAll(psInst, psInstN);
        c->VSSetShader(vs, vsInst, vsInstN);            SafeRelease(vs); ReleaseAll(vsInst, vsInstN);
        c->GSSetShader(gs, gsInst, gsInstN);            SafeRelease(gs); ReleaseAll(gsInst, gsInstN);
        c->HSSetShader(hs, hsInst, hsInstN);            SafeRelease(hs); ReleaseAll(hsInst, hsInstN);
        c->DSSetShader(ds, dsInst, dsInstN);            SafeRelease(ds); ReleaseAll(dsInst, dsInstN);
        c->IASetPrimitiveTopology(topology);
        c->IASetInputLayout(layout);                    SafeRelease(layout);
    }
};
static ShState g_shState;

// Draws the shader over the back buffer of 'sc'.
static void ShApply(IDXGISwapChain* sc, int mode)
{
    ID3D11Device* dev = nullptr;
    if (sc->GetDevice(__uuidof(ID3D11Device), (void**)&dev) < 0 || !dev) return;
    if (dev != g_sh.dev) {
        if (!ShInitDevice(dev)) g_sh.broken = true;
    }
    ID3D11Texture2D*        bb  = nullptr;
    ID3D11DeviceContext*    ctx = nullptr;
    ID3D11RenderTargetView* rtv = nullptr;
    ID3D11PixelShader*      ps  = nullptr;
    D3D11_TEXTURE2D_DESC    bd;
    D3D11_RENDER_TARGET_VIEW_DESC rd = {};

    if (g_sh.broken) goto done;
    if (sc->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&bb) < 0 || !bb) goto done;
    bb->GetDesc(&bd);
    if (!ShEnsureCopy(bd)) goto done;

    if (mode == SH_EXTERNAL) {
        if (InterlockedExchange(&g_shExtReload, 0)) ShLoadExternal();
        ps = g_sh.psExt;
    } else {
        ps = g_sh.psCrt;
    }
    if (!ps) goto done;

    rd.Format        = ShTypedFormat(bd.Format);
    rd.ViewDimension = bd.SampleDesc.Count > 1 ? D3D11_RTV_DIMENSION_TEXTURE2DMS : D3D11_RTV_DIMENSION_TEXTURE2D;
    if (dev->CreateRenderTargetView(bb, &rd, &rtv) < 0) goto done;
    dev->GetImmediateContext(&ctx);
    if (!ctx) goto done;

    {
        // The finished picture
        if (bd.SampleDesc.Count > 1) ctx->ResolveSubresource(g_sh.copy, 0, bb, 0, ShTypedFormat(bd.Format));
        else                         ctx->CopyResource(g_sh.copy, bb);

        const float w = (float)bd.Width, h = (float)bd.Height;
        ++g_shFrames;
        UINT texSlot = 0, smpSlot = 0;
        if (mode == SH_EXTERNAL) {
            const float lines = 224.0f;                  // lines of the original picture
            const float screen[4] = { w, h, 1.0f / w, 1.0f / h };
            const float srcW = (float)(int)(lines * w / h + 0.5f);
            const float source[4] = { srcW, lines, 1.0f / srcW, 1.0f / lines };
            const float frame[1]  = { (float)g_shFrames };
            for (int i = 0; i < g_sh.extVarCount; ++i) {
                const ExtVar& x = g_sh.extVar[i];
                if      (x.source == SV_AUTO_SCREEN) ShSetVar(x, screen, 4);
                else if (x.source == SV_AUTO_SOURCE) ShSetVar(x, source, 4);
                else if (x.source == SV_AUTO_FRAME)  ShSetVar(x, frame, 1);
            }
            for (int i = 0; i < g_sh.extCbCount; ++i)
                ctx->UpdateSubresource(g_sh.extCb[i].buf, 0, nullptr, g_sh.extCb[i].data, 0, 0);
            texSlot = g_sh.extTex;
            smpSlot = g_sh.extSmp;
        } else {
            const float params[8] = { g_crtSizeW > 0.0f ? g_crtSizeW : w, g_crtSizeH > 0.0f ? g_crtSizeH : h, 0.0f, 0.0f,
                                      g_crtRow2, g_crtRow3, g_crtOverspill, g_crtDiagonal };
            ctx->UpdateSubresource(g_sh.cbCrt, 0, nullptr, params, 0, 0);
        }

        g_shState.Save(ctx);

        D3D11_VIEWPORT vp = { 0.0f, 0.0f, w, h, 0.0f, 1.0f };
        const FLOAT zero[4] = { 0, 0, 0, 0 };
        ctx->RSSetViewports(1, &vp);
        ctx->RSSetState(nullptr);
        ctx->OMSetBlendState(nullptr, zero, 0xFFFFFFFF);
        ctx->OMSetDepthStencilState(nullptr, 0);
        ctx->OMSetRenderTargets(1, &rtv, nullptr);
        ctx->IASetInputLayout(nullptr);
        ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        ctx->VSSetShader(g_sh.vs, nullptr, 0);
        ctx->GSSetShader(nullptr, nullptr, 0);
        ctx->HSSetShader(nullptr, nullptr, 0);
        ctx->DSSetShader(nullptr, nullptr, 0);
        ctx->PSSetShader(ps, nullptr, 0);
        ctx->PSSetShaderResources(texSlot, 1, &g_sh.copySrv);
        ctx->PSSetSamplers(smpSlot, 1, &g_sh.sampler);
        if (mode == SH_EXTERNAL) {
            for (int i = 0; i < g_sh.extCbCount; ++i)
                ctx->PSSetConstantBuffers(g_sh.extCb[i].slot, 1, &g_sh.extCb[i].buf);
        } else {
            ctx->PSSetConstantBuffers(0, 1, &g_sh.cbCrt);
        }
        ctx->Draw(3, 0);

        g_shState.Restore(ctx);
    }

done:
    SafeRelease(ctx);
    SafeRelease(rtv);
    SafeRelease(bb);
    SafeRelease(dev);
}

// Replaces 'mov ecx,[eax]; call [ecx+0x20]' at 0x43a653: the game's only call
// of IDXGISwapChain::Present (same arguments, __stdcall).
static HRESULT STDMETHODCALLTYPE Hook_Present(IDXGISwapChain* sc, UINT syncInterval, UINT flags)
{
    const int mode = g_shMode;
    if (mode != SH_OFF && !(flags & DXGI_PRESENT_TEST))
        ShApply(sc, mode);
    Present_t present = (Present_t)(*(void***)sc)[8];
    return present(sc, syncInterval, flags);
}

static bool ShHookPresent()
{
    BYTE* p = VA(0x0043A653);
    static const BYTE expect[5] = { 0x8B, 0x08, 0xFF, 0x51, 0x20 };   // mov ecx,[eax]; call [ecx+0x20]
    if (memcmp(p, expect, 5) != 0) {
        Log("Shader: the call of Present is not as expected - shaders are off.");
        return false;
    }
    return WriteBranch(p, 0xE8, (void*)&Hook_Present, 5);
}

static DWORD WINAPI ShaderKeyThread(LPVOID)
{
    bool wasDown = false;
    for (;;) {
        Sleep(30);
        bool down = (GetAsyncKeyState(g_shKey) & 0x8000) != 0;
        if (down && !wasDown && GameHasFocus()) {
            int pos = 0;
            for (int i = 0; i < g_shCycleCount; ++i)
                if (g_shCycle[i] == g_shMode) pos = i;
            int next = g_shCycle[(pos + 1) % g_shCycleCount];
            if (next == SH_EXTERNAL) InterlockedExchange(&g_shExtReload, 1);   // pick up changes to the file
            g_shMode = next;
            wchar_t v[4];
            swprintf_s(v, 4, L"%d", next);
            WritePrivateProfileStringW(L"Shader", L"Mode", v, g_ini);
            Log("Shader: %s.", SHADER_NAMES[next]);
        }
        wasDown = down;
    }
}

static float ReadIniFloat(const wchar_t* section, const wchar_t* key, float def)
{
    wchar_t str[32];
    GetPrivateProfileStringW(section, key, L"", str, 32, g_ini);
    if (!str[0]) return def;
    return (float)_wtof(str);
}

static void Install_Shader()
{
    g_crtRow2      = ReadIniFloat(L"Shader", L"BrightnessRow2", 0.8f);
    g_crtRow3      = ReadIniFloat(L"Shader", L"BrightnessRow3", 0.6f);
    g_crtOverspill = ReadIniFloat(L"Shader", L"Overspill", 0.8f);
    g_crtDiagonal  = ReadIniFloat(L"Shader", L"Diagonal", 0.0f);
    {
        // TextureSize: width,height of the mask grid; 0 or empty = screen size
        wchar_t str[64];
        GetPrivateProfileStringW(L"Shader", L"TextureSize", L"0", str, 64, g_ini);
        wchar_t* e = nullptr;
        g_crtSizeW = (float)wcstod(str, &e);
        while (e && (*e == L',' || *e == L' ')) ++e;
        g_crtSizeH = (e && *e) ? (float)wcstod(e, nullptr) : 0.0f;
        if (g_crtSizeW <= 0.0f || g_crtSizeH <= 0.0f) g_crtSizeW = g_crtSizeH = 0.0f;
    }

    // External shader: Path (relative to the game folder, or a full path) + Filename
    wchar_t dir[MAX_PATH], file[MAX_PATH], entry[64];
    GetPrivateProfileStringW(L"Shader", L"Path", L"shaders", dir, MAX_PATH, g_ini);
    GetPrivateProfileStringW(L"Shader", L"Filename", L"", file, MAX_PATH, g_ini);
    GetPrivateProfileStringW(L"Shader", L"Entry", L"main", entry, 64, g_ini);
    const wchar_t* d = dir;
    const bool absolute = (d[0] && d[1] == L':') || (d[0] == L'\\' && d[1] == L'\\');
    if (!absolute) while (*d == L'\\' || *d == L'/') ++d;
    size_t dl = wcslen(d);
    const wchar_t* sep = (dl && d[dl - 1] != L'\\' && d[dl - 1] != L'/') ? L"\\" : L"";
    if (absolute) swprintf_s(g_shExtPath, MAX_PATH, L"%s%s%s", d, sep, file);
    else          swprintf_s(g_shExtPath, MAX_PATH, L"%s%s%s%s", g_dir, d, sep, file);
    WideCharToMultiByte(CP_ACP, 0, g_shExtPath, -1, g_shExtPathA, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_ACP, 0, entry, -1, g_shExtEntry, sizeof(g_shExtEntry), nullptr, nullptr);
    g_shExtFound = file[0] && GetFileAttributesW(g_shExtPath) != INVALID_FILE_ATTRIBUTES;

    wchar_t cycleStr[32];
    GetPrivateProfileStringW(L"Shader", L"Cycle", L"0,1", cycleStr, 32, g_ini);
    g_shCycleCount = 0;
    bool extSkipped = false;
    for (const wchar_t* c = cycleStr; *c && g_shCycleCount < SH_MODES; ++c)
        if (*c >= L'0' && *c <= L'2') {
            int m = *c - L'0';
            if (m == SH_EXTERNAL && !g_shExtFound) { extSkipped = file[0] != 0; continue; }
            bool dup = false;
            for (int i = 0; i < g_shCycleCount; ++i) dup |= (g_shCycle[i] == m);
            if (!dup) g_shCycle[g_shCycleCount++] = m;
        }

    int mode = (int)GetPrivateProfileIntW(L"Shader", L"Mode", SH_OFF, g_ini);
    if (mode < 0 || mode >= SH_MODES) mode = SH_OFF;
    if (mode == SH_EXTERNAL && !g_shExtFound) mode = SH_OFF;
    g_shMode = mode;

    wchar_t keyStr[32];
    GetPrivateProfileStringW(L"Shader", L"Hotkey", L"F8", keyStr, 32, g_ini);
    int key = ParseKeyName(keyStr);
    if (key) g_shKey = key;
    else     Log("Shader: unknown hotkey '%ls', using F8.", keyStr);

    if (!ShHookPresent()) return;
    g_shEnabled = true;
    if (extSkipped)
        Log("Shader: external shader %s not found - mode 2 is left out.", g_shExtPathA);
    if (g_shCycleCount >= 2) {
        HANDLE h = CreateThread(nullptr, 0, ShaderKeyThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
        Log("Shader: hotkey %ls, cycle %ls, starting with %s.", key ? keyStr : L"F8", cycleStr, SHADER_NAMES[mode]);
    } else {
        Log("Shader: %s (no hotkey: Cycle '%ls' has fewer than two modes).", SHADER_NAMES[mode], cycleStr);
    }
}


#ifdef GA_DIAG
// ============================================================================
//  DIAGNOSTIC BUILD ONLY (build_diag.bat defines GA_DIAG)
//
//  Battle analysis:
//   F7   Draw recorder: for 60 battle ticks, measure per call site in the
//        battle loop how many bytes of packets (battle DB +0), HD records and
//        depth-sort entries (DAT_00713c60) each call adds.
//   F11  Memory scan: for 31 battle ticks, capture .data and the first part
//        of the battle work area (*DAT_006d1a98) after the battle tick, and
//        log every dword that changed in most ticks.
// ============================================================================

static const CallSite BATTLE_CALLS[] = {
    // battle main loop FUN_00491eb0
    { 0x0049227C, 0x00497050 },
    { 0x004922D1, 0x00498C20 },   // the battle tick (index 1, used as tick marker)
    { 0x004922D6, 0x004927F0 },
    { 0x004923A8, 0x00496100 },
    // FUN_00498c20
    { 0x00498CCA, 0x00401570 }, { 0x00498D3D, 0x004982D0 }, { 0x00498D42, 0x0052ECA0 },
    { 0x00498DD3, 0x00496A60 }, { 0x00498DD8, 0x00499100 }, { 0x00498E10, 0x00537830 },
    { 0x00498E64, 0x004994F0 }, { 0x00498E69, 0x00499100 }, { 0x00498EAA, 0x0052DA20 },
    { 0x00498EFB, 0x0052DA20 }, { 0x00498F29, 0x0052DA20 }, { 0x00498F58, 0x0052DA20 },
    { 0x00498F69, 0x0052F500 }, { 0x00498FAD, 0x00537830 }, { 0x00498FB5, 0x0052F990 },
    { 0x00498FBA, 0x0052FC70 }, { 0x0049903E, 0x00403A00 },
    // FUN_0052f990
    { 0x0052FA2D, 0x00492EB0 }, { 0x0052FA4E, 0x00492EB0 }, { 0x0052FA5C, 0x00492EB0 },
    { 0x0052FA66, 0x00492EB0 }, { 0x0052FA84, 0x00492EB0 }, { 0x0052FA92, 0x00492EB0 },
    { 0x0052FAA7, 0x00532AC0 }, { 0x0052FAB3, 0x005318F0 }, { 0x0052FABC, 0x00533060 },
    { 0x0052FB31, 0x005318F0 }, { 0x0052FB8E, 0x00532580 }, { 0x0052FBD8, 0x005318F0 },
    { 0x0052FC35, 0x00532580 },
    // FUN_0052fc70
    { 0x0052FC77, 0x005331D0 }, { 0x0052FCE5, 0x00492EB0 }, { 0x0052FD06, 0x00492EB0 },
    { 0x0052FD14, 0x00492EB0 }, { 0x0052FD1E, 0x00492EB0 }, { 0x0052FD3C, 0x00492EB0 },
    { 0x0052FD4A, 0x00492EB0 }, { 0x0052FD5F, 0x00532AC0 }, { 0x0052FD6B, 0x005302A0 },
    { 0x0052FD74, 0x00533060 }, { 0x0052FD87, 0x00530F30 }, { 0x0052FEA3, 0x005302A0 },
    { 0x0052FEB8, 0x00530F30 }, { 0x0052FF0F, 0x00532580 }, { 0x0053004E, 0x005302A0 },
    { 0x00530063, 0x00530F30 }, { 0x005300C3, 0x00532580 }, { 0x00530113, 0x005318F0 },
    { 0x00530123, 0x00530F30 },
};
static const int NUM_BSITES  = sizeof(BATTLE_CALLS) / sizeof(BATTLE_CALLS[0]);
static const int BTICK_SITE  = 1;
static const int REC_TICKS   = 60;

struct RecStat { long long pk, hd, sort; int pkHits, hdHits, sortHits, calls; };
static RecStat g_bStat[NUM_BSITES];
static DWORD   g_bRet[NUM_BSITES];
static DWORD   g_bPk0[NUM_BSITES], g_bHd0[NUM_BSITES], g_bSort0[NUM_BSITES];
static volatile bool g_recActive = false;
static int     g_recTicks = 0;

static bool    g_f9WasDown = false, g_f11WasDown = false;

static DWORD RecCurPk()
{
    BYTE* db = G<BYTE*>(0x00713C64);             // battle draw buffer, +0 = packet cursor
    return db ? *(DWORD*)db : 0;
}
static DWORD RecCurHd()
{
    DWORD* v = G<DWORD*>(Addr::HdListLogic);
    return v ? (v[1] - v[0]) / HD_REC_SIZE : 0;
}
static DWORD RecCurSort() { return G<DWORD>(0x00713C60); }

// ---- memory scan ----
static const int   SCAN_TICKS    = 31;
static const DWORD SCAN_DATA_LEN = 0x1D1000;       // .data 0x610000..0x7E1000
static const DWORD SCAN_HEAP_LEN = 0x27F00;        // battle work area up to the sort list
static const DWORD SCAN_DW       = (SCAN_DATA_LEN + SCAN_HEAP_LEN) / 4;
static DWORD* g_scanPrev  = nullptr;
static DWORD* g_scanFirst = nullptr;
static DWORD* g_scanCur   = nullptr;
static BYTE*  g_scanCnt   = nullptr;
static int    g_scanTick  = -1;

static void ScanCapture(DWORD* out)
{
    memcpy(out, VA(0x00610000), SCAN_DATA_LEN);
    BYTE* heap = G<BYTE*>(0x006D1A98);
    if (heap) memcpy((BYTE*)out + SCAN_DATA_LEN, heap, SCAN_HEAP_LEN);
    else      memset((BYTE*)out + SCAN_DATA_LEN, 0, SCAN_HEAP_LEN);
}

static bool ScanNoise(DWORD a)
{
    if (a >= 0x00713CC0 && a < 0x00713DE8) return true;   // battle draw buffers
    if (a >= 0x00640C30 && a < 0x00640DA8) return true;   // vblank counter, GTE registers
    if (a >= 0x0063F880 && a < 0x0063F890) return true;   // last flip tick
    return false;
}

static void ScanStep()
{
    if (g_scanTick < 0) return;
    ScanCapture(g_scanCur);
    if (g_scanTick == 0) {
        memcpy(g_scanFirst, g_scanCur, SCAN_DW * 4);
        memset(g_scanCnt, 0, SCAN_DW);
    } else {
        for (DWORD i = 0; i < SCAN_DW; ++i)
            if (g_scanCur[i] != g_scanPrev[i] && g_scanCnt[i] < 255) ++g_scanCnt[i];
    }
    DWORD* t = g_scanPrev; g_scanPrev = g_scanCur; g_scanCur = t;
    if (++g_scanTick < SCAN_TICKS) return;

    const int minCount = (SCAN_TICKS - 1) * 2 / 3;
    Log("=== Memory scan: dwords that changed in >= %d of %d battle ticks (first -> last, count) ===",
        minCount, SCAN_TICKS - 1);
    int shown = 0;
    for (DWORD i = 0; i < SCAN_DW; ++i) {
        if (g_scanCnt[i] < minCount) continue;
        bool heap = i >= SCAN_DATA_LEN / 4;
        DWORD addr = heap ? (i * 4 - SCAN_DATA_LEN) : 0x00610000 + i * 4;
        if (!heap && ScanNoise(addr)) continue;
        if (++shown > 600) continue;
        if (heap) Log("  heap+%05lX: %08lX -> %08lX (%d)", addr, g_scanFirst[i], g_scanPrev[i], g_scanCnt[i]);
        else      Log("  %08lX: %08lX -> %08lX (%d)", addr, g_scanFirst[i], g_scanPrev[i], g_scanCnt[i]);
    }
    Log("=== end of memory scan (%d dwords%s) ===", shown, shown > 600 ? ", first 600 shown" : "");
    g_scanTick = -1;
}

static void RecReport()
{
    Log("=== Battle draw recorder over %d ticks (average per tick; hits = calls that added something) ===", REC_TICKS);
    Log("  site      target     calls  packets(bytes) hits  HD records hits  sort entries hits");
    for (int i = 0; i < NUM_BSITES; ++i) {
        const RecStat& s = g_bStat[i];
        Log("  %08lX -> %08lX  %4d   %8lld   %3d   %6lld   %3d   %6lld   %3d",
            BATTLE_CALLS[i].site, BATTLE_CALLS[i].target, s.calls,
            s.pk / REC_TICKS, s.pkHits, s.hd / REC_TICKS, s.hdHits, s.sort / REC_TICKS, s.sortHits);
    }
    Log("=== end of recorder ===");
}

static void PollDiagKeys()
{
    bool f9  = (GetAsyncKeyState(VK_F7)  & 0x8000) != 0;
    bool f11 = (GetAsyncKeyState(VK_F11) & 0x8000) != 0;
    if (f9 && !g_f9WasDown && !g_recActive) {
        memset(g_bStat, 0, sizeof(g_bStat));
        g_recTicks = 0;
        g_recActive = true;
        Log("Battle draw recorder started (F7), %d ticks...", REC_TICKS);
    }
    if (f11 && !g_f11WasDown && g_scanTick < 0) {
        if (!g_scanCnt) {
            BYTE* m = (BYTE*)VirtualAlloc(nullptr, SCAN_DW * 13, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m) {
                g_scanPrev = (DWORD*)m; g_scanFirst = g_scanPrev + SCAN_DW; g_scanCur = g_scanFirst + SCAN_DW;
                g_scanCnt = (BYTE*)(g_scanCur + SCAN_DW);
            }
        }
        if (g_scanCnt) {
            g_scanTick = 0;
            Log("Memory scan started (F11), %d ticks...", SCAN_TICKS);
        }
    }
    g_f9WasDown = f9; g_f11WasDown = f11;
}

static void __cdecl RecBefore(int idx)
{
    if (idx == BTICK_SITE && GameHasFocus())
        PollDiagKeys();
    g_bPk0[idx] = RecCurPk(); g_bHd0[idx] = RecCurHd(); g_bSort0[idx] = RecCurSort();
    switch (BATTLE_CALLS[idx].site) {
    case 0x00498E64: BChkCapture(CK_SKY);  break;
    case 0x00498FB5: BChkCapture(CK_OBJA); break;
    case 0x00498FBA: BChkCapture(CK_OBJB); break;
    }
}

static void __cdecl RecAfter(int idx)
{
    g_bLastPk[idx] = (long)(RecCurPk() - g_bPk0[idx]);
    if (BATTLE_CALLS[idx].site == 0x00498FBA) BChkCapture(CK_AFTER);
    if (idx == 2) g_bLastSort = (long)RecCurSort();
    if (g_recActive) {
        RecStat& s = g_bStat[idx];
        long long dp = (long long)RecCurPk()   - (long long)g_bPk0[idx];
        long long dh = (long long)RecCurHd()   - (long long)g_bHd0[idx];
        long long ds = (long long)RecCurSort() - (long long)g_bSort0[idx];
        s.calls++;
        if (dp > 0) { s.pk += dp;   s.pkHits++; }
        if (dh > 0) { s.hd += dh;   s.hdHits++; }
        if (ds > 0) { s.sort += ds; s.sortHits++; }
    }
    if (idx == BTICK_SITE) {
        ScanStep();
        if (g_recActive && ++g_recTicks >= REC_TICKS) {
            g_recActive = false;
            RecReport();
        }
    }
}

// For the mismatch log: every call in the battle loop and the battle tick that
// added packets in the last real frame (the calls inside the object draw
// functions are left out, the interpolated frame passes through those too).
static void LogRealTickSites()
{
    char line[512];
    int n = 0;
    line[0] = 0;
    for (int i = 0; i < NUM_BSITES; ++i) {
        if (BATTLE_CALLS[i].site >= 0x0052F000 || i == BTICK_SITE || g_bLastPk[i] == 0) continue;
        n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, " %08lX->%08lX:%ld",
                         BATTLE_CALLS[i].site, BATTLE_CALLS[i].target, g_bLastPk[i]);
        if (n < 0 || n > 400) break;
    }
    Log("   real frame per call:%s", line[0] ? line : " (none)");
}

static void Install_BattleDiag()
{
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, NUM_BSITES * 64, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!mem) { Log("Battle diag: out of memory."); return; }

    int ok = 0;
    for (int i = 0; i < NUM_BSITES; ++i) {
        if (!IsCallTo(BATTLE_CALLS[i].site, BATTLE_CALLS[i].target)) {
            Log("Battle diag: call at %08lX is not as expected - skipped.", BATTLE_CALLS[i].site);
            continue;
        }
        BYTE* site   = VA(BATTLE_CALLS[i].site);
        BYTE* target = VA(BATTLE_CALLS[i].target);
        BYTE* t = mem + i * 64;
        BYTE* p = t;
        Emit8(p, 0x60); Emit8(p, 0x9C);                                   // pushad; pushfd
        Emit8(p, 0x68); Emit32(p, (DWORD)i);                              // push i
        EmitRel(p, 0xE8, (void*)&RecBefore);                              // call RecBefore
        Emit8(p, 0x83); Emit8(p, 0xC4); Emit8(p, 0x04);                   // add esp,4
        Emit8(p, 0x9D); Emit8(p, 0x61);                                   // popfd; popad
        Emit8(p, 0x8F); Emit8(p, 0x05); Emit32(p, (DWORD)(uintptr_t)&g_bRet[i]);   // pop [ret]
        BYTE* pushAfter = p;
        Emit8(p, 0x68); Emit32(p, 0);                                     // push <after>
        EmitRel(p, 0xE9, target);                                         // jmp target
        DWORD afterAddr = (DWORD)(uintptr_t)p;
        memcpy(pushAfter + 1, &afterAddr, 4);
        Emit8(p, 0xFF); Emit8(p, 0x35); Emit32(p, (DWORD)(uintptr_t)&g_bRet[i]);   // push [ret]
        Emit8(p, 0x60); Emit8(p, 0x9C);                                   // pushad; pushfd
        Emit8(p, 0x68); Emit32(p, (DWORD)i);                              // push i
        EmitRel(p, 0xE8, (void*)&RecAfter);                               // call RecAfter
        Emit8(p, 0x83); Emit8(p, 0xC4); Emit8(p, 0x04);                   // add esp,4
        Emit8(p, 0x9D); Emit8(p, 0x61);                                   // popfd; popad
        Emit8(p, 0xC3);                                                   // ret
        if (WriteBranch(site, 0xE8, t, 5)) ++ok;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, NUM_BSITES * 64);
    Log("DIAGNOSTIC BUILD: battle diag installed on %d of %d calls. In battle: F7 = draw recorder, F11 = memory scan.",
        ok, NUM_BSITES);
}
// ---- Draw origin tracer (F5 start / F5 stop) ----
//  Every call of an HD record appender (one per HD-textured prim) is counted
//  per (call site, caller, caller's caller), separately for real frames and
//  interpolated frames. The report lists what the real frames draw more often
//  than the interpolated frames: that is what is missing (or extra) there.

struct TraceEntry { DWORD site, r1, r2; LONG real, tween; };
static const int TRACE_SLOTS = 8192;
static TraceEntry  g_trace[TRACE_SLOTS];
static volatile bool g_traceActive = false;

static void __cdecl TraceHit(int idx, DWORD ebp)
{
    if (!g_traceActive) return;
    DWORD r1 = 0, r2 = 0;
    if (OnStack(ebp)) {
        r1 = *(DWORD*)(ebp + 4);
        DWORD e2 = *(DWORD*)ebp;
        if (OnStack(e2)) r2 = *(DWORD*)(e2 + 4);
    }
    DWORD site = APPEND_CALLS[idx].site;
    DWORD h = (site * 2654435761u) ^ (r1 * 40503u) ^ (r2 * 2246822519u);
    for (int n = 0; n < TRACE_SLOTS; ++n) {
        TraceEntry& e = g_trace[(h + n) & (TRACE_SLOTS - 1)];
        if (e.site == 0) { e.site = site; e.r1 = r1; e.r2 = r2; }
        if (e.site == site && e.r1 == r1 && e.r2 == r2) {
            if (g_inTween) ++e.tween; else ++e.real;
            return;
        }
    }
}

static DWORD ToGhidra(DWORD a)
{
    BYTE* p = (BYTE*)(uintptr_t)a;
    return (p >= g_base && p < g_base + g_imageSize) ? (DWORD)(p - g_base) + GHIDRA_IMAGE_BASE : a;
}

static int TraceCmp(const void* x, const void* y)
{
    const TraceEntry* a = (const TraceEntry*)x;
    const TraceEntry* b = (const TraceEntry*)y;
    LONG da = a->real - a->tween, db = b->real - b->tween;
    if (da < 0) da = -da;
    if (db < 0) db = -db;
    return (db > da) - (db < da);
}

static void TraceReport()
{
    static TraceEntry sorted[TRACE_SLOTS];
    int n = 0;
    for (int i = 0; i < TRACE_SLOTS; ++i) if (g_trace[i].site) sorted[n++] = g_trace[i];
    qsort(sorted, n, sizeof(TraceEntry), TraceCmp);
    Log("=== Draw origin tracer: %d different origins. Rows where real frames and interpolated frames differ ===", n);
    Log("  appender call  caller      caller's caller   real  interpolated");
    int shown = 0;
    for (int i = 0; i < n && shown < 80; ++i) {
        if (sorted[i].real == sorted[i].tween) continue;
        ++shown;
        Log("  %08lX      %08lX    %08lX         %5ld  %5ld", sorted[i].site,
            ToGhidra(sorted[i].r1), ToGhidra(sorted[i].r2), sorted[i].real, sorted[i].tween);
    }
    Log("=== end of tracer (%d rows differ) ===", shown);
}

// ---- Text watch (F6) ----
//  For the next TW_TWEENS interpolated frames: whether the task drawing was
//  copied (and if not, why), where the ring buffer copy went, what the
//  interpolated frame and the real ticks changed in the HD text registry
//  (vector at 0x640c20, 16-byte entries), and every VRAM upload
//  (FUN_0041f4f0) with its caller and rectangle, real and interpolated.
static const int   TW_TWEENS = 150, TW_LINES = 40, TW_REG_MAX = 1024, TW_DIFF_LOGS = 8;
static const DWORD TXT_REG = 0x00640C20;
static volatile bool g_twStart = false;
static int   g_twLeft = 0, g_twN = 0, g_twDiffLogs = 0, g_twRealDiffLogs = 0;
struct TwLoad { DWORD ret; short r[4]; LONG real, tween; };
static TwLoad g_twLoad[64];
static int   g_twLoadN = 0;
static LONG  g_twLoadLost = 0, g_twLoadsNow = 0;
static LONG  g_twApply[8], g_twBad[8], g_twRegChanged, g_twRealRegChanged, g_twRingWrap, g_twTweenLoads, g_twSkipped;
static BYTE  g_twReg[TW_REG_MAX * 16], g_twRegEnd[TW_REG_MAX * 16];
static DWORD g_twRegLen = 0, g_twRegEndLen = 0;
static bool  g_twHaveEnd = false;
static DWORD g_liCont = 0;

static void __cdecl OnLoadImage(DWORD ret, const short* rect)
{
    if (g_twLeft <= 0 || !rect) return;
    const bool tw = g_inTween;
    if (tw) ++g_twLoadsNow;
    DWORD r = ToGhidra(ret);
    for (int i = 0; i < g_twLoadN; ++i) {
        TwLoad& e = g_twLoad[i];
        if (e.ret == r && memcmp(e.r, rect, 8) == 0) { if (tw) ++e.tween; else ++e.real; return; }
    }
    if (g_twLoadN < 64) {
        TwLoad& e = g_twLoad[g_twLoadN++];
        e.ret = r; memcpy(e.r, rect, 8);
        e.real = tw ? 0 : 1; e.tween = tw ? 1 : 0;
    } else {
        ++g_twLoadLost;
    }
}

static __declspec(naked) void Stub_LoadImage() { __asm {
    pushad
    push ecx                        // rectangle
    push dword ptr [esp + 0x24]     // return address
    call OnLoadImage
    add  esp, 8
    popad
    push ebp
    mov  ebp, esp
    and  esp, 0xFFFFFFF8
    jmp  dword ptr [g_liCont]
} }

static void Install_LoadImageWatch()
{
    BYTE* p = VA(0x0041F4F0);
    static const BYTE expect[6] = { 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8 };
    if (memcmp(p, expect, 6) != 0) { Log("Text watch: start of FUN_0041f4f0 is not as expected."); return; }
    g_liCont = (DWORD)(uintptr_t)(p + 6);
    WriteBranch(p, 0xE9, (void*)&Stub_LoadImage, 6);
}

static const BYTE* RegData(DWORD* len)
{
    DWORD b = G<DWORD>(TXT_REG), e = G<DWORD>(TXT_REG + 4);
    *len = (b && e >= b) ? e - b : 0;
    return (const BYTE*)(uintptr_t)b;
}

static void TwEntry(const char* tag, const BYTE* e)
{
    const short* r = (const short*)(e + 8);
    Log("      %s %08lX %08lX  VRAM x %d y %d, %d x %d", tag, *(const DWORD*)e, *(const DWORD*)(e + 4),
        r[0], r[1], r[2], r[3]);
}

static bool TwHas(const BYTE* list, DWORD len, const BYTE* e)
{
    for (DWORD i = 0; i + 16 <= len; i += 16) if (memcmp(list + i, e, 16) == 0) return true;
    return false;
}

// Logs the entries that were added (+) and removed (-) from 'a' to 'b'.
static void TwDiff(const BYTE* a, DWORD alen, const BYTE* b, DWORD blen)
{
    int n = 0;
    for (DWORD i = 0; i + 16 <= blen && n < 12; i += 16)
        if (!TwHas(a, alen, b + i)) { TwEntry("+", b + i); ++n; }
    for (DWORD i = 0; i + 16 <= alen && n < 24; i += 16)
        if (!TwHas(b, blen, a + i)) { TwEntry("-", a + i); ++n; }
    if (!n) Log("      (same entries, different order)");
}

// Appender calls on prims outside the frame buffers (diagnostics)
struct TwApp { int idx; DWORD prim; LONG real, tween; short xReal, xTween; };
static TwApp g_twApp[64];
static int   g_twAppN = 0;
static LONG  g_twAppLost = 0, g_twAppFresh[2];

static void TwAppend(int idx, DWORD prim, int area)
{
    if (g_twLeft <= 0) return;
    const bool tw = g_inTween;
    if (!area) { ++g_twAppFresh[tw ? 1 : 0]; return; }
    const short x = *(const short*)(uintptr_t)(prim + 0x0C);
    for (int i = 0; i < g_twAppN; ++i) {
        TwApp& e = g_twApp[i];
        if (e.idx == idx && e.prim == prim) {
            if (tw) { if (!e.tween++) e.xTween = x; } else { if (!e.real++) e.xReal = x; }
            return;
        }
    }
    if (g_twAppN >= 64) { ++g_twAppLost; return; }
    TwApp& e = g_twApp[g_twAppN++];
    e.idx = idx; e.prim = prim; e.real = e.tween = 0; e.xReal = e.xTween = 0;
    if (tw) { e.tween = 1; e.xTween = x; } else { e.real = 1; e.xReal = x; }
}

// Objects whose position the interpolated frame changes (diagnostics)
struct TwObj { LONG moved, jumped, swapped; LONG maxD; };
static TwObj g_twObj[BNUM_OBJ];
static int   g_twObjLines = 0;

static void TwObjDesc(char* out, size_t n, const BYTE* o)
{
    const DWORD w = (DWORD)(uintptr_t)BWork(), p = (DWORD)(uintptr_t)o;
    if (w && p >= w && p < w + 0x163A00) _snprintf_s(out, n, _TRUNCATE, "work+%05lX", p - w);
    else _snprintf_s(out, n, _TRUNCATE, "%08lX", ToGhidra(p));
}

static void TwObjects(const BattleSnap& a, const BattleSnap& b)
{
    if (g_twLeft <= 0) return;
    for (int i = 0; i < BNUM_OBJ; ++i) {
        BYTE* o = b.obj[i];
        if (!o) continue;
        TwObj& t = g_twObj[i];
        if (a.obj[i] != o) { ++t.swapped; continue; }
        if (a.pos[i][0] == b.pos[i][0] && a.pos[i][1] == b.pos[i][1] && a.pos[i][2] == b.pos[i][2]) continue;
        const bool jump = IsJump(a.pos[i], b.pos[i]) || BToggles(i, a, b);
        if (jump) ++t.jumped; else ++t.moved;
        for (int k = 0; k < 3; ++k) {
            LONG d = (LONG)((unsigned)b.pos[i][k] - (unsigned)a.pos[i][k]);
            if (d < 0) d = -d;
            if (d > t.maxD) t.maxD = d;
        }
        if (g_twObjLines < 40 && g_twN < 4) {
            ++g_twObjLines;
            char where[32]; TwObjDesc(where, sizeof(where), o);
            const DWORD* h = (const DWORD*)o;
            Log("   obj %3d %s: %d,%d,%d -> %d,%d,%d%s | %08lX %08lX %08lX %08lX", i, where,
                a.pos[i][0], a.pos[i][1], a.pos[i][2], b.pos[i][0], b.pos[i][1], b.pos[i][2],
                jump ? (BToggles(i, a, b) ? " (toggles, not interpolated)" : " (jump, not interpolated)") : "", h[0], h[1], h[2], h[3]);
        }
    }
}

static void TwObjReport()
{
    Log("  objects moved by the interpolation (index, object, frames interpolated / jumps or toggles / other object in the slot, largest step):");
    int shown = 0;
    for (int i = 0; i < BNUM_OBJ && shown < 40; ++i) {
        const TwObj& t = g_twObj[i];
        if (!t.moved && !t.jumped && !t.swapped) continue;
        ++shown;
        char where[32] = "-";
        if (g_bCur.obj[i]) TwObjDesc(where, sizeof(where), g_bCur.obj[i]);
        Log("    %3d  %-11s  %4ld / %4ld / %4ld   %ld", i, where, t.moved, t.jumped, t.swapped, t.maxD);
    }
}

static void TwReport()
{
    TwObjReport();
    Log("  copy results: copied %ld, no valid capture %ld, empty %ld, state differs %ld, OT %ld, HD room %ld, packets too big %ld, ring full %ld",
        g_twApply[0], g_twApply[1], g_twApply[2], g_twApply[3], g_twApply[4], g_twApply[5], g_twApply[6], g_twApply[7]);
    Log("  registry changed by interpolated frames: %ld, by real ticks: %ld", g_twRegChanged, g_twRealRegChanged);
    Log("  VRAM uploads in interpolated frames: %ld", g_twTweenLoads);
    Log("  VRAM uploads (caller, rectangle, real ticks, interpolated frames):");
    for (int i = 0; i < g_twLoadN; ++i) {
        const TwLoad& e = g_twLoad[i];
        Log("    %08lX  x %4d y %3d, %3d x %3d   %4ld  %4ld", e.ret, e.r[0], e.r[1], e.r[2], e.r[3], e.real, e.tween);
    }
    if (g_twLoadLost) Log("    (%ld more not listed)", g_twLoadLost);
    Log("  appender calls on prims in the frame buffers: real %ld, interpolated %ld", g_twAppFresh[0], g_twAppFresh[1]);
    Log("  appender calls on prims outside them (call site -> appender, prim, real, interpolated, x before the call real / interpolated):");
    const DWORD w = (DWORD)(uintptr_t)BWork();
    for (int i = 0; i < g_twAppN; ++i) {
        const TwApp& e = g_twApp[i];
        char where[32];
        if (w && e.prim >= w && e.prim < w + 0x163A00) _snprintf_s(where, sizeof(where), _TRUNCATE, "work+%05lX", e.prim - w);
        else _snprintf_s(where, sizeof(where), _TRUNCATE, "%08lX", ToGhidra(e.prim));
        Log("    %08lX -> %08lX  %-11s  %4ld  %4ld   %5d / %5d", APPEND_CALLS[e.idx].site, APPEND_CALLS[e.idx].target,
            where, e.real, e.tween, e.xReal, e.xTween);
    }
    if (g_twAppLost) Log("    (%ld more not listed)", g_twAppLost);
    g_traceActive = false;
    TraceReport();
    Log("=== end of text watch ===");
}

static void TwTweenBegin()
{
    if (g_twStart) {
        g_twStart = false;
        g_twLeft = TW_TWEENS; g_twN = 0; g_twDiffLogs = g_twRealDiffLogs = 0;
        g_twLoadN = 0; g_twLoadLost = 0; g_twHaveEnd = false;
        memset(g_twObj, 0, sizeof(g_twObj)); g_twObjLines = 0;
        g_twAppN = 0; g_twAppLost = 0; g_twAppFresh[0] = g_twAppFresh[1] = 0;
        memset(g_twApply, 0, sizeof(g_twApply)); memset(g_twBad, 0, sizeof(g_twBad));
        g_twRegChanged = g_twRealRegChanged = g_twRingWrap = g_twTweenLoads = g_twSkipped = 0;
        memset(g_trace, 0, sizeof(g_trace));
        g_traceActive = true;
        DWORD len; RegData(&len);
        Log("=== Text watch (F6): the next %d interpolated frames (text registry: %lu entries) ===", TW_TWEENS, len / 16);
    }
    if (g_twLeft <= 0) return;
    DWORD len; const BYTE* d = RegData(&len);
    g_twRegLen = len > sizeof(g_twReg) ? sizeof(g_twReg) : len;
    if (g_twRegLen) memcpy(g_twReg, d, g_twRegLen);
    if (g_twHaveEnd && (g_twRegLen != g_twRegEndLen || memcmp(g_twReg, g_twRegEnd, g_twRegLen) != 0)) {
        ++g_twRealRegChanged;
        if (g_twRealDiffLogs++ < TW_DIFF_LOGS) {
            Log("   real tick changed the text registry (%lu -> %lu entries):", g_twRegEndLen / 16, g_twRegLen / 16);
            TwDiff(g_twRegEnd, g_twRegEndLen, g_twReg, g_twRegLen);
        }
    }
    g_twLoadsNow = 0;
}

static void TwAfterApply() {}

static bool g_twRegCh = false;

static void TwTweenEnd()
{
    if (g_twLeft <= 0) return;
    DWORD len; const BYTE* d = RegData(&len);
    g_twRegEndLen = len > sizeof(g_twRegEnd) ? sizeof(g_twRegEnd) : len;
    if (g_twRegEndLen) memcpy(g_twRegEnd, d, g_twRegEndLen);
    g_twHaveEnd = true;
    g_twRegCh   = g_twRegEndLen != g_twRegLen || memcmp(g_twReg, g_twRegEnd, g_twRegLen) != 0;
    ++g_twApply[g_lcApplyCode & 7];
    if (g_twRegCh) ++g_twRegChanged;
    g_twTweenLoads += g_twLoadsNow;
}

// After the state is restored: sizes of the real frame and the interpolated frame.
static void TwFrameDone(long realPk, long twPk, long realHd, long twHd)
{
    if (g_twLeft <= 0) return;
    if (g_twN < TW_LINES)
        Log("  frame %3d: real %ld bytes / %ld HD, interpolated %ld bytes / %ld HD%s | task copy %d | registry %lu -> %lu | uploads %ld",
            g_twN, realPk, realHd, twPk, twHd, (realPk != twPk || realHd != twHd) ? " <>" : "",
            g_lcApplyCode, g_twRegLen / 16, g_twRegEndLen / 16, g_twLoadsNow);
    if (g_twRegCh && g_twDiffLogs++ < TW_DIFF_LOGS) {
        Log("   interpolated frame %d changed the text registry:", g_twN);
        TwDiff(g_twReg, g_twRegLen, g_twRegEnd, g_twRegEndLen);
    }
    ++g_twN;
    if (--g_twLeft == 0) TwReport();
}

// ---- Video memory dump (F4, field) ----
//  Writes the emulated PS1 video memory as ga_vram.bmp (15-bit colors as they
//  are) and ga_vram.bin (raw), lists the textured prims of the real frame that
//  cover the largest screen area (texture page, CLUT, uv range), and decodes
//  the texture of the 4 largest as ga_tex_1..4.bmp (magenta = transparent).
static bool WriteBmp24(const wchar_t* name, int w, int h, const DWORD* rgb)
{
    wchar_t path[MAX_PATH];
    swprintf_s(path, MAX_PATH, L"%s%s", g_dir, name);
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    const DWORD rowBytes = ((DWORD)w * 3 + 3) & ~3u;
    const DWORD imgBytes = rowBytes * (DWORD)h;
    BYTE hdr[54] = { 'B', 'M' };
    DWORD v;
    v = 54 + imgBytes; memcpy(hdr + 2, &v, 4);
    v = 54;            memcpy(hdr + 10, &v, 4);
    v = 40;            memcpy(hdr + 14, &v, 4);
    v = (DWORD)w;      memcpy(hdr + 18, &v, 4);
    v = (DWORD)h;      memcpy(hdr + 22, &v, 4);
    hdr[26] = 1; hdr[28] = 24;
    v = imgBytes;      memcpy(hdr + 34, &v, 4);
    DWORD written;
    WriteFile(f, hdr, 54, &written, nullptr);
    static BYTE row[1024 * 3 + 4];
    for (int y = h - 1; y >= 0; --y) {
        memset(row, 0, rowBytes);
        for (int x = 0; x < w; ++x) {
            DWORD c = rgb[y * w + x];
            row[x * 3 + 0] = (BYTE)(c);         // B
            row[x * 3 + 1] = (BYTE)(c >> 8);    // G
            row[x * 3 + 2] = (BYTE)(c >> 16);   // R
        }
        WriteFile(f, row, rowBytes, &written, nullptr);
    }
    CloseHandle(f);
    return true;
}

static DWORD Ps1ToRgb(WORD c)
{
    DWORD r = (c & 31) * 255 / 31, g = ((c >> 5) & 31) * 255 / 31, b = ((c >> 10) & 31) * 255 / 31;
    return (r << 16) | (g << 8) | b;
}

struct DumpTex { WORD tpage, clut; int u0, v0, u1, v1; long area; int count; };

static void DiagDumpField()
{
    const WORD* vram = G<const WORD*>(0x0063F884);
    if (!vram) vram = G<const WORD*>(0x0063F880);
    if (!vram) { Log("Dump (F4): no video memory found."); return; }
    static DWORD img[1024 * 512];

    // 1. Video memory, raw and as an image
    {
        wchar_t path[MAX_PATH];
        swprintf_s(path, MAX_PATH, L"%sga_vram.bin", g_dir);
        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(f, vram, 1024 * 512 * 2, &written, nullptr);
            CloseHandle(f);
        }
        for (int i = 0; i < 1024 * 512; ++i) img[i] = Ps1ToRgb(vram[i]);
        WriteBmp24(L"ga_vram.bmp", 1024, 512, img);
    }

    // 2. Textured polygons in the ordering table of the real frame
    static DumpTex tex[256];
    int nTex = 0, nPrims = 0, nPolys = 0;
    BYTE* cdb = G<BYTE*>(Addr::g_cdb);
    const DWORD otA = (DWORD)(uintptr_t)(cdb + DB_OT), otB = otA + DB_OT_SIZE * 8;
    for (DWORD e = otA; cdb && e < otB; e += 8) {
        DWORD p = *(DWORD*)(uintptr_t)e;
        for (int guard = 0; guard < 20000 && p != 0xFFFFFFFF && !(p >= otA && p < otB); ++guard) {
            const BYTE* q = (const BYTE*)(uintptr_t)p;
            ++nPrims;
            const BYTE len  = q[7];
            const BYTE code = q[0x0B];
            if (len >= 6 && (code & 0xE4) == 0x24) {           // textured polygon (0x24..0x3F)
                ++nPolys;
                const bool quad = (code & 0x08) != 0, gour = (code & 0x10) != 0;
                // offsets of xy and uv for vertex k
                int xyOf[4], uvOf[4];
                for (int k = 0; k < 4; ++k) {
                    int stride = gour ? 12 : 8;
                    xyOf[k] = 0x0C + k * stride;
                    uvOf[k] = xyOf[k] + 4;
                }
                const int nv = quad ? 4 : 3;
                const WORD clut  = *(const WORD*)(q + uvOf[0] + 2);
                const WORD tpage = *(const WORD*)(q + uvOf[1] + 2);
                int xmin = 32767, xmax = -32768, ymin = 32767, ymax = -32768, umin = 255, umax = 0, vmin = 255, vmax = 0;
                for (int k = 0; k < nv; ++k) {
                    const short x = *(const short*)(q + xyOf[k]), y = *(const short*)(q + xyOf[k] + 2);
                    const BYTE u = q[uvOf[k]], v = q[uvOf[k] + 1];
                    if (x < xmin) xmin = x; if (x > xmax) xmax = x;
                    if (y < ymin) ymin = y; if (y > ymax) ymax = y;
                    if (u < umin) umin = u; if (u > umax) umax = u;
                    if (v < vmin) vmin = v; if (v > vmax) vmax = v;
                }
                const long area = (long)(xmax - xmin) * (ymax - ymin);
                int i = 0;
                while (i < nTex && !(tex[i].tpage == tpage && tex[i].clut == clut)) ++i;
                if (i == nTex && nTex < 256) {
                    tex[nTex] = { tpage, clut, umin, vmin, umax, vmax, 0, 0 };
                    ++nTex;
                }
                if (i < nTex) {
                    DumpTex& t = tex[i];
                    t.area += area; ++t.count;
                    if (umin < t.u0) t.u0 = umin; if (vmin < t.v0) t.v0 = vmin;
                    if (umax > t.u1) t.u1 = umax; if (vmax > t.v1) t.v1 = vmax;
                }
            }
            p = *(const DWORD*)q;
        }
    }
    // largest total area first
    for (int a = 0; a < nTex; ++a)
        for (int b = a + 1; b < nTex; ++b)
            if (tex[b].area > tex[a].area) { DumpTex t = tex[a]; tex[a] = tex[b]; tex[b] = t; }

    Log("=== Dump (F4): ga_vram.bmp / ga_vram.bin written. Display mode %d. %d prims, %d textured polygons, %d textures ===",
        g_mode, nPrims, nPolys, nTex);
    Log("  texture page / CLUT: polygons, total screen area, uv range");
    for (int i = 0; i < nTex && i < 25; ++i) {
        const DumpTex& t = tex[i];
        const int bpp = (t.tpage >> 7) & 3;
        Log("  tpage %04X (x %4d y %3d, %s, abr %d)  clut %04X (x %4d y %3d): %4d polys, area %7ld, u %3d-%3d v %3d-%3d",
            t.tpage, (t.tpage & 15) * 64, ((t.tpage >> 4) & 1) * 256, bpp == 0 ? "4-bit" : bpp == 1 ? "8-bit" : "15-bit",
            (t.tpage >> 5) & 3, t.clut, (t.clut & 63) * 16, t.clut >> 6, t.count, t.area, t.u0, t.u1, t.v0, t.v1);
    }

    // 3. The 4 largest textures, decoded with their CLUT
    for (int i = 0; i < nTex && i < 4; ++i) {
        const DumpTex& t = tex[i];
        const int bx = (t.tpage & 15) * 64, by = ((t.tpage >> 4) & 1) * 256, bpp = (t.tpage >> 7) & 3;
        const int cx = (t.clut & 63) * 16, cy = t.clut >> 6;
        for (int v = 0; v < 256; ++v)
            for (int u = 0; u < 256; ++u) {
                WORD c;
                const int y = (by + v) & 511;
                if (bpp == 0) {
                    WORD hw = vram[y * 1024 + ((bx + u / 4) & 1023)];
                    int idx = (hw >> ((u & 3) * 4)) & 15;
                    c = vram[(cy & 511) * 1024 + ((cx + idx) & 1023)];
                } else if (bpp == 1) {
                    WORD hw = vram[y * 1024 + ((bx + u / 2) & 1023)];
                    int idx = (hw >> ((u & 1) * 8)) & 255;
                    c = vram[(cy & 511) * 1024 + ((cx + idx) & 1023)];
                } else {
                    c = vram[y * 1024 + ((bx + u) & 1023)];
                }
                img[v * 256 + u] = c == 0 ? 0xFF00FF : Ps1ToRgb(c);
            }
        wchar_t name[32];
        swprintf_s(name, 32, L"ga_tex_%d.bmp", i + 1);
        WriteBmp24(name, 256, 256, img);
    }
    Log("=== end of dump (ga_tex_1..%d.bmp: the largest textures, magenta = transparent) ===", nTex < 4 ? nTex : 4);
}

static DWORD WINAPI DiagKeyThread(LPVOID)
{
    bool was = false, was6 = false, was4 = false;
    for (;;) {
        Sleep(30);
        bool f4 = (GetAsyncKeyState(VK_F4) & 0x8000) != 0;
        if (f4 && !was4 && GameHasFocus() && !g_dumpRequest) {
            g_dumpRequest = true;
            Log("Dump requested (F4) - written at the next field frame.");
        }
        was4 = f4;
        bool f6 = (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
        if (f6 && !was6 && GameHasFocus() && g_twLeft <= 0 && !g_twStart) {
            g_twStart = true;
            Log("Text watch requested (F6) - starts with the next interpolated battle frame.");
        }
        was6 = f6;
        bool down = (GetAsyncKeyState(VK_F5) & 0x8000) != 0;
        if (down && !was && GameHasFocus()) {
            if (!g_traceActive) {
                memset(g_trace, 0, sizeof(g_trace));
                g_traceActive = true;
                Log("Draw origin tracer started (F5). Press F5 again to stop.");
            } else {
                g_traceActive = false;
                Sleep(100);
                TraceReport();
            }
        }
        was = down;
    }
}

static void Install_AppendTracer()
{
    Install_AppendHooks();
    Install_LoadImageWatch();
    HANDLE h = CreateThread(nullptr, 0, DiagKeyThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
    Log("DIAGNOSTIC BUILD: draw origin tracer on the %d appender calls. F5 = start/stop. F6 = text watch in battle. F4 = video memory dump (field).", NUM_ASITES);
}
#endif // GA_DIAG

// ============================================================================
//  Crash logger: on a crash, writes the address (as a Ghidra address), the
//  thread, the hook phase and a rough call stack to grandia_mod.log.
// ============================================================================

static volatile LONG g_crashLogCount = 0;

static bool SafeReadDword(const void* p, DWORD* out)
{
    __try { *out = *(const DWORD*)p; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void DescribeAddress(DWORD addr, char* out, size_t count)
{
    BYTE* a = (BYTE*)(uintptr_t)addr;
    if (a >= g_base && a < g_base + g_imageSize) {
        _snprintf_s(out, count, _TRUNCATE, "grandia.exe %08lX",
                    (DWORD)(a - g_base) + GHIDRA_IMAGE_BASE);
        return;
    }
    HMODULE mod = nullptr;
    char name[MAX_PATH] = "?";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)a, &mod) && mod) {
        char full[MAX_PATH];
        if (GetModuleFileNameA(mod, full, MAX_PATH)) {
            const char* s = strrchr(full, '\\');
            strcpy_s(name, s ? s + 1 : full);
        }
        _snprintf_s(out, count, _TRUNCATE, "%s+%lX", name, (DWORD)(a - (BYTE*)mod));
    } else {
        _snprintf_s(out, count, _TRUNCATE, "%08lX (unknown module)", addr);
    }
}

static LONG CALLBACK CrashLogger(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION   && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION   && code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_STACK_OVERFLOW)
        return EXCEPTION_CONTINUE_SEARCH;
    if (g_probeThread != 0 && g_probeThread == GetCurrentThreadId())
        return EXCEPTION_CONTINUE_SEARCH;       // Readable() is testing an address
    static volatile LONG inHandler = 0;
    if (InterlockedCompareExchange(&inHandler, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;       // exception while logging
    if (InterlockedIncrement(&g_crashLogCount) > 3) {
        inHandler = 0;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT* c = ep->ContextRecord;
    char where[160];
    DescribeAddress((DWORD)(uintptr_t)ep->ExceptionRecord->ExceptionAddress, where, sizeof(where));

    DWORD tid = GetCurrentThreadId();
    const char* thread = (tid == g_logicThreadId) ? "logic thread" : "other thread";

    Log("=== EXCEPTION 0x%08lX at %s ===", code, where);
    Log("Thread %lu (%s), phase: %s, draw step: %ld, interpolated frames: %u, display mode: %d",
        tid, thread, g_phase, g_tweenStep, g_tween.framesDone, g_mode);
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        ULONG_PTR kind = ep->ExceptionRecord->ExceptionInformation[0];
        Log("Memory error: %s at address %08lX",
            kind == 0 ? "read" : kind == 1 ? "write" : "execute",
            (DWORD)ep->ExceptionRecord->ExceptionInformation[1]);
    }
    Log("EAX=%08lX EBX=%08lX ECX=%08lX EDX=%08lX ESI=%08lX EDI=%08lX EBP=%08lX ESP=%08lX",
        c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->Esp);

    // Rough call stack: values on the stack that point into grandia.exe
    int found = 0;
    for (int i = 0; i < 256 && found < 12; ++i) {
        DWORD v;
        if (!SafeReadDword((const BYTE*)(uintptr_t)c->Esp + i * 4, &v))
            break;
        BYTE* a = (BYTE*)(uintptr_t)v;
        if (a >= g_base && a < g_base + g_imageSize) {
            Log("  stack+%03X: grandia.exe %08lX", i * 4, (DWORD)(a - g_base) + GHIDRA_IMAGE_BASE);
            ++found;
        }
    }
    inHandler = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
//  Reading settings and installing patches
// ============================================================================

static const wchar_t* DEFAULT_TWEEN_DRAW =
    L"004552d0,0047a330,004542e0,MAPFX,RESETSORT,004825d0,00468970,004836f0,"
    L"SORT,004823d0:f,RESETSORT,COMPASS,004823d0:b,PORTRAITS,00452b00:0,00452b00:1,004671d0";

static bool ParseTweenOps(const wchar_t* list)
{
    wchar_t buf[2048];
    wcsncpy_s(buf, list, _TRUNCATE);

    g_tween.opCount = 0;
    wchar_t* ctx = nullptr;
    for (wchar_t* tok = wcstok_s(buf, L", \t", &ctx); tok; tok = wcstok_s(nullptr, L", \t", &ctx)) {
        if (g_tween.opCount >= MAX_TWEEN_OPS) {
            Log("Interpolation: too many draw steps (max %d).", MAX_TWEEN_OPS);
            return false;
        }
        TweenOp& op = g_tween.ops[g_tween.opCount];
        op.fn  = nullptr;
        op.ecx = 0;
        op.edx = 0;
        _snprintf_s(op.label, sizeof(op.label), _TRUNCATE, "%ls", tok);

        if (_wcsicmp(tok, L"RESETSORT") == 0) {
            op.kind = OP_RESETSORT;
        } else if (_wcsicmp(tok, L"SORT") == 0) {
            op.kind = OP_SORT;
        } else if (_wcsicmp(tok, L"COND457610") == 0) {
            op.kind = OP_COND457610;
        } else if (_wcsicmp(tok, L"COMPASS") == 0) {
            op.kind = OP_COMPASS;
        } else if (_wcsicmp(tok, L"PORTRAITS") == 0) {
            op.kind = OP_PORTRAITS;
        } else if (_wcsicmp(tok, L"MAPFX") == 0) {
            op.kind = OP_MAPFX;
        } else {
            // address[:ecx[:edx]], all hexadecimal
            wchar_t* end = nullptr;
            unsigned long a = wcstoul(tok, &end, 16);
            bool ok = end && end != tok && InImage((DWORD)a, 16);
            if (ok && *end == L':') { op.ecx = wcstoul(end + 1, &end, 16); }
            if (ok && *end == L':') { op.edx = wcstoul(end + 1, &end, 16); }
            if (!ok || *end != L'\0') {
                Log("Interpolation: invalid draw step '%ls' in grandia_mod.ini.", tok);
                return false;
            }
            op.kind = OP_CALL;
            op.fn   = (Fast2_t)VA((DWORD)a);
        }
        ++g_tween.opCount;
    }
    return g_tween.opCount > 0;
}

static bool g_blocksTried = false, g_blocksMarkDirty = false;
static bool Install_TweenBlocks()
{
    if (!g_blocksTried) {
        g_blocksTried = true;
        g_blocksMarkDirty = Install_MarkDirtyBlock();
        Install_CdTickBlock();
    }
    return g_blocksMarkDirty;
}

static void Install_TweenFrames()
{
    wchar_t alphaStr[32];
    GetPrivateProfileStringW(L"Interpolation", L"TweenAlpha", L"0.5", alphaStr, 32, g_ini);
    g_tween.alpha = (float)_wtof(alphaStr);

    // Hidden advanced setting: [Interpolation] Draw=... overrides the draw step list.
    wchar_t drawList[2048];
    GetPrivateProfileStringW(L"Interpolation", L"Draw", DEFAULT_TWEEN_DRAW, drawList, 2048, g_ini);
    if (!ParseTweenOps(drawList)) {
        Log("Interpolation: no valid draw step list - interpolation off.");
        return;
    }

    // Check everything first, then patch
    if (!InImage(Addr::CallEndFrameInMainLoop, 5) ||
        !IsCallTo(Addr::CallEndFrameInMainLoop, Addr::Field_EndFrame)) {
        Log("Interpolation: call of Field_EndFrame is not as expected - interpolation off.");
        return;
    }
    if (!InstallDrawSnapHooks()) {
        Log("Interpolation off.");
        return;
    }

    if (IsCallTo(Addr::CallCompassPrep, Addr::CompassPrep))
        g_compassHooked = WriteBranch(VA(Addr::CallCompassPrep), 0xE8, (void*)&Stub_CompassPrep, 5);
    if (IsCallTo(0x004565CC, 0x004817E0)) {
        g_fxWaveTarget = (DWORD)(uintptr_t)VA(0x004817E0);
        if (!WriteBranch(VA(0x004565CC), 0xE8, (void*)&Stub_MapWaveDraw, 5)) g_fxWaveTarget = 0;
    }
    if (!g_fxWaveTarget)
        Log("Interpolation: map wave effect not hooked - mist layers are left out of interpolated frames.");
    if (!g_compassHooked)
        Log("Interpolation: compass detection failed - the compass will be missing in interpolated frames.");

    bool markDirty = Install_TweenBlocks();
    bool cdTick    = g_cdTickCont != 0;

    if (!WriteBranch(VA(Addr::CallEndFrameInMainLoop), 0xE8, (void*)&Hook_Field_EndFrame, 5)) {
        Log("Interpolation: VirtualProtect failed (error %lu).", GetLastError());
        return;
    }

    g_tween.enabled = true;
    if (!VERBOSE) { Log("Field interpolation: installed."); return; }
    Log("Field interpolation: installed. TweenAlpha=%.2f, %d draw steps; compass %s, "
        "'mark dirty' %s, CD ticks %s during interpolated frames.",
        g_tween.alpha, g_tween.opCount, g_compassHooked ? "yes" : "no",
        markDirty ? "blocked" : "NOT blocked", cdTick ? "blocked" : "NOT blocked");
}

// ============================================================================
//  The real d3d11.dll
// ============================================================================

static HMODULE                                g_realD3D11 = nullptr;
static PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN g_realCreateDeviceAndSwapChain = nullptr;
static PFN_D3D11_CREATE_DEVICE                g_realCreateDevice = nullptr;

// Do not call from DllMain (LoadLibrary under the loader lock is forbidden).
static bool LoadRealD3D11()
{
    if (g_realD3D11)
        return true;

    wchar_t path[MAX_PATH];
    UINT len = GetSystemDirectoryW(path, MAX_PATH);
    if (len == 0 || len > MAX_PATH - 12) {
        Log("GetSystemDirectoryW failed.");
        return false;
    }
    wcscat_s(path, MAX_PATH, L"\\d3d11.dll");

    HMODULE h = LoadLibraryW(path);
    if (!h) {
        Log("Could not load the real d3d11.dll (error %lu).", GetLastError());
        return false;
    }

    g_realCreateDeviceAndSwapChain =
        (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetProcAddress(h, "D3D11CreateDeviceAndSwapChain");
    g_realCreateDevice =
        (PFN_D3D11_CREATE_DEVICE)GetProcAddress(h, "D3D11CreateDevice");
    g_realD3D11 = h;

    if (VERBOSE) Log("Real d3d11.dll loaded: %ls", path);
    return true;
}

extern "C" HRESULT WINAPI Proxy_D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter*               pAdapter,
    D3D_DRIVER_TYPE             DriverType,
    HMODULE                     Software,
    UINT                        Flags,
    const D3D_FEATURE_LEVEL*    pFeatureLevels,
    UINT                        FeatureLevels,
    UINT                        SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain**            ppSwapChain,
    ID3D11Device**              ppDevice,
    D3D_FEATURE_LEVEL*          pFeatureLevel,
    ID3D11DeviceContext**       ppImmediateContext)
{
    if (!LoadRealD3D11() || !g_realCreateDeviceAndSwapChain)
        return E_FAIL;

    HRESULT hr = g_realCreateDeviceAndSwapChain(
        pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
        SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
        ppImmediateContext);

    if (!VERBOSE && hr >= 0) {
        // quiet log: only failures
    } else if (pSwapChainDesc) {
        Log("D3D11CreateDeviceAndSwapChain -> 0x%08lX (%ux%u, windowed=%d)",
            hr, pSwapChainDesc->BufferDesc.Width, pSwapChainDesc->BufferDesc.Height,
            pSwapChainDesc->Windowed);
    } else {
        Log("D3D11CreateDeviceAndSwapChain -> 0x%08lX", hr);
    }
    return hr;
}

extern "C" HRESULT WINAPI Proxy_D3D11CreateDevice(
    IDXGIAdapter*            pAdapter,
    D3D_DRIVER_TYPE          DriverType,
    HMODULE                  Software,
    UINT                     Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT                     FeatureLevels,
    UINT                     SDKVersion,
    ID3D11Device**           ppDevice,
    D3D_FEATURE_LEVEL*       pFeatureLevel,
    ID3D11DeviceContext**    ppImmediateContext)
{
    if (!LoadRealD3D11() || !g_realCreateDevice)
        return E_FAIL;

    return g_realCreateDevice(
        pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
        SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
}

// ============================================================================
//  DllMain
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID /*reserved*/)
{
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinstDLL);

    // Folder of grandia.exe
    GetModuleFileNameW(nullptr, g_dir, MAX_PATH);
    wchar_t* slash = wcsrchr(g_dir, L'\\');
    if (slash) slash[1] = L'\0'; else g_dir[0] = L'\0';
    swprintf_s(g_ini, MAX_PATH, L"%sgrandia_mod.ini", g_dir);

    // New log file every session
    wchar_t logPath[MAX_PATH];
    LogPath(logPath, MAX_PATH);
    DeleteFileW(logPath);

    // Load address and size of grandia.exe
    g_base = (BYTE*)GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)g_base;
    auto nt  = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    g_imageSize = nt->OptionalHeader.SizeOfImage;

    if (VERBOSE) Log("Grand Aspect v1.3.1 loaded. grandia.exe at %p (size 0x%08lX).", g_base, g_imageSize);
    else         Log("Grand Aspect v1.3.1 loaded.");

    ResolveGameFunctions();
    AddVectoredExceptionHandler(1, CrashLogger);

    // 'Field' was called 'Enabled' before; an old ini keeps working.
    const UINT fieldOld = GetPrivateProfileIntW(L"Interpolation", L"Enabled", 1, g_ini);
    if (GetPrivateProfileIntW(L"Interpolation", L"Field", fieldOld, g_ini))
        Install_TweenFrames();
    else
        Log("Field interpolation is off (Field=0).");

    if (GetPrivateProfileIntW(L"Interpolation", L"Battle", 1, g_ini))
        Install_BattleTween();
    else
        Log("Battle interpolation is off (Battle=0).");

    if (g_tween.enabled || g_bEnabled)
        Install_FrameModeKey();

    if (GetPrivateProfileIntW(L"Display", L"Enabled", 1, g_ini))
        Install_DisplayModes();
    else
        Log("Display modes are off (Enabled=0).");

    if (GetPrivateProfileIntW(L"Shader", L"Enabled", 1, g_ini))
        Install_Shader();
    else
        Log("Shader is off (Enabled=0).");

#ifdef GA_DIAG
    Install_BattleDiag();
    Install_AppendTracer();
#endif

    return TRUE;
}
