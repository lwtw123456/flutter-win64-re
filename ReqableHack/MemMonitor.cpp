#include "MemMonitor.h"
#include <windows.h>
#include <unordered_set>

constexpr auto THRESHOLD = 10ULL * 1024 * 1024;

static const DWORD WRITE_FLAGS = PAGE_READWRITE
                                | PAGE_WRITECOPY
                                | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY;

static const DWORD EXEC_FLAGS  = PAGE_EXECUTE
                                | PAGE_EXECUTE_READ
                                | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY;

static bool is_target(const MEMORY_BASIC_INFORMATION& mbi) {
    return mbi.State      == MEM_COMMIT
        && mbi.Type       == MEM_PRIVATE
        && mbi.RegionSize >= THRESHOLD
        && (mbi.AllocationProtect & WRITE_FLAGS)
        && (mbi.Protect           & EXEC_FLAGS);
}

struct Ctx {
    MemMonitorCallback callback;
    void*              user_data;
    unsigned int       interval_ms;
    volatile LONG      stop;
};

static HANDLE g_thread = NULL;
static Ctx    g_ctx    = {};

static DWORD WINAPI thread_proc(LPVOID param) {
    Ctx* ctx = (Ctx*)param;
    std::unordered_set<unsigned long long> seen;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (InterlockedCompareExchange(&ctx->stop, 0, 0) == 0) {
        std::unordered_set<unsigned long long> current_scan;
        LPVOID addr = NULL;

        while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (is_target(mbi)) {
                auto base = (unsigned long long)mbi.BaseAddress;
                current_scan.insert(base);
                if (seen.insert(base).second) {
                    MemRegionInfo info = {};
                    info.base          = base;
                    info.size          = mbi.RegionSize;
                    info.protect       = mbi.Protect;
                    info.alloc_protect = mbi.AllocationProtect;
                    ctx->callback(&info, ctx->user_data);
                }
            }
            if ((unsigned long long)addr + mbi.RegionSize <= (unsigned long long)addr) break;
            addr = (LPBYTE)addr + mbi.RegionSize;
        }

        for (auto it = seen.begin(); it != seen.end(); ) {
            if (current_scan.find(*it) == current_scan.end())
                it = seen.erase(it);
            else
                ++it;
        }

        Sleep(ctx->interval_ms);
    }
    return 0;
}

extern "C" {

int mem_monitor_start(MemMonitorCallback callback, void* user_data, unsigned int interval_ms) {
    if (g_thread) return 0;
    g_ctx = { callback, user_data, interval_ms ? interval_ms : 500, 0 };
    g_thread = CreateThread(NULL, 0, thread_proc, &g_ctx, 0, NULL);
    return g_thread != NULL;
}

void mem_monitor_stop(void) {
    if (!g_thread) return;
    InterlockedExchange(&g_ctx.stop, 1);
    WaitForSingleObject(g_thread, 5000);
    CloseHandle(g_thread);
    g_thread = NULL;
}

}