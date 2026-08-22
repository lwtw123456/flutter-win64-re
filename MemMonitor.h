#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned long long base;
    unsigned long long size;
    unsigned long      protect;       /* 当前保护 */
    unsigned long      alloc_protect; /* 初始保护 */
} MemRegionInfo;

typedef void (*MemMonitorCallback)(const MemRegionInfo* region, void* user_data);

int  mem_monitor_start(MemMonitorCallback callback, void* user_data, unsigned int interval_ms);
void mem_monitor_stop(void);

#ifdef __cplusplus
}
#endif