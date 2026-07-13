#pragma once

#include "common/ITypes.h"

/* CRITICAL_SECTION must stay 24 bytes on x86 or dependent struct layouts shift. */
typedef struct _BGS_RTL_CRITICAL_SECTION {
    void*         DebugInfo;
    long          LockCount;
    long          RecursionCount;
    void*         OwningThread;
    void*         LockSemaphore;
    unsigned long SpinCount;
} CRITICAL_SECTION;

#ifndef EnterCriticalSection
#define EnterCriticalSection(p)      ((void)0)
#endif
#ifndef LeaveCriticalSection
#define LeaveCriticalSection(p)      ((void)0)
#endif
#ifndef InitializeCriticalSection
#define InitializeCriticalSection(p) ((void)0)
#endif
#ifndef DeleteCriticalSection
#define DeleteCriticalSection(p)     ((void)0)
#endif
#ifndef InterlockedIncrement
#define InterlockedIncrement(p)      (0)
#endif
#ifndef InterlockedDecrement
#define InterlockedDecrement(p)      (0)
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
