// ============================================================================
// Astra Runtime - M-06 Allocator
// src/allocator/allocator_service.cpp
//
// Implementation file for AllocatorService.
// Sprint 1: most logic lives in the headers (PoolAllocator is a template,
// MemoryManager is inline). This file exists to give the linker a
// translation unit for AllocatorService and to hold any non-template
// code that grows in Sprint 2/3.
// ============================================================================
#include <astra/allocator/allocator_service.h>
#include <astra/core/logger.h>

ASTRA_DEFINE_LOGGER(allocator)

// Currently the service is fully header-implemented.
// Sprint 2 will add guard page setup (mmap/mprotect calls) here.
// Sprint 3 will add per-module quota tracking here.
//
// This file ensures astra_allocator has a compiled translation unit
// and the logger macro creates the per-module log file.
