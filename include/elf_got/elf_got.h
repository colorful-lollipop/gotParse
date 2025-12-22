#pragma once

/**
 * @file elf_got.h
 * @brief Public API for ELF GOT Parser library
 *
 * A comprehensive library for analyzing Global Offset Table (GOT) sections
 * in ELF binaries, with support for runtime process analysis and symbol
 * resolution.
 */

// Core types
#include "core/types.h"

// ELF file parsing
#include "core/elf_parser.h"

// Process memory reading
#include "process/process_reader.h"
#include "process/maps_parser.h"

// Symbol resolution
#include "symbol/symbol_resolver.h"

/**
 * @namespace elf::got
 * @brief ELF GOT analysis library
 *
 * Provides:
 * - ELFParser: Parse GOT sections from ELF files
 * - ProcessReader: Read process memory via /proc/pid/mem
 * - MapsParser: Parse /proc/pid/maps memory regions
 * - SymbolResolver: Resolve symbols from addresses
 */
