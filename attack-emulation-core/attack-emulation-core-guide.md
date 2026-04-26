# Attack Emulation Core Guide

This document provides a focused workflow for building and validating the baseline emulation target used by the intelligent attack system.

## Scope

- Build a deterministic ARM target.
- Validate binary output and memory layout.
- Prepare the target for trace collection.

## Files

- `simple_xor.c`: baseline target implementation.
- `link.ld`: Cortex-M3 memory layout.

## Build

```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O0 -g -nostdlib -T link.ld -o simple_xor.elf simple_xor.c
file simple_xor.elf
```

Expected: ARM ELF executable suitable for emulation.

## Emulation Readiness Checklist

1. Build completes without errors.
2. `simple_xor.elf` is generated and recognized as ARM binary.
3. Function symbols are available for instrumentation.
4. Input/key buffers are deterministic for reproducible traces.

## Recommended Next Integration

- Use this binary as input to the trace generation step in `intelligent-attack-pipeline`.
- Keep this target unchanged when comparing model performance across experiments.
