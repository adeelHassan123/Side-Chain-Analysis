# Side-Channel Operations Playbook

This is a concise runbook for the operational modules in this repository.

## Setup

```bash
python3 -m venv rainbow_env
source rainbow_env/bin/activate
pip install -U pip
pip install -r requirements.txt
```

If you have a local Rainbow checkout:

```bash
cd rainbow
pip install -e .
cd ..
```

## Core Workflows

### 1) Emulation Core

- Source: `attack-emulation-core/simple_xor.c`
- Linker: `attack-emulation-core/link.ld`

Compile example:

```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O0 -g -nostdlib -T attack-emulation-core/link.ld -o simple_xor.elf attack-emulation-core/simple_xor.c
```

### 2) Intelligent Attack Pipeline

```bash
python3 intelligent-attack-pipeline/generate_dataset.py
python3 intelligent-attack-pipeline/attack.py
python3 intelligent-attack-pipeline/comparative_analysis.py
```

### 3) Adaptive Cryptanalysis Core (ASCON Track)

- Roadmap: `adaptive-cryptanalysis-core/implementation-roadmap.md`
- Target: `adaptive-cryptanalysis-core/ascon128_reference.c`
- Validation: `adaptive-cryptanalysis-core/ascon_validation_harness.c`

## Troubleshooting

- `No module named rainbow.generics`: reinstall Rainbow from local source with `pip install -e .`.
- Missing Python modules: rerun `pip install -r requirements.txt`.
- ARM toolchain compile failure: install `gcc-arm-none-eabi` and `binutils-arm-none-eabi`.
