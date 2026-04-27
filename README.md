# Side-Chain-Analysis Operations Guide

This repository contains two operational modules for an intelligent side-channel attack system:
- `attack-emulation-core`: low-level side-channel emulation and target binary setup
- `intelligent-attack-pipeline`: dataset generation, deep learning attack training, and evaluation

## Getting started

### 1) Prerequisites
- Linux (Ubuntu 20.04+/22.04+ or Kali)
- Python 3.10+
- `git`, `build-essential`
- ARM toolchain: `gcc-arm-none-eabi`, `binutils-arm-none-eabi`

### 2) Clone repository
```bash
cd /workspaces
git clone https://github.com/adeelHassan123/Side-Chain-Analysis.git
cd Side-Chain-Analysis
```

### 3) Create and activate virtual environment
```bash
python3 -m venv rainbow_env
source rainbow_env/bin/activate

# Confirm Python
python3 --version
```

### 4) Install Python dependencies
```bash
pip install -U pip
pip install -r requirements.txt
```

### 5) Install Rainbow local package (recommended)
```bash
cd rainbow
pip install -e .
cd ..
```

### 6) Verify install
```bash
python3 -c "from rainbow.generics import rainbow_arm; print('Rainbow OK')"
python3 -c "import lascar; print('Lascar OK')"
```

---

## Module 1: Attack Emulation Core (Rainbow)

### Create module working directory
```bash
mkdir -p ~/attack-emulation-core && cd ~/attack-emulation-core
```

### 1) C implementation (`simple_xor.c`)
```c
#include <stdint.h>

void xor_encrypt(uint8_t *data, uint8_t *key, int length) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key[i % 16];
    }
}

int main(void) {
    uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t key[16]       = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    xor_encrypt(plaintext, key, 16);
    return 0;
}
```

### 2) Linker script (`link.ld`)
```ld
MEMORY {
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
  RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .text : { *(.text*) } > FLASH
  .data : { *(.data*) } > RAM AT > FLASH
  .bss  : { *(.bss*)  } > RAM
}
```

### 3) Compile for ARM Cortex-M3
```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O0 -g -nostdlib -T link.ld -o simple_xor.elf simple_xor.c
file simple_xor.elf
```

### 4) Run Rainbow simulation example
```bash
cd rainbow/examples/pimp_my_xor
python3 x64_pimpmyxor.py
```

### 5) Run AWing and trace analysis (CortexM_AES)
```bash
cd rainbow/examples/CortexM_AES
python3 cortexm_aes_fixed.py
```

Expect printed key matching and saved CPA trace plots.

---

## Module 2: Intelligent Attack Pipeline

### 1) Generate dataset (fixed-key / variable-key)
Use `intelligent-attack-pipeline/generate_dataset.py` from this repository.

### 2) Train deep learning model
Use `intelligent-attack-pipeline/attack.py` or `intelligent-attack-pipeline/comparative_analysis.py` with HDF5 datasets:
- `intelligent-attack-pipeline/datasets/fixed_key_dataset.h5`
- `intelligent-attack-pipeline/datasets/variable_key_dataset.h5`

### 3) Verify key recovery
Run from command line and confirm report for accuracy on profiling and attack sets.

---

## Notes
- Use `rainbow_env/bin/activate` path if using workspace-based environment.
- If `rainbow.generics` not found, uninstall PyPI rainbow and reinstall local repo with `pip install -e .`.
- If any module is missing, re-run `pip install -r requirements.txt`.

## Keywords
side-channel, rainbow, unicorn, hamming-weight, correlation-power-analysis, cpa, masking
