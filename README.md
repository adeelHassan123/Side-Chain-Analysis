# Side-Chain-Analysis

An industry-structured repository for building an intelligent side-channel attack system.

## Repository Modules

- `attack-emulation-core`: baseline emulation target and linker setup.
- `intelligent-attack-pipeline`: dataset generation, model training, and attack evaluation.
- `adaptive-cryptanalysis-core`: ASCON implementation track and implementation roadmap for upcoming work.

## Quick Start

### 1) Environment setup

```bash
python3 -m venv rainbow_env
source rainbow_env/bin/activate
pip install -U pip
pip install -r requirements.txt
```

### 2) Optional Rainbow local install

Use this when you maintain a local `rainbow/` source checkout:

```bash
cd rainbow
pip install -e .
cd ..
```

### 3) Verify dependencies

```bash
python3 -c "from rainbow.generics import rainbow_arm; print('Rainbow OK')"
python3 -c "import lascar; print('Lascar OK')"
```

## Module Usage

### `attack-emulation-core`

- Contains low-level C target and linker script.
- Example compile command:

```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O0 -g -nostdlib -T attack-emulation-core/link.ld -o simple_xor.elf attack-emulation-core/simple_xor.c
```

### `intelligent-attack-pipeline`

Run from repository root:

```bash
python3 intelligent-attack-pipeline/generate_dataset.py
python3 intelligent-attack-pipeline/attack.py
python3 intelligent-attack-pipeline/comparative_analysis.py
```

Outputs include trained models and analysis plots.

### `adaptive-cryptanalysis-core`

- `implementation-roadmap.md`: implementation plan for your next ASCON-focused phase.
- `ascon128_reference.c`: reference ASCON implementation target.
- `ascon_validation_harness.c`: validation harness for functional checks.

## Recommended Execution Order

1. Build and validate emulation target in `attack-emulation-core`.
2. Generate and train in `intelligent-attack-pipeline`.
3. Start ASCON implementation flow in `adaptive-cryptanalysis-core` (roadmap-first).

## Troubleshooting

- If `rainbow.generics` import fails, reinstall Rainbow from local source checkout (`pip install -e .`).
- If Python modules are missing, run `pip install -r requirements.txt` again.
- If ARM compile fails, install `gcc-arm-none-eabi` and `binutils-arm-none-eabi`.
