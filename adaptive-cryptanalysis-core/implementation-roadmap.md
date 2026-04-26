# Adaptive Cryptanalysis Core Roadmap

This roadmap defines the next implementation milestone: building and attacking an ASCON-128 target in a structured, reproducible pipeline.

## Objective

Build an end-to-end workflow that:
- implements ASCON-128 in C for ARM Cortex-M3,
- generates side-channel traces via emulation,
- trains models for key-recovery attacks,
- evaluates fixed-key vs variable-key robustness.

## Phase 1 - Cryptographic Target Definition

- Confirm ASCON-128 scope (encryption path, nonce/key handling, tag generation).
- Select leakage target focused on S-box-dependent intermediates.
- Define clear attack labels (Hamming weight class per selected intermediate).

Deliverable: target specification and leakage definition.

## Phase 2 - ARM Implementation Baseline

- Implement and validate ASCON-128 in `ascon128_reference.c`.
- Keep code deterministic and testable for trace reproducibility.
- Validate with `ascon_validation_harness.c`.

Deliverable: verified Cortex-M3 compatible target implementation.

## Phase 3 - Trace Generation Pipeline

- Build emulator driver for ARM binary execution.
- Capture synthetic traces using a stable leakage model (HW baseline).
- Export profiling/attack datasets in HDF5 format.

Deliverable: reproducible datasets for fixed-key and variable-key scenarios.

## Phase 4 - Intelligent Attack Training

- Train baseline classifiers on profiling traces.
- Run attack-set inference and key rank computation.
- Compare fixed-key vs variable-key key-recovery behavior.

Deliverable: model artifacts, success-rate metrics, and key-rank curves.

## Phase 5 - Hardening and Iteration

- Introduce controlled noise/countermeasures.
- Re-run attack evaluation to measure resilience.
- Document trade-offs: leakage reduction vs performance/complexity.

Deliverable: resilience report with recommended next controls.

## Immediate Next Steps

1. Compile `ascon128_reference.c` + `ascon_validation_harness.c` for Cortex-M3.
2. Define trace capture script inputs/outputs and dataset schema.
3. Run a first small-batch trace collection to validate labels.
4. Start baseline training and capture first key-rank results.
