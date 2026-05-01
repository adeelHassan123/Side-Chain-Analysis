

DEPARTMENT OF COMPUTING

CS-360: Cyber Security
Class: BSCS-2K23


Lab 07: Side Channel Emulator-Rainbow


CLO-3: Students will be able to perform practical technical tasks by following, applying, and demonstrating guided procedures and techniques in supervised laboratory or training environments.



Date: 3rd March 2026
Time: 10:00 - 12:50 / 14:00 - 16:50


Lab Instructor: Ms. Hadia Tahir
Class Instructor: Dr. Madiha Khalid


Lab 07: Side Channel Emulator-Rainbow

Introduction
This lab introduces Rainbow, Ledger's side-channel analysis simulation and emulation tool. Rainbow bridges the gap between theoretical side-channel attacks and real hardware attacks by providing a controlled simulation environment where students can observe and analyze side-channel leakage at the instruction level.
Unlike Lab 06 where we worked with pre-recorded power traces from real hardware, Rainbow allows us to:
•	Simulate cryptographic implementations in a CPU emulator
•	Generate synthetic power consumption traces
•	Observe leakage at the assembly instruction level
•	Test different attack scenarios without physical hardware
•	Understand how specific instructions leak information
•	Experiment with countermeasures in a safe environment
Objectives
After completing this lab, students will be able to:
•	Understand hardware-level side-channel leakage mechanisms
•	Install and configure Rainbow simulation framework
•	Write simple cryptographic implementations (AES, XOR cipher)
•	Generate synthetic power traces from code execution
•	Analyze leakage at the instruction level
•	Implement and test side-channel attacks (CPA, DPA)
•	Apply and evaluate basic countermeasures (masking, shuffling)
•	Understand the relationship between code and physical leakage
•	Simulate realistic attack scenarios without hardware
•	Compare simulated traces with real hardware behavior
Tools/Software Requirements
Linux (Ubuntu/Kali)
•	Ubuntu 20.04+ or Kali Linux
•	Python 3.8+
•	Rainbow framework (will be installed)
•	Unicorn CPU emulator
•	Lief (Library to Instrument Executable Formats)
•	SCAred (Side-Channel Analysis for Reverse Engineering)
 
Section 1: Understanding Rainbow Framework
Rainbow
Rainbow is an open-source side-channel analysis simulation tool developed by Ledger's Donjon security research team. It provides:
•	CPU emulation using Unicorn Engine (based on QEMU)
•	Synthetic trace generation simulating power consumption
•	Support for ARM Cortex-M architectures (common in embedded devices)
•	Hamming Weight and Hamming Distance leakage models
•	Integration with Python for analysis
•	Fast simulation compared to real hardware
•	Reproducible experiments
Architecture Overview
Rainbow Architecture:

1. INPUT: Binary executable (ELF file for ARM)
2. EMULATION: Unicorn CPU emulator executes code
3. INSTRUMENTATION: Lief hooks into execution
4. LEAKAGE MODEL: Simulates power based on operations
5. OUTPUT: Synthetic power traces (time series)
6. ANALYSIS: Standard SCA techniques (CPA, DPA)
Leakage Models in Rainbow
Hamming Weight (HW) Model
Power consumption proportional to number of '1' bits
Power(operation) = c × HW(data) + noise

Where:
- c = proportionality constant
- HW(data) = number of '1' bits
- noise = Gaussian noise

Example:
- Processing 0xFF (11111111) → High power
- Processing 0x00 (00000000) → Low power
Hamming Distance (HD) Model
Power consumption proportional to bit flips between operations
Power(transition) = c × HD(previous, current) + noise

Where:
- HD = number of bits that changed
- previous = value before operation
- current = value after operation

Example:
- 0xFF → 0x00: HD = 8 (all bits flip) → High power
- 0xFF → 0xFE: HD = 1 (one bit flip) → Low power
Which model is more realistic?
Hamming Distance (HD) is generally more accurate for CMOS circuits where power is consumed during transitions. However, both models are used in practice and Rainbow supports both.

Section 2: Installing Rainbow
Step 1: System Preparation
# Update system
sudo apt update
sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip git build-essential
sudo apt install -y gcc-arm-none-eabi binutils-arm-none-eabi

# Verify Python version (should be 3.8+)
python3 --version
Step 2: Install Rainbow and Dependencies
# Create virtual environment (recommended)
python3 -m venv rainbow_env
source rainbow_env/bin/activate

# Install Rainbow and dependencies
pip install rainbow-py
pip install numpy matplotlib scipy
pip install lief
pip install unicorn

# Verify installation
python3 -c "import rainbow; print('Rainbow installed successfully!')"
Step 3: Clone Rainbow Examples
# Clone Ledger's Rainbow repository
git clone https://github.com/Ledger-Donjon/rainbow.git
cd rainbow/

# Explore structure
ls -la examples/

# Check README
cat README.md
Section 3: Your First Rainbow Simulation
Example 1: Simple XOR Cipher
Let's start with a simple example to understand Rainbow's workflow.
Step 3.1: Write Target Code (C)
File: simple_xor.c
// simple_xor.c - Simple XOR encryption
#include <stdint.h>

void xor_encrypt(uint8_t *data, uint8_t *key, int length) {
    for(int i = 0; i < length; i++) {
        data[i] = data[i] ^ key[i % 16];  // 16-byte key
    }
}

int main() {
    // Plaintext
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    
    // Secret key
    uint8_t key[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    
    // Encrypt
    xor_encrypt(plaintext, key, 16);
    
    return 0;
}
Step 3.2: Compile for ARM
# Compile to ARM Cortex-M3 binary
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb \
    -O0 -g \
    -nostdlib \
    -T link.ld \
    -o simple_xor.elf \
    simple_xor.c

# Verify compilation
file simple_xor.elf
# Output: simple_xor.elf: ELF 32-bit LSB executable, ARM...

Note: You'll need a linker script (link.ld) for bare-metal ARM. Rainbow examples provide this.

Step 3.3: Rainbow Simulation Script
File: simulate_xor.py
#!/usr/bin/env python3
import rainbow
import numpy as np
import matplotlib.pyplot as plt

# Load ELF binary
emu = rainbow.Rainbow('simple_xor.elf')

# Set up memory and registers
emu.load()

# Start emulation
emu.start(start_address, num_instructions=1000)

# Extract power trace (Hamming Weight of register values)
trace = emu.get_trace()

# Plot trace
plt.figure(figsize=(14, 4))
plt.plot(trace)
plt.title('Simulated Power Trace - XOR Cipher')
plt.xlabel('Time (instruction count)')
plt.ylabel('Power Consumption (HW)')
plt.grid(True, alpha=0.3)
plt.savefig('xor_trace.png')
plt.show()

print(f"Generated {len(trace)} power samples")
Step 3.4: Run Simulation
python3 simulate_xor.py

# Expected output:
# Generated 1000 power samples
# [Plot shows power consumption over time]
Step 3.5: Analyze the Trace
What to look for in the trace:
•	Peaks: Correspond to operations on high Hamming Weight values
•	Patterns: Repetitive patterns indicate loop iterations
•	Baseline: Relatively constant for NOPs and low-activity instructions
•	Spikes: XOR operations with data-dependent values
•	Length: Proportional to number of instructions executed
Section 4: Performing Side-Channel Attacks
Correlation Power Analysis (CPA)
CPA is a statistical technique that correlates measured power consumption with predicted power consumption for different key hypotheses.
CPA Algorithm
For each key byte guess (0-255):
    1. For each trace:
        a. Compute hypothetical intermediate value
           (e.g., S-box(plaintext ⊕ key_guess))
        b. Compute hypothetical power (HW or HD)
    2. Compute correlation between:
        - Hypothetical power values
        - Actual measured power at each time point
    3. Key guess with highest correlation is likely correct
Implementing CPA in Rainbow
#!/usr/bin/env python3
import rainbow
import numpy as np
from scipy.stats import pearsonr

# AES S-box
SBOX = [0x63, 0x7C, 0x77, ...] # Full S-box

def hamming_weight(n):
    return bin(n).count('1')

def cpa_attack(traces, plaintexts, target_byte=0):
    """
    Perform CPA attack on simulated traces
    
    Args:
        traces: Power traces (N_traces x N_samples)
        plaintexts: Known plaintexts (N_traces x 16)
        target_byte: Which key byte to attack
    
    Returns:
        best_key: Recovered key byte
        correlations: Correlation values for all key guesses
    """
    N_traces, N_samples = traces.shape
    correlations = np.zeros(256)
    
    # For each key hypothesis
    for key_guess in range(256):
        # Compute hypothetical power for each trace
        hypothetical_power = np.zeros(N_traces)
        
        for trace_idx in range(N_traces):
            # Compute intermediate value
            pt_byte = plaintexts[trace_idx][target_byte]
            sbox_out = SBOX[pt_byte ^ key_guess]
            
            # Hamming weight model
            hypothetical_power[trace_idx] = hamming_weight(sbox_out)
        
        # Compute correlation at each time point
        max_corr = 0
        for sample_idx in range(N_samples):
            actual_power = traces[:, sample_idx]
            corr, _ = pearsonr(hypothetical_power, actual_power)
            max_corr = max(max_corr, abs(corr))
        
        correlations[key_guess] = max_corr
    
    # Key with highest correlation
    best_key = np.argmax(correlations)
    return best_key, correlations

# Usage
# traces = generate_multiple_traces()  # From Rainbow
# plaintexts = get_plaintexts()
# recovered_key, corr_values = cpa_attack(traces, plaintexts)
# print(f"Recovered key byte: 0x{recovered_key:02X}")
Section 5: Testing Countermeasures
Why Countermeasures?
Side-channel attacks are devastating because they bypass cryptographic security. Countermeasures are techniques to reduce or eliminate leakage.
Masking (Boolean Masking)
Split sensitive values using random masks
Without Masking:
    sensitive_value = key ^ plaintext

With Masking:
    mask = random()
    masked_value = (key ^ plaintext) ^ mask
    # Now: masked_value ⊕ mask = key ^ plaintext
    # But attacker doesn't know mask!

Implementation:
void aes_masked_sbox(uint8_t input, uint8_t mask) {
    uint8_t masked_input = input ^ mask;
    uint8_t masked_output = SBOX[masked_input];
    // Unmask at the end
    return masked_output ^ mask;
}
Shuffling (Random Execution Order)
Randomize operation order to decorrelate leakage
Without Shuffling:
    for(i = 0; i < 16; i++) {
        ciphertext[i] = AES_encrypt(plaintext[i], key);
    }

With Shuffling:
    int order[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    shuffle(order);  // Random permutation
    
    for(i = 0; i < 16; i++) {
        int idx = order[i];
        ciphertext[idx] = AES_encrypt(plaintext[idx], key);
    }
    
    # Now attacker doesn't know which trace corresponds to which byte!
Testing Countermeasures in Rainbow
# Compare attack success with/without countermeasures

# 1. Generate traces WITHOUT masking
traces_unprotected = generate_traces(implementation='plain_aes')
key_unprotected, corr_unprot = cpa_attack(traces_unprotected, plaintexts)

# 2. Generate traces WITH masking
traces_protected = generate_traces(implementation='masked_aes')
key_protected, corr_prot = cpa_attack(traces_protected, plaintexts)

# 3. Compare
print(f"Unprotected: Correlation = {max(corr_unprot):.4f}")
print(f"Protected: Correlation = {max(corr_prot):.4f}")

if max(corr_unprot) > 0.8:
    print("✗ Unprotected: Highly vulnerable!")
if max(corr_prot) < 0.2:
    print("✓ Protected: Countermeasure effective!")











Lab Tasks
Task 1: Installation and Setup 
1.	Install Rainbow framework and dependencies
2.	Clone Rainbow repository from GitHub
3.	Verify ARM toolchain installation
4.	Test basic Rainbow import in Python
5.	Explore example directory structure
6.	Compile a test program for ARM
7.	Take screenshot of successful installation



 

 
Task 2: Simple XOR Simulation 
1.	Write simple XOR cipher in C
2.	Compile to ARM binary (ELF format)
3.	Create Rainbow simulation script
4.	Generate synthetic power traces
5.	Plot and analyze traces
6.	Identify XOR operations in trace
7.	Experiment with different keys
8.	Take screenshots of traces

 

Task 3: AES Implementation and Analysis 
1.	Use provided AES implementation (Rainbow examples)
2.	Generate multiple traces with different plaintexts
3.	Analyze trace characteristics
4.	Identify S-box operations in traces
5.	Measure Hamming Weight distribution
6.	Compare with Lab 06 ASCAD traces
7.	Document differences (simulated vs real hardware)

import os
import numpy as np
import matplotlib.pyplot as plt
from rainbow import Print, TraceConfig, HammingWeight
from rainbow.generics import rainbow_arm
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR

binary_path = os.path.join(os.getcwd(), 'test_xor.elf')

emu = rainbow_arm(print_config=Print(0), trace_config=TraceConfig(register=HammingWeight()))

# Load the ELF binary into the emulator's memory
emu.load(binary_path, typ='elf', except_missing_libs=False)

# Map a RAM region for Unicorn (the underlying emulator)
RAM_BASE = 0x20000000
RAM_SIZE = 0x100000
emu.emu.mem_map(RAM_BASE, RAM_SIZE)

# Define addresses in RAM for our data
PLAINTEXT_ADDR = RAM_BASE + 0x1000
KEY_ADDR = RAM_BASE + 0x2000
STACK_ADDR = RAM_BASE + RAM_SIZE - 0x100  # Top of RAM
DUMMY_RETURN = 0xDEADBEEF                  # A known, invalid address to stop emulation

# --- Trace Generation Function ---
def generate_xor_trace(key_byte):
    """
    Runs the XOR cipher for a single key and returns the power trace.
    """
    # Reset the emulator state for a clean run
    emu.reset()

    # Prepare plaintext and key arrays in memory
    plaintext = b"HelloWorld12345678"
    key_array = bytes([key_byte] * 16)  # 16-byte key for pointer-based API
    emu.emu.mem_write(PLAINTEXT_ADDR, plaintext)
    emu.emu.mem_write(KEY_ADDR, key_array)

    # --- FINAL AND CRITICAL FIX: Prepare a Complete Stack Frame ---
    # The function is compiled with a standard prologue/epilogue (e.g., PUSH {R4-R11, LR}).
    # Its corresponding epilogue (POP {R4-R11, PC}) expects to pop 9 words (36 bytes) from the stack.
    # We must provide a stack frame that contains this much data to prevent it from
    # reading uninitialized memory and crashing.
    current_sp = emu.emu.reg_read(UC_ARM_REG_SP)

    # Push 32 bytes (8 words) of dummy data for the function to pop into registers.
    # This is a safe amount for a simple function.
    dummy_stack_data = b'\x00\x00\x00\x00' * 8
    current_sp -= len(dummy_stack_data)
    emu.emu.mem_write(current_sp, dummy_stack_data)

    # Now, push the actual return address. This will be the last thing popped.
    current_sp -= 4
    emu.emu.mem_write(current_sp, DUMMY_RETURN.to_bytes(4, 'little'))

    # Update the stack pointer to the new top of the stack.
    emu.emu.reg_write(UC_ARM_REG_SP, current_sp)
    # --- END OF FINAL FIX ---

    # Set up registers for the ARM calling convention (AAPCS)
    emu.emu.reg_write(UC_ARM_REG_R0, PLAINTEXT_ADDR)  # First arg: data pointer
    emu.emu.reg_write(UC_ARM_REG_R1, KEY_ADDR)        # Second arg: key pointer
    emu.emu.reg_write(UC_ARM_REG_R2, 16)              # Third arg: length
    emu.emu.reg_write(UC_ARM_REG_LR, DUMMY_RETURN)    # Set Link Register (good practice)

    # Get the address of the function from the binary (e.g., from objdump)
    function_addr = 0x5c  # Address of 'xor_with_trace_points'

    try:
        # Start emulation. It will stop when the PC hits DUMMY_RETURN.
        emu.start(begin=function_addr, end=DUMMY_RETURN)
    except Exception as e:
        # This exception is expected when the emulator jumps to the dummy address.
        # It's our signal that emulation is complete.
        # We will not print this to keep the output clean.
        pass

    # Extract the power trace from the emulator's trace buffer
    if not emu.trace:
        # If for some reason no trace was recorded, return a zero trace
        print(f"Warning: No trace data recorded for key 0x{key_byte:02X}. Returning zero trace.")
        return np.zeros(1000)

    # The trace contains events; we are interested in the 'register' leak model.
    power_trace = np.array([point.get('register', 0) for point in emu.trace])

    # Ensure the trace has a fixed length of 1000 samples
    if len(power_trace) < 1000:
        power_trace = np.pad(power_trace, (0, 1000 - len(power_trace)), 'constant')
    else:
        power_trace = power_trace[:1000]

    return power_trace

# --- Main Execution ---
if __name__ == "__main__":
    print("Generating XOR cipher power traces...")
    keys = [0x42, 0x13, 0x37, 0x99, 0xFF]
    traces = []
    labels = []

    for key in keys:
        print(f"Generating trace for key: 0x{key:02X}", end=' ')
        trace = generate_xor_trace(key)
        traces.append(trace)
        labels.append(key)
        print(f"(Trace length: {len(trace)})")

    # Convert lists to numpy arrays and save to files
    traces = np.array(traces)
    np.save('xor_traces.npy', traces)
    np.save('xor_labels.npy', np.array(labels))
    print(f"\nGenerated {len(traces)} traces with shape {traces.shape}")
    print("Traces saved to: xor_traces.npy")
    print("Labels saved to: xor_labels.npy")

    # --- Visualization and Analysis ---
    plt.figure(figsize=(12, 8))
    for i, (trace, key) in enumerate(zip(traces, labels)):
        plt.plot(trace[:500], label=f'Key 0x{key:02X}', alpha=0.7)

    plt.title('XOR Cipher Power Traces for Different Keys')
    plt.xlabel('Time (sample index)')
    plt.ylabel('Power (Hamming Weight)')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig('xor_traces.png')
    print("Plot saved to: xor_traces.png")
    # plt.show() # Uncomment to display the plot interactively

    print("\nAnalyzing trace differences...")
    for i in range(len(traces)):
        for j in range(i + 1, len(traces)):
            diff = np.mean(np.abs(traces[i] - traces[j]))
            print(f"Average difference between key 0x{labels[i]:02X} and 0x{labels[j]:02X}: {diff:.2f}")


 
 
 


Task 4: CPA Attack Implementation 
1.	Implement basic CPA attack function
2.	Generate 100+ traces for attack
3.	Perform CPA on first key byte
4.	Plot correlation values for all 256 key guesses
5.	Recover correct key byte
6.	Measure attack success rate
7.	Determine minimum traces needed

 

Task 5: Countermeasure Testing 
1.	Implement simple masking countermeasure
2.	Generate traces with masking enabled
3.	Perform CPA attack on masked implementation
4.	Compare correlation values (masked vs unmasked)
5.	Analyze effectiveness of countermeasure
6.	Test with different numbers of traces
7.	Document findings









Deliverable:
1.	Add screenshot / website links which clearly define the references for each answer on your report. 
2.	Finalize the document in a well-structured manner. Save the file with your name and 
registration number and upload it on LMS under submission link before the deadline.

