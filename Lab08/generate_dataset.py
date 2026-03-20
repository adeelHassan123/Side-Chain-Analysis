import numpy as np
import h5py
import os


def hamming_weight(byte_val):
    return bin(int(byte_val)).count('1')


def generate_sca_dataset(filename, num_profiling=50000, num_attack=10000, fixed_key=True):
    """Generate ASCAD-like dataset with 1551 sample traces"""
    assert num_profiling > 0 and num_attack > 0
    total_traces = num_profiling + num_attack

    # Plaintext and key generation
    plaintext = np.random.randint(0, 256, (total_traces, 16), dtype=np.uint8)

    if fixed_key:
        fixed_key_bytes = np.random.randint(0, 256, 16, dtype=np.uint8)
        print(f"Fixed key (hex): {fixed_key_bytes.tolist()}")
        key = np.tile(fixed_key_bytes, (total_traces, 1))
    else:
        # Unique random key for each trace
        key = np.zeros((total_traces, 16), dtype=np.uint8)
        key_set = set()
        for i in range(total_traces):
            while True:
                candidate = np.random.randint(0, 256, 16, dtype=np.uint8)
                kchan = candidate.tobytes()
                if kchan not in key_set:
                    key_set.add(kchan)
                    key[i] = candidate
                    break

    # Ciphertext and trace generation
    ciphertext = np.zeros_like(plaintext)
    traces = np.zeros((total_traces, 1551), dtype=np.float32)

    for i in range(total_traces):
        ciphertext[i] = plaintext[i] ^ key[i]
        intermediate = ciphertext[i]
        hw_leakage = np.array([hamming_weight(v) for v in intermediate], dtype=np.float32)

        # Simulate 1551 sample trace by linear interpolation plus noise
        baseline = np.interp(np.linspace(0, 15, 1551), np.arange(16), hw_leakage)
        noise = np.random.normal(loc=0.0, scale=0.3, size=baseline.shape)
        traces[i] = baseline + noise

    # Write ASCAD-like structure
    with h5py.File(filename, 'w') as f:
        prof = f.create_group('Profiling_traces')
        prof.create_dataset('traces', data=traces[:num_profiling], dtype='float32')
        prof_meta = prof.create_group('metadata')
        prof_meta.create_dataset('plaintext', data=plaintext[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('key', data=key[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('ciphertext', data=ciphertext[:num_profiling], dtype='uint8')

        att = f.create_group('Attack_traces')
        att.create_dataset('traces', data=traces[num_profiling:], dtype='float32')
        att_meta = att.create_group('metadata')
        att_meta.create_dataset('plaintext', data=plaintext[num_profiling:], dtype='uint8')
        att_meta.create_dataset('key', data=key[num_profiling:], dtype='uint8')
        att_meta.create_dataset('ciphertext', data=ciphertext[num_profiling:], dtype='uint8')

    print(f"Saved {filename}: profiling={num_profiling}, attack={num_attack}")


if __name__ == '__main__':
    os.makedirs('datasets', exist_ok=True)
    generate_sca_dataset('datasets/fixed_key_dataset.h5', 50000, 10000, fixed_key=True)
    generate_sca_dataset('datasets/variable_key_dataset.h5', 50000, 10000, fixed_key=False)
