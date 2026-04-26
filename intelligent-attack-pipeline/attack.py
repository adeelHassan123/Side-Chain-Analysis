import h5py
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

def hamming_weight(arr):
    return np.array([bin(int(v)).count('1') for v in arr], dtype=np.int32)

def build_model(input_dim=1551, num_classes=9, dropout_rate=0.0, variable_key=False):
    model = Sequential()
    if variable_key:
        model.add(Dense(512, activation='relu', input_shape=(input_dim,)))
        model.add(Dropout(dropout_rate))
        model.add(Dense(512, activation='relu'))
        model.add(Dropout(dropout_rate))
        model.add(Dense(256, activation='relu'))
    else:
        model.add(Dense(256, activation='relu', input_shape=(input_dim,)))
        model.add(Dense(256, activation='relu'))

    model.add(Dense(num_classes, activation='softmax'))
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model


def generate_labels(pt, key, target_byte=0):
    intermediate = np.bitwise_xor(pt[:, target_byte], key[:, target_byte])
    return hamming_weight(intermediate)


def key_recovery_from_predictions(predictions, pt, true_key_byte):
    # predictions shape [num_traces, num_classes=9]
    num_traces = pt.shape[0]
    key_scores = np.zeros(256, dtype=np.float64)
    for k in range(256):
        hw_hyp = hamming_weight(np.bitwise_xor(pt[:, 0], k))
        probs = predictions[np.arange(num_traces), hw_hyp]
        key_scores[k] = np.sum(np.log(probs + 1e-36))

    rank = np.argsort(-key_scores)
    true_rank = np.where(rank == int(true_key_byte))[0][0]
    return int(true_rank), key_scores


def per_trace_variable_key_success(predictions, pt, key_bytes):
    n = pt.shape[0]
    ranks = np.zeros(n, dtype=np.int32)
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        for k in range(256):
            hw = bin(int(pt[i, 0] ^ k)).count('1')
            score[k] = np.log(predictions[i, hw] + 1e-36)

        rank = np.argsort(-score)
        ranks[i] = np.where(rank == int(key_bytes[i, 0]))[0][0]
    return ranks


def run_experiment(datafile, variable_key=False, model_path='model.h5'):
    with h5py.File(datafile, 'r') as f:
        x = f['Profiling_traces/traces'][:]
        pt = f['Profiling_traces/metadata/plaintext'][:]
        key = f['Profiling_traces/metadata/key'][:]

        x_attack = f['Attack_traces/traces'][:]
        pt_attack = f['Attack_traces/metadata/plaintext'][:]
        key_attack = f['Attack_traces/metadata/key'][:]

    y = generate_labels(pt, key, target_byte=0)
    y_cat = to_categorical(y, num_classes=9)

    x_train, x_val, y_train, y_val = train_test_split(x, y_cat, test_size=0.2, stratify=y, random_state=42)

    model = build_model(input_dim=x.shape[1], num_classes=9, dropout_rate=0.25 if variable_key else 0.0, variable_key=variable_key)

    history = model.fit(x_train, y_train, epochs=70 if variable_key else 50,
                        batch_size=256, validation_data=(x_val, y_val), verbose=2)
    model.save(model_path)

    print(f"Model saved to {model_path}")

    # Evaluate attack on attack set
    preds_attack = model.predict(x_attack)

    if not variable_key:
        fixed_key_byte = key_attack[0, 0]
        rank, scores = key_recovery_from_predictions(preds_attack, pt_attack, fixed_key_byte)
        print(f"Fixed-key attack result: true byte=0x{fixed_key_byte:02x}, rank={rank}")
        success_rate = 1.0 if rank == 0 else 0.0
        print(f"Fixed-key success rate (rank 0): {success_rate*100:.2f}%")
    else:
        ranks = per_trace_variable_key_success(preds_attack, pt_attack, key_attack)
        success_rate = np.mean(ranks == 0)
        mean_rank = np.mean(ranks)
        print(f"Variable-key attack success rate (rank0): {success_rate*100:.2f}%")
        print(f"Variable-key mean key rank: {mean_rank:.2f}")

    return history


if __name__ == '__main__':
    print('Running fixed-key experiment...')
    run_experiment('datasets/fixed_key_dataset.h5', variable_key=False, model_path='fixed_key_model.h5')

    print('Running variable-key experiment...')
    run_experiment('datasets/variable_key_dataset.h5', variable_key=True, model_path='variable_key_model.h5')
