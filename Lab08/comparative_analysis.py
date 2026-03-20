import h5py
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import pandas as pd


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

    history = model.fit(x_train, y_train, epochs=10 if variable_key else 5,
                        batch_size=128, validation_data=(x_val, y_val), verbose=1)
    model.save(model_path)

    # Evaluate attack on attack set
    preds_attack = model.predict(x_attack, verbose=0)

    if not variable_key:
        fixed_key_byte = key_attack[0, 0]
        rank, scores = key_recovery_from_predictions(preds_attack, pt_attack, fixed_key_byte)
        success_rate = 1.0 if rank == 0 else 0.0
        return history, success_rate, rank, None
    else:
        ranks = per_trace_variable_key_success(preds_attack, pt_attack, key_attack)
        success_rate = np.mean(ranks == 0)
        mean_rank = np.mean(ranks)
        return history, success_rate, mean_rank, ranks


def main():
    print('Running fixed-key experiment...')
    hist_fixed, sr_fixed, rank_fixed, _ = run_experiment('datasets/fixed_key_dataset.h5', variable_key=False, model_path='fixed_key_model.h5')

    print('Running variable-key experiment...')
    hist_var, sr_var, rank_var, ranks_var = run_experiment('datasets/variable_key_dataset.h5', variable_key=True, model_path='variable_key_model.h5')

    # Comparison Table
    comparison = pd.DataFrame({
        'Metric': ['Training Accuracy (final)', 'Validation Accuracy (final)', 'Attack Success Rate', 'Key Rank'],
        'Fixed-Key': [hist_fixed.history['accuracy'][-1], hist_fixed.history['val_accuracy'][-1], sr_fixed, rank_fixed],
        'Variable-Key': [hist_var.history['accuracy'][-1], hist_var.history['val_accuracy'][-1], sr_var, rank_var]
    })
    print('\nComparison Table:')
    print(comparison.to_string(index=False))

    # Plot Training Curves
    plt.figure(figsize=(12, 5))

    plt.subplot(1, 2, 1)
    plt.plot(hist_fixed.history['accuracy'], label='Fixed-Key Train')
    plt.plot(hist_fixed.history['val_accuracy'], label='Fixed-Key Val')
    plt.plot(hist_var.history['accuracy'], label='Variable-Key Train')
    plt.plot(hist_var.history['val_accuracy'], label='Variable-Key Val')
    plt.title('Training Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()

    plt.subplot(1, 2, 2)
    plt.plot(hist_fixed.history['loss'], label='Fixed-Key Train')
    plt.plot(hist_fixed.history['val_loss'], label='Fixed-Key Val')
    plt.plot(hist_var.history['loss'], label='Variable-Key Train')
    plt.plot(hist_var.history['val_loss'], label='Variable-Key Val')
    plt.title('Training Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()

    plt.tight_layout()
    plt.savefig('training_curves.png')
    plt.show()

    # Key Rank Distribution for Variable-Key
    if ranks_var is not None:
        plt.figure()
        plt.hist(ranks_var, bins=50, alpha=0.7, edgecolor='black')
        plt.title('Variable-Key Attack: Key Rank Distribution')
        plt.xlabel('Key Rank')
        plt.ylabel('Frequency')
        plt.savefig('rank_distribution.png')
        plt.show()

    # Explanation
    print('\nExplanation:')
    print('Variable-key attacks are more challenging than fixed-key attacks because:')
    print('1. In fixed-key scenarios, the model learns patterns specific to one key, allowing it to generalize well on that key.')
    print('2. In variable-key scenarios, each trace has a different key, so the model must learn to distinguish leakage across all possible keys, which is harder due to increased variability.')
    print('3. This leads to lower success rates and higher average key ranks in variable-key attacks.')


if __name__ == '__main__':
    main()