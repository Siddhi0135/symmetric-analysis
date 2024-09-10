from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
import os
import time
import matplotlib.pyplot as plt

# Key and IV Generation for AES
def generate_aes_key_iv(key_size=32):
    key = os.urandom(key_size)  # AES-256 requires 32 bytes key
    iv = os.urandom(16)         # AES block size is 16 bytes
    return key, iv

# AES Encryption
def aes_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# AES Decryption
def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Key Generation for DES
def generate_des_key():
    return os.urandom(8)  # DES requires an 8-byte key

# DES Encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return iv, ciphertext

# DES Decryption
def des_decrypt(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES.block_size)
    return plaintext

# Key Generation for 3DES
def generate_3des_key():
    while True:
        key = os.urandom(24)  # Generate a 24-byte (192-bit) key
        try:
            DES3.adjust_key_parity(key)
            return key
        except ValueError:
            continue

# 3DES Encryption
def triple_des_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(plaintext, DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return iv, ciphertext

# 3DES Decryption
def triple_des_decrypt(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES3.block_size)
    return plaintext

# Function to measure performance
def measure_performance(algorithm_name, encrypt_func, decrypt_func, key, plaintext, iv=None):
    # Measure encryption time
    start_time = time.perf_counter()
    if iv:
        ciphertext = encrypt_func(plaintext, key, iv)
    else:
        iv, ciphertext = encrypt_func(plaintext, key)
    encryption_time = time.perf_counter() - start_time

    # Measure decryption time
    start_time = time.perf_counter()
    if iv:
        decrypt_func(ciphertext, key, iv)
    else:
        decrypt_func(ciphertext, key)
    decryption_time = time.perf_counter() - start_time

    print(f"{algorithm_name} Encryption Time: {encryption_time:.6f} seconds")
    print(f"{algorithm_name} Decryption Time: {decryption_time:.6f} seconds\n")

    return encryption_time, decryption_time

# Function to plot performance comparison
def plot_performance(encryption_times, decryption_times):
    algorithms = ['AES', 'DES', '3DES']
    x = range(len(algorithms))

    plt.figure(figsize=(10, 5))

    plt.bar(x, encryption_times, width=0.4, label='Encryption Time', color='skyblue', align='center')
    plt.bar(x, decryption_times, width=0.4, label='Decryption Time', color='lightcoral', align='edge')

    plt.xlabel('Algorithm')
    plt.ylabel('Time (seconds)')
    plt.title('Performance Comparison of Symmetric Encryption Algorithms')
    plt.xticks(x, algorithms)
    plt.legend()
    plt.show()

# Main function
def main():
    print("Symmetric Encryption Algorithms:")
    print("1. AES (Advanced Encryption Standard)")
    print("2. DES (Data Encryption Standard)")
    print("3. 3DES (Triple Data Encryption Standard)")

    choice = input("Select the encryption algorithm (1/2/3): ")

    # User input for plaintext
    plaintext = input("Enter the plaintext to encrypt: ").encode()

    encryption_times = []
    decryption_times = []

    if choice == '1':
        print("\nUsing AES Encryption")
        key, iv = generate_aes_key_iv()
        enc_time, dec_time = measure_performance("AES", aes_encrypt, aes_decrypt, key, plaintext, iv)
        encryption_times.append(enc_time)
        decryption_times.append(dec_time)

    elif choice == '2':
        print("\nUsing DES Encryption")
        key = generate_des_key()
        iv, _ = des_encrypt(plaintext, key)  # Capture IV during encryption
        enc_time, dec_time = measure_performance("DES", des_encrypt, des_decrypt, key, plaintext)
        encryption_times.append(enc_time)
        decryption_times.append(dec_time)

    elif choice == '3':
        print("\nUsing 3DES Encryption")
        key = generate_3des_key()
        iv, _ = triple_des_encrypt(plaintext, key)  # Capture IV during encryption
        enc_time, dec_time = measure_performance("3DES", triple_des_encrypt, triple_des_decrypt, key, plaintext)
        encryption_times.append(enc_time)
        decryption_times.append(dec_time)

    else:
        print("Invalid choice! Please select 1, 2, or 3.")
        return

    # Plot performance comparison
    plot_performance(encryption_times, decryption_times)

if __name__ == "__main__":
    main()
