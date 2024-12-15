
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

keys = {
    0b00: 0xd7ffe8f10f124c56918a614acfc65814,
    0b01: 0x5526736ddd6c4a0592ed33cbc5b1b76d,
    0b10: 0x88863eef1a37427ea0b867227f09a7c1,
    0b11: 0x45355f125db4449eb07415e8df5e27d4
}


# Function to encrypt a string using AES
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # Generate a random 16-byte IV

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create encryptor
    encryptor = cipher.encryptor()

    # Pad the plaintext to be AES block size (16 bytes) compatible
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the ciphertext (to be used in decryption)
    return iv + ciphertext


# Function to decrypt the AES ciphertext
def aes_decrypt(ciphertext, key):
    # Extract the IV from the first 16 bytes
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # Create cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create decryptor
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the original plaintext as a string
    return unpadded_data.decode()


def decompose_byte(byte):
    crumbs = []
    crumb = byte & 0b11
    crumbs.append(crumb)
    byte = byte >> 2
    crumb = byte & 0b11
    crumbs.append(crumb)
    byte = byte >> 2
    crumb = byte & 0b11
    crumbs.append(crumb)
    byte = byte >> 2
    crumb = byte & 0b11
    crumbs.append(crumb)
    return crumbs


def recompose_byte(crumbs):
    # Combine the crumbs back into the original byte
    return (crumbs[0] << 6) + (crumbs[1] << 4) + (crumbs[2] << 2) + crumbs[3]
