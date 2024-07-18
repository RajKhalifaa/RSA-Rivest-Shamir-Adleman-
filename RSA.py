from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def encrypt_symmetric_key(symmetric_key, public_key):
    """
    Encrypts a symmetric key using RSA encryption with OAEP padding.

    :param symmetric_key: The symmetric key to be encrypted.
    :param public_key: The RSA public key in PEM format.
    :return: The encrypted symmetric key.
    """
    RSA_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_symmetric_key = RSA_cipher.encrypt(symmetric_key)
    return encrypted_symmetric_key

def decrypt_symmetric_key(encrypted_symmetric_key, private_key):
    """
    Decrypts an encrypted symmetric key using RSA decryption with OAEP padding.

    :param encrypted_symmetric_key: The encrypted symmetric key.
    :param private_key: The RSA private key in PEM format.
    :return: The decrypted symmetric key.
    """
    RSA_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted_symmetric_key = RSA_cipher.decrypt(encrypted_symmetric_key)
    return decrypted_symmetric_key

def encrypt_plaintext(symmetric_key, nonce, plaintext):
    """
    Encrypts plaintext using AES encryption with GCM mode.

    :param symmetric_key: The symmetric key for AES encryption.
    :param nonce: The nonce value for AES-GCM mode.
    :param plaintext: The plaintext message to be encrypted.
    :return: The ciphertext.
    """
    symmetric_cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = symmetric_cipher.encrypt_and_digest(plaintext)
    return ciphertext

def decrypt_plaintext(symmetric_key, nonce, ciphertext):
    """
    Decrypts ciphertext using AES decryption with GCM mode.

    :param symmetric_key: The symmetric key for AES decryption.
    :param nonce: The nonce value for AES-GCM mode.
    :param ciphertext: The ciphertext to be decrypted.
    :return: The decrypted plaintext.
    """
    symmetric_cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
    decrypted_plaintext = symmetric_cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
    return decrypted_plaintext

# Generate symmetric key and nonce
symmetric_key = get_random_bytes(16)
nonce = get_random_bytes(16)

# Get user input for plaintext
plaintext = input("Enter your secret message: ").encode()

# Generate RSA key pair
RSA_key = RSA.generate(2048)
private_key = RSA_key.export_key(format="PEM")
public_key = RSA_key.publickey().export_key(format="PEM")

# Encrypt symmetric key using RSA public key
encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, public_key)

# Decrypt symmetric key using RSA private key
decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, private_key)

# Encrypt plaintext using symmetric key and nonce
ciphertext = encrypt_plaintext(symmetric_key, nonce, plaintext)

# Decrypt ciphertext using symmetric key and nonce
decrypted_plaintext = decrypt_plaintext(symmetric_key, nonce, ciphertext)

# Print outputs
print("\nPrivate key:\n", private_key.decode())
print("\nPublic key:\n", public_key.decode())
print("\nSymmetric key:\n", symmetric_key.hex())
print("\nEncrypted symmetric key:\n", encrypted_symmetric_key.hex())
print("\nDecrypted symmetric key:\n", decrypted_symmetric_key.hex())
print("\nPlaintext:\n", plaintext.decode())
print("\nCiphertext:\n", ciphertext.hex())
print("\nDecrypted plaintext:\n", decrypted_plaintext.decode())
