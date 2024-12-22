import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


class Cryptography:
    @staticmethod
    def generate_key(bit_length):
        p = Cryptography.blum_prime(bit_length // 2)
        q = Cryptography.blum_prime(bit_length // 2)
        n = p * q
        return n, p, q

    @staticmethod
    def encrypt(m, n):
        return pow(m, 2, n)

    @staticmethod
    def decrypt(c, p, q):
        n = p * q
        p1 = pow(c, (p + 1) // 4, p)
        p2 = p - p1
        q1 = pow(c, (q + 1) // 4, q)
        q2 = q - q1

        gcd, yp, yq = Cryptography.extended_gcd(p, q)

        d1 = (yp * p * q1 + yq * q * p1) % n
        d2 = (yp * p * q2 + yq * q * p1) % n
        d3 = (yp * p * q1 + yq * q * p2) % n
        d4 = (yp * p * q2 + yq * q * p2) % n

        return d1, d2, d3, d4

    @staticmethod
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = Cryptography.extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    @staticmethod
    def blum_prime(bit_length):
        while True:
            p = getPrime(bit_length)
            if p % 4 == 3:
                return p

    @staticmethod
    def split_into_blocks(message, block_size):
        # Split message into blocks of max `block_size` length
        blocks = []
        for i in range(0, len(message), block_size):
            blocks.append(message[i:i + block_size])
        return blocks

    @staticmethod
    def decrypt_blocks(decrypted_values):
        decrypted_message = ""
        for value in decrypted_values:
            try:
                candidate_message = long_to_bytes(value).decode('ascii')
                decrypted_message += candidate_message
            except Exception:
                pass
        return decrypted_message


def main():
    # Generate keys
    print("\n=== Key Generation ===")
    n, p, q = Cryptography.generate_key(512)
    print("Public Key (n):", n)
    print("Private Keys (p, q):", p, q)

    # Input plaintext message
    plaintext = input("\nEnter a plaintext message to encrypt: ")
    print("Input Plaintext:", plaintext)

    # Split the message into blocks if it exceeds 63 characters
    block_size = 63
    message_blocks = Cryptography.split_into_blocks(plaintext, block_size)
    print("\nMessage Split into Blocks:", message_blocks)

    # Encrypt each block
    encrypted_blocks = []
    for block in message_blocks:
        m = bytes_to_long(block.encode('ascii'))  # Convert block to number
        c = Cryptography.encrypt(m, n)  # Encrypt the block
        encrypted_blocks.append(c)

    print("\nEncrypted Blocks (Ciphertext):", encrypted_blocks)

    # Decrypt each block
    decrypted_values = []
    for c in encrypted_blocks:
        decrypted_values.extend(Cryptography.decrypt(c, p, q))

    # Reconstruct the decrypted message
    decrypted_message = Cryptography.decrypt_blocks(decrypted_values)

    # Output the decrypted message
    print("\n=== Decryption ===")
    if decrypted_message == plaintext:
        print("Decrypted Message:", decrypted_message)
    else:
        print("Decryption failed. Could not recover the original message.")


if __name__ == "__main__":
    main()
