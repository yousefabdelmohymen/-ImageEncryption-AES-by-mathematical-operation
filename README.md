import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets

def generate_aes_key(key_size):
    """Generate a random AES key of the specified size."""
    return secrets.token_bytes(key_size)

def manipulate_pixels(image):
    """Manipulate pixels by adding a constant value (e.g., 50) to each pixel."""
    # Perform a simple mathematical operation on each pixel
    manipulated_image = image + 50  # Example: adding 50 to each pixel value
    return manipulated_image

def encrypt_image(image_path, key):
    try:
        # Read the image
        image = cv2.imread(image_path)

        if image is None:
            print(f"Error: Unable to read image from {image_path}")
            return False

        # Ensure image is in uint8 format for proper encryption
        image = image.astype(np.uint8)

        # Manipulate pixels (example: addition operation)
        manipulated_image = manipulate_pixels(image)

        # Convert key to bytes if it's not already
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes.")

        # Initialize AES cipher in CBC mode
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Convert manipulated image to bytes and pad if necessary
        image_data = manipulated_image.tobytes()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(image_data) + padder.finalize()

        # Encrypt the image data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted image with the specified filename
        with open('encrypted_image.jpg', 'wb') as f:
            f.write(iv + encrypted_data)

        print(f"Encrypted image saved as 'encrypted_image.jpg'")
        return True
    except Exception as e:
        print(f"Error during encryption: {str(e)}")
        return False

def decrypt_image(encrypted_image_path, key, original_image_shape):
    try:
        # Read the encrypted image
        with open(encrypted_image_path, 'rb') as f:
            encrypted_data = f.read()

        if len(encrypted_data) < 16:
            print("Error: Invalid encrypted image file.")
            return False

        # Extract initialization vector (IV) and encrypted data
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        # Convert key to bytes if it's not already
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes.")

        # Initialize AES cipher in CBC mode with extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the encrypted data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Convert decrypted data back to image array
        decrypted_image = np.frombuffer(unpadded_data, dtype=np.uint8).reshape(original_image_shape)

        # Save the decrypted image with the specified filename
        cv2.imwrite('decrypted_image.jpg', decrypted_image)
        print(f"Decrypted image saved as 'decrypted_image.jpg'")
        return True
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        return False

def main():
    try:
        while True:
            image_path = input("Enter the image path: ").strip()

            # Check if the image path is valid
            if not image_path:
                print("Error: Image path cannot be empty.")
                continue

            # Check if the image file exists
            if not os.path.isfile(image_path):
                print(f"Error: Image file '{image_path}' not found.")
                continue

            key_size = 32  # AES-256 key size in bytes
            key = generate_aes_key(key_size)

            # Store the original image shape for decryption
            original_image = cv2.imread(image_path)
            if original_image is None:
                print(f"Error: Unable to read image from {image_path}")
                continue
            original_image_shape = original_image.shape

            if encrypt_image(image_path, key):
                print("Image encrypted successfully!")
                continue_decrypt = input("Do you want to decrypt this image now? (yes/no): ").strip().lower()

                if continue_decrypt == 'yes':
                    if decrypt_image('encrypted_image.jpg', key, original_image_shape):
                        print("Image decrypted successfully!")
                    else:
                        print("Decryption failed.")
                else:
                    print("Skipping decryption.")
            else:
                print("Encryption failed.")

            # Ask user if they want to continue
            choice = input("Do you want to continue? (yes/no): ").strip().lower()
            if choice != 'yes':
                break

    except Exception as e:
        print(f"Error in main: {str(e)}")

if __name__ == "__main__":
    main()
