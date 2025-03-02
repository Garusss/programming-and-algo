import argparse
import os
from cryptography.fernet import Fernet
from PIL import Image
import base64

def generate_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def encrypt_message(message, key):
    """Encrypt the message using AES encryption."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    """Decrypt the message using AES decryption."""
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return "❌ Failed to decode the message. Incorrect key!"

def save_key(output_image, key):
    """Save the encryption key to a text file."""
    key_filename = f"{output_image}_key.txt"
    with open(key_filename, "wb") as f:  # Save in binary format
        f.write(key)
    print(f"🔑 Key saved to {key_filename} (Use this key for decoding)")

def load_key_from_file(key_file):
    """Load the encryption key from a saved key file."""
    try:
        with open(key_file, "rb") as f:  # Read in binary format
            key = f.read()
        return key
    except Exception as e:
        print(f"❌ Error loading key: {e}")
        return None

def encode_image(image_path, message, output_image, key):
    """Hide an encrypted message inside an image."""
    try:
        img = Image.open(image_path).convert("RGB")
        encrypted_message = encrypt_message(message, key)

        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message) + '1111111111111110'

        if len(binary_message) > img.width * img.height:
            raise ValueError("Message too long to encode in this image.")

        pixels = img.load()
        data_index = 0

        for y in range(img.height):
            for x in range(img.width):
                if data_index < len(binary_message):
                    r, g, b = pixels[x, y]
                    r = (r & ~1) | int(binary_message[data_index])  
                    pixels[x, y] = (r, g, b)
                    data_index += 1
                else:
                    break

        img_format = "PNG" if output_image.lower().endswith(".png") else "JPEG"
        img.save(output_image, format=img_format)
        save_key(output_image, key)
        print(f"✅ Message successfully encoded into {output_image}")

    except Exception as e:
        print(f"❌ Error: {e}")

def decode_image(image_path, key):
    """Extract and decrypt the hidden message from an image."""
    try:
        img = Image.open(image_path).convert("RGB")
        binary_message = ''
        pixels = img.load()

        for y in range(img.height):
            for x in range(img.width):
                r, _, _ = pixels[x, y]
                binary_message += str(r & 1)

        chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
        encrypted_message = ''.join(chr(int(char, 2)) for char in chars)

        if "1111111111111110" in encrypted_message:
            encrypted_message = encrypted_message.split("1111111111111110")[0]
        
        return decrypt_message(encrypted_message, key)

    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="🔐 Secure Image Steganography Tool (Fixed Key Handling)")
    parser.add_argument("-e", "--encode", help="Encode a message into an image", action="store_true")
    parser.add_argument("-d", "--decode", help="Decode a message from an image", action="store_true")
    parser.add_argument("-i", "--image", help="Input image path", required=True)
    parser.add_argument("-o", "--output", help="Output image path (for encoding)")
    parser.add_argument("-m", "--message", help="Message to encode (or file path)")
    parser.add_argument("-k", "--keyfile", help="Path to the key file for decryption", required=False)

    args = parser.parse_args()

    if args.encode:
        if not args.output or not args.message:
            print("❌ Error: Output image and message are required for encoding.")
            return

        # Generate a new encryption key
        key = generate_key()

        if os.path.exists(args.message):
            with open(args.message, "r") as file:
                message = file.read()
        else:
            message = args.message

        encode_image(args.image, message, args.output, key)

    elif args.decode:
        if not args.keyfile:
            print("❌ Error: A key file is required for decoding!")
            return

        key = load_key_from_file(args.keyfile)
        if not key:
            return

        decoded_message = decode_image(args.image, key)
        if decoded_message:
            print(f"🔍 Decoded Message: {decoded_message}")

    else:
        print("❌ Error: Use -e to encode or -d to decode.")

if __name__ == "__main__":
    main()