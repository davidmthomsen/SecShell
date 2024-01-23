import argparse
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
from Crypto.Hash import RIPEMD160
import urllib.parse
import sys

def read_data(file_path):
    try:
        with open (file_path, 'r') as file:
            return file.read()
    except IOError:
        print(f"Error: Could not read file {file_path}")
        sys.exit(1)

def encode_data(args):
    data = args.data or read_data(args.file) if args.file else sys.stdin.read().strip()

    if args.type == 'base64':
        encoded_data = base64.b64encode(data.encode('utf-8'))  # Encode string to bytes
        print(encoded_data.decode('utf-8'))  # Decode bytes to string for display
    elif args.type == 'urlencode':
        encoded_data = urllib.parse.quote_plus(data)
        print(encoded_data)
    elif args.type == 'hex':
        encoded_data = binascii.hexlify(data.encode('utf-8'))
        print(encoded_data.decode('utf-8'))
    elif args.type == 'base32':
        encoded_data = base64.b32encode(data.encode('utf-8'))
        print(encoded_data.decode('utf-8'))
    elif args.type == 'ascii85':
        encoded_data = base64.a85encode(data.encode('utf-8'))
        print(encoded_data.decode('utf-8'))
    elif args.type == 'base85':
        encoded_data = base64.b85encode(data.encode('utf-8'))
        print(encoded_data.decode('utf-8'))
    else:
        print(f"Encoding type {args.type} is not implemented.")

def decode_data(args):
    data = args.data or read_data(args.file) if args.file else sys.stdin.read().strip()

    if args.type == 'base64':
        decoded_data = base64.b64decode(data).decode('utf-8')
        print(decoded_data)
    elif args.type == 'base32':
        decoded_data = base64.b32decode(data).decode('utf-8')
        print(decoded_data)
    elif args.type == 'base85':
        decoded_data = base64.b85decode(data).decode('utf-8')
        print(decode_data)
    elif args.type == 'ascii85':
        decoded_data = base64.a85decode(data).decode('utf-8')
        print(decoded_data)
    elif args.type == 'hex':
        decoded_data = binascii.unhexlify(data).decode('utf-8')
        print(decoded_data)
    elif args.type == 'urlencode':
        decoded_data = urllib.parse.unquote_plus(data)
        print(decoded_data)
    else:
        print(f"Decoding type {args.type} is not implemented.")

def hash_data(args):
    data = args.data or read_data(args.file) if args.file else sys.stdin.read().strip()
    data_bytes = data.encode('utf-8')

    # Function to handle data hashing 
    if args.type == 'sha256':
        hash_object = hashlib.sha256(data_bytes) # Hashing requires encode bytes
        hex_dig = hash_object.hexdigest() # Get hexadecimal digest string
        print(hex_dig)
    elif args.type == 'md5':
        hash_object = hashlib.md5(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'sha1':
        hash_object = hashlib.sha1(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'sha512':
        hash_object = hashlib.sha512(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'sha3_256':
        hash_object = hashlib.sha3_256(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'sha3_512':
        hash_object = hashlib.sha3_512(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'blake2b':
        hash_object = hashlib.blake2b(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'blake2s':
        hash_object = hashlib.blake2s(data_bytes)
        print(hash_object.hexdigest())
    elif args.type == 'ripemd160':
        hash_object = hashlib.new('ripemd160', data_bytes)
        print(hash_object.hexdigest())
    else:
        print(f"Hash type {args.type} not implemented.")

def encrypt_data(args):
    data = args.data
    key = args.key

    # Convert strings to bytes
    data_bytes = data.encode('utf-8')
    key_bytes = key.encode('utf-8')

    # Ensure key is 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
    key_bytes = pad(key_bytes, 32)

    # Create AES Cipher
    cipher = AES.new(key_bytes, AES.MODE_CBC)

    # Pad data and encrypt
    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))

    # Encode the IV and ciphertext to base64 for easy storage/transmission 
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')

    print(f"IV: {iv}\nCipher Text: {ct}")

def decrypt_data(args):
    iv = args.iv
    ct = args.data
    key = args.key

    # Convert base64 strings and key to bytes
    iv_bytes = base64.b64decode(iv)
    ct_bytes = base64.b64decode(ct)
    key_bytes = key.encode('utf-8')

    # Ensure key is of proper length
    key_bytes = pad(key_bytes, AES.block_size)

    # Create AES cipher
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)

    # Decrypt and unpad
    pt_bytes = unpad(cipher.decrypt(ct_bytes), AES.block_size)

    print(f"Plain Text: {pt_bytes.decode('utf-8')}")

def main():
    parser = argparse.ArgumentParser(description="SecShell - Security CLI Tool")
    parser.add_argument('-f', '--file', type=str, help='Path to a file containing data')
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser("encode", help="Encode data in a specified format",
                                          description="Encode data in various formats like Base64, URL, Hex, Base32, ASCII85, or Base85.")
    encode_parser.add_argument('type', type=str, choices=['base64', 'urlencode', 'hex', 'base32', 'ascii85', 'base85'], help='Type of encoding')
    encode_parser.add_argument('data', nargs='?', type=str, help='Data to encode')
    encode_parser.set_defaults(func=encode_data)

    # Subparser for decoding
    decode_parser = subparsers.add_parser("decode", help="Decode data in a specified format")
    decode_parser.add_argument('type', type=str, choices=['base64', 'urlencode', 'base32', 'base85', 'ascii85', 'hex'])
    decode_parser.add_argument('data', nargs='?', type=str)
    decode_parser.set_defaults(func=decode_data)

    # Subparser for hashing
    hash_parser = subparsers.add_parser("hash", help="Hash data using a specified algorithm",
                                                description="Hash data using a specified algorithm such as MD5, SHA-1, SHA-256, or RIPEMD-160")
    hash_parser.add_argument('type', type=str, choices=['md5', 'sha1', 'sha256', 'ripemd160','blake2s', 'blake2b', 'sha3_512', 'sha3_256'], help='Type of hash')
    hash_parser.add_argument('data', nargs='?', type=str, help='Data to hash')
    hash_parser.set_defaults(func=hash_data)

    # Subparser for encryption
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt data')
    encrypt_parser.add_argument('data', type=str, help='Data to encrypt')
    encrypt_parser.add_argument('key', type=str, help='Encryption key')
    encrypt_parser.set_defaults(func=encrypt_data)

    # Subparser for decryption
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data')
    decrypt_parser.add_argument('iv', type=str, help='Initialization Vector')
    decrypt_parser.add_argument('data', type=str, help='Data to decrypt')
    decrypt_parser.add_argument('key', type=str, help='Decryption key')
    decrypt_parser.set_defaults(func=decrypt_data)


    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()