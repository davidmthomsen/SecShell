import argparse
import base64
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
    else:
        print(f"Encoding type {args.type} is not implemented.")

def decode_data(args):
    data = args.data or read_data(args.file) if args.file else sys.stdin.read().strip()

    if args.type == 'base64':
        decoded_data = base64.b64decode(data).decode('utf-8')
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

def main():
    parser = argparse.ArgumentParser(description="SecShell - Security CLI Tool")
    parser.add_argument('-f', '--file', type=str, help='Path to a file containing data')
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser("encode", help="Encode data in a specified format")
    encode_parser.add_argument('type', type=str, choices=['base64', 'urlencode'])
    encode_parser.add_argument('data', nargs='?', type=str)
    encode_parser.set_defaults(func=encode_data)

    # Subparser for decoding
    decode_parser = subparsers.add_parser("decode", help="Decode data in a specified format")
    decode_parser.add_argument('type', type=str, choices=['base64', 'urlencode'])
    decode_parser.add_argument('data', nargs='?', type=str)
    decode_parser.set_defaults(func=decode_data)

    # Subparser for hashing
    hash_parser = subparsers.add_parser("hash", help="Hash data using a specified algorithm",
                                                description="Hash data using a specified algorithm such as MD5, SHA-1, SHA-256, or RIPEMD-160")
    hash_parser.add_argument('type', type=str, choices=['md5', 'sha1', 'sha256', 'ripemd160','blake2s', 'blake2b', 'sha3_512', 'sha3_256'], help='Type of hash')
    hash_parser.add_argument('data', nargs='?', type=str, help='Data to hash')
    hash_parser.set_defaults(func=hash_data)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()