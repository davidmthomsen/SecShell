import argparse
import base64
import hashlib


def encode_data(data, encoding_type):
    # Function to handle data encoding
    if encoding_type == 'base64':
        encode_data = base64.b64encode(data.encode('utf-8')) # Encode strings to bytes
        print(encode_data.decode('utf-8')) # Decode bytes to string for display 
    else:
        print(f"Encoding type {encoding_type} is not implemented.")

def hash_data(data, hash_type):
    # Function to handle data hashing 
    if hash_type == 'sha256':
        hash_object = hashlib.sha256(data.encode('utf-8')) # Hashing requires encode bytes
        hex_dig = hash_object.hexdigest() # Get hexadecimal digest string
        print(hex_dig)
    else:
        print(f"Hash type {hash_type} not implemented.")
    pass

def main():
    parser = argparse.ArgumentParser(description="SecShell  - Security CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument('data', type=str, help='Data to encode')
    encode_parser.add_argument('type', type=str, choices=['base64'], help='Type of encoding.')
    encode_parser.set_defaults(func=encode_data)

    # Subarser for hashing 
    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument("type", choices=["md5", "sha1", "sha256"])
    hash_parser.add_argument("data")
    hash_parser.set_defaults(func=hash_data)

    # Add more subparsers as needed

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args.data, args.type)
    else:
        parser.print_help()

if __name__ == "__main__":
    args = parser.parse_args()
    if 'func' in args:
        args.func(args.data, args.type) # Call function passed by set_defaults
    else:
        parser.print_help()
    main()