import argparse
import base64
import hashlib
import urllib.parse


def encode_data(data, encoding_type):
    if encoding_type == 'base64':
        encoded_data = base64.b64encode(data.encode('utf-8'))  # Encode string to bytes
        print(encoded_data.decode('utf-8'))  # Decode bytes to string for display
    elif encoding_type == 'urlencode':
        encoded_data = urllib.parse.quote_plus(data)
        print(encoded_data)
    else:
        print(f"Encoding type {encoding_type} is not implemented.")

def hash_data(data, hash_type):
    data_bytes = data.encode('utf-8')

    # Function to handle data hashing 
    if hash_type == 'sha256':
        hash_object = hashlib.sha256(data.encode('utf-8')) # Hashing requires encode bytes
        hex_dig = hash_object.hexdigest() # Get hexadecimal digest string
        print(hex_dig)
    elif hash_type == 'md5':
        hash_object = hashlib.md5(data_bytes)
        print(hash_object.hexdigest())
    elif hash_type == 'sha1':
        hash_object = hashlib.sha1(data_bytes)
        print(hash_object.hexdigest())
    else:
        print(f"Hash type {hash_type} not implemented.")

def main():
    parser = argparse.ArgumentParser(
        description="SecShell - Security CLI Tool",
        epilog="Examples:\n"
               " python3 cli.py encode 'data' base64\n"
               " python3 cli.py hash 'data' sha256\n"
               " python3 cli.py encode 'https://example.com' urlencode\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser(
        "encode",
        help="Encode data in a specified format",
        description="Encode data in a specified format such as Base64 or URL encoding.",
        epilog="Examples:\n"
               "  python3 cli.py encode 'data' base64\n"
               "  python3 cli.py encode 'https://example.com' urlencode\n"
    )
    encode_parser.add_argument('data', type=str, help='Data to encode')
    encode_parser.add_argument('type', type=str, choices=['base64', 'urlencode'], help='Type of encoding')

    # Subparser for hashing
    hash_parser = subparsers.add_parser(
        "hash",
        help="Hash data using a specified algorithm",
        description="Hash data using a specified algorithm such as MD5, SHA-1, or SHA-256.",
        epilog="Examples:\n"
               "  python3 cli.py hash 'data' md5\n"
               "  python3 cli.py hash 'data' sha1\n"
               "  python3 cli.py hash 'data' sha256\n"
    )
    hash_parser.add_argument('data', type=str, help='Data to hash')
    hash_parser.add_argument('type', type=str, choices=['md5', 'sha1', 'sha256'], help='Type of hash')

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args.data, args.type)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()