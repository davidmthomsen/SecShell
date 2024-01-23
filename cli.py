import argparse
import base64
import hashlib
import urllib.parse
import sys

def read_data(args):
    if args.file:
        with open(args.file, 'r') as file:
            return file.read().strip()
    elif args.data:
        return args.data
    else:
        return sys.stdin.read().strip() # Read from stdin if no other data source

def encode_data(data, encoding_type):
    data = read_data(data)

    if encoding_type == 'base64':
        encoded_data = base64.b64encode(data.encode('utf-8'))  # Encode string to bytes
        print(encoded_data.decode('utf-8'))  # Decode bytes to string for display
    elif encoding_type == 'urlencode':
        encoded_data = urllib.parse.quote_plus(data)
        print(encoded_data)
    else:
        print(f"Encoding type {encoding_type} is not implemented.")

def decode_data(data, decoding_type):
    data = read_data(data)

    if decoding_type == 'base64':
        decoded_data = base64.b64decode(data).decode('utf-8')
        print(decoded_data)
    elif decoding_type == 'urlencode':
        decoded_data = urllib.parse.unquote_plus(data)
        print(decoded_data)
    else:
        print(f"Decoding type {decoding_type} is not implemented.")

def hash_data(data, hash_type):
    data_bytes = data.encode('utf-8')
    data = read_data(data)
    
    # Function to handle data hashing 
    if hash_type == 'sha256':
        hash_object = hashlib.sha256(data_bytes) # Hashing requires encode bytes
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
               " python3 cli.py encode base64 'data'\n"
               " python3 cli.py hash sha256 'data'\n"
               " python3 cli.py encode urlencode 'https://example.com'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-f', '--file', type=str, help='Path to a file containing data')
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser(
        "encode",
        help="Encode data in a specified format",
        description="Encode data in a specified format such as Base64 or URL encoding.",
        epilog="Examples:\n"
               "  python3 cli.py encode base64 'data'\n"
               "  python3 cli.py encode urlencode 'https%3A%2F%2Fexample%2Ecom'\n"
    )
    encode_parser.add_argument('type', type=str, choices=['base64', 'urlencode'], help='Type of encoding')
    encode_parser.add_argument('data', nargs='?', type=str, help='Data to encode')
    encode_parser.set_defaults(func=encode_data)

    # Subparser for decoding
    decode_parser = subparsers.add_parser(
        "decode",
        help="Decoding data in a specified format",
        description="Decode data in a specified format such as Base64 or URL encoding.",
        epilog="Examples:\n"
        "  python3 cli.py decode base64 'data'\n"
        "  python3 cli.py decode urlencode 'https%3A%2F%2Fexample%2Ecom'"
    )
    decode_parser.add_argument('type', type=str, choices=['base64', 'urlencode'], help='Type of encoding to decode')
    decode_parser.add_argument('data', nargs='?', type=str, help='Data to decode')
    decode_parser.set_defaults(func=decode_data)

    # Subparser for hashing
    hash_parser = subparsers.add_parser(
        "hash",
        help="Hash data using a specified algorithm",
        description="Hash data using a specified algorithm such as MD5, SHA-1, or SHA-256.",
        epilog="Examples:\n"
               "  python3 cli.py hash md5 'data'\n"
               "  python3 cli.py hash sha1 'data'\n"
               "  python3 cli.py hash sha256 'data'\n"
    )
    hash_parser.add_argument('type', type=str, choices=['md5', 'sha1', 'sha256'], help='Type of hash')
    hash_parser.add_argument('data', nargs='?', type=str, help='Data to hash')
    hash_parser.set_defaults(func=hash_data)

    args = parser.parse_args()
    if not sys.stdin.isatty(): # Check if data is being piped into stdin
        input_data = sys.stdin.read().strip()
        args.data = input_data  # Use data from stdin

    if hasattr(args, 'func'):
        args.func(args.data, args.type)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()