import argparse

def encode_data(data, encoding_type):
    # Function to handle data encoding
    pass

def hash_data(data, hash_type):
    # Function to handle data hashing 
    pass

def main():
    parser = argparse.ArgumentParser(description="SecShell  - Security CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for encoding
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument("type", choices=["base64", "hex", "url"])
    encode_parser.add_argument("data")
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
    main()