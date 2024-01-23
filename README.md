 ```
  __           __ _          _ _ 
/ _\ ___  ___/ _\ |__   ___| | |
\ \ / _ \/ __\ \| '_ \ / _ \ | |
_\ \  __/ (___\ \ | | |  __/ | |
\__/\___|\___\__/_| |_|\___|_|_|
```
## Overview
SecShell is a command-line interface (CLI) tool designed for security professionals and enthusiasts. It brings together a suite of security-focused utilities, making it easier to perform a wide range of tasks including encoding/decoding, hashing, encryption, and more. Inspired by the versatility of CyberChef, SecShell aims to provide a similar experience in a CLI environment, catering to the needs of penetration testers, security researchers, and system administrators.

## Features
- **Encoding/Decoding**: Support for Base64, Hex, URL encoding, and more.
- **Hashing**: Generate and verify hashes using algorithms like MD5, SHA-1, SHA-256, RIPEMD-160, and Whirlpool.
- **Encryption/Decryption**: Perform symmetric encryption with algorithms like AES.
- **File Integrity Check**: Compute and validate file checksums.
- **Data Inspection**: Tools for analyzing and inspecting strings, including regex search.
- **Extensible Framework**: Easily extendable to integrate additional tools and functionalities.
- **File Input Support**: Process data directly from files for encoding, decoding, and hashing operations.
- **Standard Input Support**: Accept data piped from standard input (stdin) for flexible integration with other command-line tools.

## Installation
1. Clone the repository: `git clone https://github.com/davidmthomsen/SecShell.git`
2. Navigate to the SecShell directory: `cd SecShell`
3. Install dependencies: `pip install -r requirements.txt` *(if applicable)*
4. Run the tool: `python cli.py`

## Usage
- To encode a string in Base64: `python cli.py encode base64 "SecGPT"`
- To compute an SHA-256 hash of a string: `python cli.py hash sha256 "example"`
- To encode a string in Hex: `python cli.py encode hex "example"`
- To decode a Base64 encoded string: `python cli.py decode base64 "encodedString"`
- To hash using RIPEMD-160: `python cli.py hash ripemd160 "example"`

## Contributing
We welcome contributions from the community! If you have suggestions or improvements, feel free to fork the repository and submit a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.