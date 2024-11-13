import requests
import argparse
import re

COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[93m"
COLOR_WHITE = "\033[1;37m"

def main():
    banner = """
   {}___ _      _            ___        __     
  / __(_)_ __| |_  ___ _ _/ __| __ _ / _|___ 
 | (__| | '_ \\ ' \\/ -_) '_\\__ \\/ _` |  _/ -_)
  \\___|_| .__/_||_\\___|_| |___/\\__,_|_| \\___|
{}@itisMHN{}|_|{}V.1.1 github.com/itismhn/ciphersafe{}
    """.format(COLOR_WHITE, COLOR_GREEN, COLOR_RESET, COLOR_GREEN, COLOR_RESET)
    print(banner)
    # Parse arguments
    parser = argparse.ArgumentParser(description="Process and get details for TLS cipher suites from Nmap output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed information")
    args = parser.parse_args()
    # Read input from stdin (piped data) or command-line arguments
    input_data = sys.stdin.read() if not sys.stdin.isatty() else ' '.join(sys.argv[1:])
    if not input_data:
        print("No input provided. Please provide Nmap output or cipher suite data.")
        sys.exit(1)
    # Extract cipher suites from the input data
    cipher_suites = extract_ciphers(input_data)
    else:
        print("No cipher suites found in the provided input.")

def extract_ciphers(input_data):
    # Extract cipher suites from input data using regex
    cipher_pattern = r"TLS_[A-Z0-9_]+"  # Regex to find TLS cipher suite names
    ciphers = re.findall(cipher_pattern, input_data)
    return set(ciphers)

# base URL of the API
base_url = "https://ciphersuite.info/api"

def get_cipher_suite(cipher_suite_name):
    # Endpoint for getting a TLS cipher suite by name
    endpoint = "/cs/{}".format(cipher_suite_name)
    url = base_url + endpoint
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        cipher_info = data[cipher_suite_name]
        print(COLOR_YELLOW + "Cipher Suite:" + COLOR_RESET, COLOR_WHITE + str(cipher_suite_name) + COLOR_RESET)
        print(COLOR_YELLOW + "Security:" + COLOR_RESET, end=" ")
        security_status = cipher_info.get('security', 'N/A')
        if security_status == 'secure' or security_status == 'recommended':
            print(COLOR_GREEN + security_status + COLOR_RESET)
        elif security_status == 'weak':
            print(COLOR_YELLOW + security_status + COLOR_RESET)
        else:
            print(COLOR_RED + security_status + COLOR_RESET)
        print(COLOR_YELLOW + "TLS Version:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('tls_version', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Hex Byte 1:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('hex_byte_1', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Hex Byte 2:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('hex_byte_2', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Protocol Version:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('protocol_version', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Key Exchange Algorithm:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('kex_algorithm', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Authentication Algorithm:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('auth_algorithm', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Encryption Algorithm:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('enc_algorithm', 'N/A')) + COLOR_RESET)
        print(COLOR_YELLOW + "Hash Algorithm:" + COLOR_RESET, COLOR_WHITE + str(cipher_info.get('hash_algorithm', 'N/A')) + COLOR_RESET)
        



    else:
        print("Failed to retrieve data. Status code:", response.status_code)

if __name__ == "__main__":
    main()
