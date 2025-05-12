import requests
import argparse
import re
import sys
from sslinspect import get_certificate_info

COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[93m"
COLOR_WHITE = "\033[1;37m"

# base URL of the API
base_url = "https://ciphersuite.info/api"

def main():
    banner = """
   {}___ _      _            ___        __     
  / __(_)_ __| |_  ___ _ _/ __| __ _ / _|___ 
 | (__| | '_ \\ ' \\/ -_) '_\\__ \\/ _` |  _/ -_)
  \\___|_| .__/_||_\\___|_| |___/\\__,_|_| \\___|
{}@itisMHN{}|_|{}V.2.0 github.com/itismhn/ciphersafe{}
    """.format(COLOR_WHITE, COLOR_GREEN, COLOR_RESET, COLOR_GREEN, COLOR_RESET)
    print(banner)

    # Parse arguments
    parser = argparse.ArgumentParser(description="Process and get details for TLS cipher suites from any output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed information")
    parser.add_argument("-c", "--cipher", help="Query information for a single cipher suite")
    parser.add_argument("-l", "--list", help="Query information for a comma-separated list of cipher suites")
    parser.add_argument("-u", "--url", help="Do SSL Inspect on a url")

    args = parser.parse_args()

    # Handle -u for ssl inspection
    if args.url:
        url = args.url.strip()
        port=443
        cert_data = get_certificate_info(url, port)
        print("\n=== Certificate Information ===")
        for key, value in cert_data.items():
            if key == "ciphers":
                print("\nSupported Ciphers:")
                for cipher in value:
                    print(f"- {cipher}")
            else:
                pass
    # Handle -c for a single cipher
    if args.cipher:
        cipher = args.cipher.strip()
        if args.verbose:
            print_cipher_details([cipher])
        else:
            print_cipher_list([cipher])
    return

    # Handle -l for a list of ciphers
    if args.list:
        try:
            with open(args.list, 'r') as file:
                cipher_suites = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{COLOR_RED}Error reading file: {e}{COLOR_RESET}")
            sys.exit(1)

        if cipher_suites:
            print_cipher_list(cipher_suites)
            if args.verbose:
                print_cipher_details(cipher_suites)
        else:
            print(f"{COLOR_RED}No valid cipher suites found in the file.{COLOR_RESET}")
    else:
        print("No input provided. Please provide Nmap output, a cipher name with -C, or a list with -l.")
        sys.exit(1)

    # Otherwise, read input from stdin (piped data) or command-line arguments
    input_data = sys.stdin.read() if not sys.stdin.isatty() else ' '.join(sys.argv[1:])
    if not input_data:
        print("No input provided. Please provide Nmap output or cipher suite data.")
        sys.exit(1)

    # Extract cipher suites from the input data
    cipher_suites = extract_ciphers(input_data)
    if cipher_suites:
        print_cipher_list(cipher_suites)
        if args.verbose:
            print_cipher_details(cipher_suites)
    else:
        print("No cipher suites found in the provided input.")

def extract_ciphers(input_data):
    # Extract cipher suites from input data using regex
    cipher_pattern = r"TLS_[A-Z0-9_]+"
    ciphers = re.findall(cipher_pattern, input_data)
    return set(ciphers)

def print_cipher_list(ciphers):
    cipher_list = []
    for cipher in ciphers:
        original_cipher = cipher.strip()

        # Try without TLS_ prefix
        cipher_info = get_cipher_suite_info(original_cipher)

        # If not found, try with TLS_ prefix
        if cipher_info is None and not original_cipher.startswith("TLS_"):
            prefixed_cipher = "TLS_" + original_cipher
            cipher_info = get_cipher_suite_info(prefixed_cipher)
            cipher_to_display = prefixed_cipher if cipher_info else original_cipher
        else:
            cipher_to_display = original_cipher

        if cipher_info:
            cipher_data = cipher_info.get(cipher_to_display, {})
            security_status = cipher_data.get('security', 'N/A')

            if security_status in ('secure', 'recommended'):
                security_fin = COLOR_GREEN + security_status + COLOR_RESET
            elif security_status == 'weak':
                security_fin = COLOR_YELLOW + security_status + COLOR_RESET
            else:
                security_fin = COLOR_RED + security_status + COLOR_RESET

            cipher_list.append(f"{COLOR_WHITE}{cipher_to_display}{COLOR_RESET} [{security_fin}]")
        else:
            cipher_list.append(f"{COLOR_RED}Failed to retrieve data for {original_cipher}{COLOR_RESET}")

    print("Cipher Suites and Security Status:")
    for line in cipher_list:
        print(line)

def print_cipher_details(ciphers):
    for cipher in ciphers:
        cipher_info = get_cipher_suite_info(cipher)
        if cipher_info:
            cipher_data = cipher_info.get(cipher, {})
            print(f"Suite: {COLOR_WHITE}{cipher}{COLOR_RESET}")
            print(f"Security: {COLOR_YELLOW}{cipher_data.get('security', 'N/A')}{COLOR_RESET}")
            print(f"TLS Version: {COLOR_WHITE}{cipher_data.get('tls_version', 'N/A')}{COLOR_RESET}")
            print(f"Hex Byte 1: {COLOR_WHITE}{cipher_data.get('hex_byte_1', 'N/A')}{COLOR_RESET}")
            print(f"Hex Byte 2: {COLOR_WHITE}{cipher_data.get('hex_byte_2', 'N/A')}{COLOR_RESET}")
            print(f"Protocol Version: {COLOR_WHITE}{cipher_data.get('protocol_version', 'N/A')}{COLOR_RESET}")
            print(f"Key Exchange Algorithm: {COLOR_WHITE}{cipher_data.get('kex_algorithm', 'N/A')}{COLOR_RESET}")
            print(f"Authentication Algorithm: {COLOR_WHITE}{cipher_data.get('auth_algorithm', 'N/A')}{COLOR_RESET}")
            print(f"Encryption Algorithm: {COLOR_WHITE}{cipher_data.get('enc_algorithm', 'N/A')}{COLOR_RESET}")
            print(f"Hash Algorithm: {COLOR_WHITE}{cipher_data.get('hash_algorithm', 'N/A')}{COLOR_RESET}")
            print(f"--------------------------------------------------")
        else:
            print(f"{COLOR_RED}Failed to retrieve data for {cipher}{COLOR_RESET}")

def get_cipher_suite_info(cipher_suite_name):
    endpoint = f"/cs/{cipher_suite_name}"
    url = base_url + endpoint
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass
    return None

if __name__ == "__main__":
    main()