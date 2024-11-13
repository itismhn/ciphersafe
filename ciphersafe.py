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

def print_cipher_list(ciphers):
    # Print a list of cipher suites with their security status.
    cipher_list = []
    
    for cipher in ciphers:
        cipher_info = get_cipher_suite_info(cipher)
        
        if cipher_info:
            cipher_data = cipher_info.get(cipher, {})
            security_status = cipher_data.get('security', 'N/A')
            if security_status == 'secure' or security_status == 'recommended':
                security_fin = COLOR_GREEN + security_status + COLOR_RESET
            elif security_status == 'weak':
                security_fin = COLOR_YELLOW + security_status + COLOR_RESET
            else:
                security_fin = COLOR_RED + security_status + COLOR_RESET
            
            cipher_list.append(f"{COLOR_WHITE}{cipher}{COLOR_RESET} [{security_fin}]")
        else:
            cipher_list.append(f"{COLOR_RED}Failed to retrieve data for {cipher}{COLOR_RESET}")

    # Print the list of cipher suites with security status
    print("Cipher Suites and Security Status:")
    for cipher in cipher_list:
        print(cipher)

def print_cipher_details(ciphers):
    """Print detailed information for each cipher suite."""
    for cipher in ciphers:
        cipher_info = get_cipher_suite_info(cipher)
        
        if cipher_info:
            cipher_data = cipher_info.get(cipher, {})
            security_status = cipher_data.get('security', 'N/A')
            print(f"\n--------------------------------------------------")
            print(f"Suite: {COLOR_WHITE}{cipher}{COLOR_RESET}")
            print(f"Security: {COLOR_YELLOW}{security_status}{COLOR_RESET}")
            print(f"TLS Version: {COLOR_WHITE}{str(cipher_data.get('tls_version', 'N/A'))}{COLOR_RESET}")
            print(f"Hex Byte 1: {COLOR_WHITE}{str(cipher_data.get('hex_byte_1', 'N/A'))}{COLOR_RESET}")
            print(f"Hex Byte 2: {COLOR_WHITE}{str(cipher_data.get('hex_byte_2', 'N/A'))}{COLOR_RESET}")
            print(f"Protocol Version: {COLOR_WHITE}{str(cipher_data.get('protocol_version', 'N/A'))}{COLOR_RESET}")
            print(f"Key Exchange Algorithm: {COLOR_WHITE}{str(cipher_data.get('kex_algorithm', 'N/A'))}{COLOR_RESET}")
            print(f"Authentication Algorithm: {COLOR_WHITE}{str(cipher_data.get('auth_algorithm', 'N/A'))}{COLOR_RESET}")
            print(f"Encryption Algorithm: {COLOR_WHITE}{str(cipher_data.get('enc_algorithm', 'N/A'))}{COLOR_RESET}")
            print(f"Hash Algorithm: {COLOR_WHITE}{str(cipher_data.get('hash_algorithm', 'N/A'))}{COLOR_RESET}")
            print(f"--------------------------------------------------")
        else:
            print(f"{COLOR_RED}Failed to retrieve data for {cipher}{COLOR_RESET}")

if __name__ == "__main__":
    main()
