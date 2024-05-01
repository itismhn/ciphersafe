import requests
import argparse

COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[93m"

def main():
    print("""
   ___ _      _            ___        __     
  / __(_)_ __| |_  ___ _ _/ __| __ _ / _|___ 
 | (__| | '_ \\ ' \\/ -_) '_\\__ \\/ _` |  _/ -_)
  \\___|_| .__/_||_\\___|_| |___/\\__,_|_| \\___|
@itisMHN|_|V.1.1 github.com/itismhn/ciphersafe
    """)
    # Create the argument parser
    parser = argparse.ArgumentParser(description="check information of tls cipher suites from the Ciphersuite.info API")
    parser.add_argument("-C", "--cipher", type=str, help="Get information about a specific cipher suite by name")
    args = parser.parse_args()
    if args.cipher:
        get_cipher_suite(args.cipher)
    else:
        print("Please provide an argument. Use -h or --help for more information.")


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
        print(COLOR_BOLD + "Cipher Suite:", cipher_suite_name + COLOR_RESET)
        print("Security:", end=" ")
        security_status = cipher_info.get('security', 'N/A')
        if security_status == 'secure':
            print(COLOR_GREEN + security_status + COLOR_RESET)
        elif security_status == 'weak':
            print(COLOR_YELLOW + security_status + COLOR_RESET)
        else:
            print(COLOR_RED + security_status + COLOR_RESET)
        print("TLS Version:", cipher_info.get('tls_version', 'N/A'))
        print("Hex Byte 1:", cipher_info.get('hex_byte_1', 'N/A'))
        print("Hex Byte 2:", cipher_info.get('hex_byte_2', 'N/A'))
        print("Protocol Version:", cipher_info.get('protocol_version', 'N/A'))
        print("Key Exchange Algorithm:", cipher_info.get('kex_algorithm', 'N/A'))
        print("Authentication Algorithm:", cipher_info.get('auth_algorithm', 'N/A'))
        print("Encryption Algorithm:", cipher_info.get('enc_algorithm', 'N/A'))
        print("Hash Algorithm:", cipher_info.get('hash_algorithm', 'N/A'))
        



    else:
        print("Failed to retrieve data. Status code:", response.status_code)

if __name__ == "__main__":
    main()