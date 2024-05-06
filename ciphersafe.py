import requests
import argparse

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
    # Create the argument parser
    parser = argparse.ArgumentParser(description="check information of tls cipher suites from the Ciphersuite.info API")
    parser.add_argument("-C", "--cipher", type=str, help="Get information about a specific cipher suite by name")
    parser.add_argument("-L", "--list", type=str, help="Import a file containing a list of all ciphers")
    args = parser.parse_args()
    if args.cipher:
        get_cipher_suite(args.cipher)
    elif args.list:
        list_cipher_suites(args.list)
    else:
        print("Please provide an argument. Use -h or --help for more information.")


# base URL of the API
base_url = "https://ciphersuite.info/api"
def list_cipher_suites(file_path):
    with open(file_path, 'r') as file:
        ciphers = file.readlines()

    for cipher in ciphers:
        cipher = cipher.strip()
        endpoint = "/cs/{}".format(cipher)
        url = base_url + endpoint
        # Send a GET request to the API
        response = requests.get(url)
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            cipher_info = data[cipher]
            security_status = cipher_info.get('security', 'N/A')
            if security_status == 'secure':
                security_fin = COLOR_GREEN + security_status + COLOR_RESET
            elif security_status == 'weak':
                security_fin = COLOR_YELLOW + security_status + COLOR_RESET
            else:
                security_fin = COLOR_RED + security_status + COLOR_RESET
            print(COLOR_YELLOW + COLOR_RESET, COLOR_WHITE + str(cipher) + COLOR_RESET + " [" + security_fin + "]")
        else:
            print(f"[ {cipher} Not Found ]")
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
        if security_status == 'secure':
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