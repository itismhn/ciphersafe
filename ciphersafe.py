import requests
import argparse
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
        print("Cipher Suite:", cipher_suite_name)
        print("Security:", cipher_info['security'])
        print("TLS Version:", cipher_info['tls_version'])
        print("Hex Byte 1:", cipher_info['hex_byte_1'])
        print("Hex Byte 2:", cipher_info['hex_byte_2'])
        print("Protocol Version:", cipher_info['protocol_version'])
        print("Key Exchange Algorithm:", cipher_info['kex_algorithm'])
        print("Authentication Algorithm:", cipher_info['auth_algorithm'])
        print("Encryption Algorithm:", cipher_info['enc_algorithm'])
        print("Hash Algorithm:", cipher_info['hash_algorithm'])



    else:
        print("Failed to retrieve data. Status code:", response.status_code)

if __name__ == "__main__":
    main()
