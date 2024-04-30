import requests

def main():
    print("""
   ___ _      _            ___        __     
  / __(_)_ __| |_  ___ _ _/ __| __ _ / _|___ 
 | (__| | '_ \ ' \/ -_) '_\__ \/ _` |  _/ -_)
  \___|_| .__/_||_\___|_| |___/\__,_|_| \___|
@itisMHN|_|V.1.1 https://github.com/itismhn/ciphersafe
    """)


# base URL of the API
base_url = "https://ciphersuite.info/api"

def get_cipher_suite(cipher_suite_name):
    # Endpoint for getting a TLS cipher suite by name
    endpoint = "/cs/{}".format(cipher_suite_name)
    url = base_url + endpoint
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        print(data)
    else:
        print("Failed to retrieve data. Status code:", response.status_code)

if __name__ == "__main__":
    main()