import requests
import argparse
def main():
    print("""
   ___ _      _            ___        __     
  / __(_)_ __| |_  ___ _ _/ __| __ _ / _|___ 
 | (__| | '_ \ ' \/ -_) '_\__ \/ _` |  _/ -_)
  \___|_| .__/_||_\___|_| |___/\__,_|_| \___|
@itisMHN|_|V.1.1 https://github.com/itismhn/ciphersafe
    """)
    get_cipher_suite(cipher_suite_name)


# base URL of the API
base_url = "https://ciphersuite.info/api"


if __name__ == "__main__":
    main()