<p align="center">
  <img src="images/ciphersafe.jpg" />
</p>

# CipherSafe
CipherSafe is a Python script to check information about TLS cipher suites.
CipherSafe is a Python script designed to assist with security testing by providing information about TLS cipher suites. It leverages the Ciphersuite.info API to retrieve detailed data about specific cipher suites commonly used in secure communication protocols like HTTPS.

## Features

- Retrieve detailed information about TLS cipher suites, including their security status, supported TLS versions, key exchange algorithms, authentication algorithms, encryption algorithms, and hash algorithms.
- Helps security professionals understand the security posture of web applications and services by analyzing the cipher suites they support.
- Useful during penetration testing engagements to assess the cryptographic configuration of web servers and identify potential vulnerabilities.
- Aligns with the WSTG-CRYP-01 testing criteria from the OWASP Web Security Testing Guide, which focuses on cryptography-related security testing.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your_username/ciphersafe.git
    ```

2. Navigate to the `ciphersafe` directory:

    ```bash
    cd ciphersafe
    ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

#### Specific Cipher Suite

The `Cipher` option allows you to retrieve the security status of a specific cipher suite.

To use this option, run the script and provide the cipher suite name as an argument:

```bash
python ciphersafe.py -C <cipher_suite_name>
```
#### List of Cipher Suites

The list option enables you to import a file containing a list of cipher suites and retrieve the `security` status for each one.

To utilize this option, execute the following command:

```bash
python script.py -L <file_path>
```
##### Example

Suppose you have a file named `cipher_list.txt` containing a list of cipher suites:
```
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```
You can use the list option to fetch information about each cipher suite listed in the file:

```bash
python script.py -L cipher_list.txt
```
This command will retrieve and display the security status of each cipher suite listed in cipher_list.txt.