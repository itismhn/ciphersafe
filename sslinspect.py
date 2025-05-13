import ssl
import socket
import contextlib
import warnings
from typing import Any, Dict, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def extract_cert_extensions(certificate: x509.Certificate) -> Dict[str, Any]:
    extensions = {}
    for extension in certificate.extensions:
        extension_name = extension.oid._name if extension.oid._name else str(extension.oid)
        extensions[extension_name] = {
            "critical": extension.critical,
            "value": extension.value
        }
    return extensions

def detect_supported_ciphers(server_host: str, server_port: int) -> List[str]:
    candidate_ciphers = ssl.create_default_context().get_ciphers()
    compatible_ciphers = []

    for cipher_entry in candidate_ciphers:
        cipher_label = cipher_entry["name"]
        with contextlib.suppress(Exception):
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.set_ciphers(cipher_label)
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((server_host, server_port), timeout=2) as connection:
                with tls_context.wrap_socket(connection, server_hostname=server_host):
                    compatible_ciphers.append(cipher_label)

    return compatible_ciphers

def retrieve_cert_details(server_host: str, server_port: int) -> Dict[str, Any]:
    raw_cert = bytes(ssl.get_server_certificate((server_host, server_port)), "utf-8")
    parsed_cert = x509.load_pem_x509_certificate(raw_cert, default_backend())
    cert_details = {
        "version": parsed_cert.version.name,
        "serial_number": parsed_cert.serial_number,
        "validity_period": {
            "starts_on": str(parsed_cert.not_valid_before),
            "expires_on": str(parsed_cert.not_valid_after),
        },
        "issuer_info": {field.oid._name: field.value for field in parsed_cert.issuer},
        "fingerprint_hashes": {
            "SHA256": parsed_cert.fingerprint(hashes.SHA256()),
            "SHA1": parsed_cert.fingerprint(hashes.SHA1()),
        },
        "extension_data": extract_cert_extensions(parsed_cert),
        "cipher_suites": detect_supported_ciphers(server_host, server_port),
    }
    return cert_details