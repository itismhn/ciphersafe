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

def get_certificate_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    ext_dict = {}
    for ext in cert.extensions:
        ext_name = ext.oid._name if ext.oid._name else str(ext.oid)
        ext_dict[ext_name] = {"critical": ext.critical, "value": ext.value}
    return ext_dict

def get_supported_ciphers(host: str, port: int) -> List[str]:
    available_ciphers = ssl.create_default_context().get_ciphers()
    supported_ciphers = []

    for cipher in available_ciphers:
        cipher_name = cipher["name"]
        with contextlib.suppress(Exception):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers(cipher_name)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported_ciphers.append(cipher_name)

    return supported_ciphers
def get_certificate_info(host: str, port: int) -> Dict[str, Any]:
    pem_data = bytes(ssl.get_server_certificate((host, port)), "utf-8")
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    cert_info = {
        "version": cert.version.name,
        "serial": cert.serial_number,
        "validity": {
            "not_valid_before": str(cert.not_valid_before),
            "not_valid_after": str(cert.not_valid_after),
        },
        "issuer": {attr.oid._name: attr.value for attr in cert.issuer},
        "fingerprints": {
            "SHA256": cert.fingerprint(hashes.SHA256()),
            "SHA1": cert.fingerprint(hashes.SHA1()),
        },
        "extensions": get_certificate_extensions(cert),
        "ciphers": get_supported_ciphers(host, port),
    }
    return cert_info