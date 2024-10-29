import argparse
import re
import xml.etree.ElementTree as ET
import base64
import hashlib
import os
from pathlib import Path
from pydoc import plaintext


def _get_password_from_curly_braces(pwd: str) -> bytes|str:
    if match := re.search(".*?[^\\\\]?\\{(.*?[^\\\\])}.*", pwd):
        return base64.b64decode(match.group(1))
    return pwd


import argparse
import base64
import hashlib
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets


def aesgcm_decrypt(ciphertext, password):
    material = _get_password_from_curly_braces(ciphertext)

    iv = material[:12]
    salt = material[12:28]
    ct = material[28:]

    key = pbkdf2_derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ct, None)
    return plaintext
    # cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    # decryptor = cipher.decryptor()
    # padded_data = decryptor.update(ct) + decryptor.finalize()
    # unpadder = padding.PKCS7(128).unpadder()
    # return unpadder.update(padded_data) + unpadder.finalize()


def pbkdf2_derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=310000,
        backend=default_backend()
    )
    return kdf.derive(password)

def read_settings_security(file_path: Path) -> str | bytes | None:
    # This function reads the settings-security.xml file
    if not file_path.exists():
        return None

    tree = ET.parse(file_path)
    root = tree.getroot()
    master_password = root.find('.//master').text
    return _get_password_from_curly_braces(master_password)


def read_settings(file_path: Path) -> list[dict]:
    # This function reads the settings.xml file
    tree = ET.parse(file_path)
    root = tree.getroot()
    servers = []
    for server in root.findall('.//server'):
        server_id = server.find('id').text
        username = server.find('username').text
        password = server.find('password').text
        servers.append({'id': server_id, 'username': username, 'password': password})
    return servers


def print_passwords(settings_file: Path, security_file: Path):
    # This function prints the decrypted passwords
    master_password = read_settings_security(security_file)
    servers = read_settings(settings_file)
    for server in servers:
        if master_password is None:
            decoded_password = server['password']
        else:
            decoded_password = aesgcm_decrypt(server['password'], master_password)

        print(f"Credentials for server {server['id']} are:")
        print(f"Username: {server['username']}")
        print(f"Password: {decoded_password}")
        print("-------------------------------------------------------------------------")

def main():
    parser = argparse.ArgumentParser(description='Decrypt Maven settings.xml passwords')
    parser.add_argument('-s', '--settings-security', help='Path to settings-security.xml file', default=Path.home() / '.m2/settings-security.xml', type=Path)
    parser.add_argument('-f', '--settings', help='Path to settings.xml file', default=Path.home() / '.m2/settings.xml', type=Path)
    args = parser.parse_args()
    if not args.settings.exists():
        print(f"Error: settings.xml file not found at {args.settings}")
        return
    print_passwords(args.settings, args.settings_security)

if __name__ == '__main__':
    main()
