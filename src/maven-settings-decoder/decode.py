from __future__ import annotations

import argparse
import base64
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger

# Links:
# https://github.com/sonatype/plexus-cipher/blob/master/src/main/java/org/sonatype/plexus/components/cipher/PBECipher.java
# https://github.com/apache/maven/blob/master/impl/maven-cli/src/main/java/org/apache/maven/cling/invoker/mvnenc/goals/Encrypt.java#L45
# https://github.com/apache/maven/blob/2a6fc5ab6766d0a6837422a78bab3040c32a8d8d/compat/maven-settings-builder/src/main/java/org/apache/maven/settings/crypto/MavenSecDispatcher.java#L42


def get_password_from_curly_braces(pwd: str) -> bytes | str:
    """Extract and decode password from Maven's curly brace format."""
    if not pwd:
        return pwd
    if match := re.search(r".*?[^\\]?\{(.*?[^\\])}.*", pwd):
        return base64.b64decode(match.group(1))
    return pwd


def decrypt(encryptedText: bytes | str, password: str) -> str:
    if not isinstance(encryptedText, bytes):
        encryptedText = get_password_from_curly_braces(encryptedText)

    total_len = len(encryptedText)
    salt = encryptedText[:8]
    pad_len = encryptedText[8]
    encrypted_length = total_len - 8 - 1 - pad_len
    encrypted_bytes = encryptedText[9 : 9 + encrypted_length]

    key_and_iv = b""
    result = b""
    pwd_bytes = password.encode("utf-8")

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    while len(key_and_iv) < 32:  # TODO: what if I pass multiple times here?
        digest.update(pwd_bytes)
        if salt:
            digest.update(salt[:8])
        result = digest.finalize()
        key_and_iv += result

    key = key_and_iv[:16]
    iv = key_and_iv[16:32]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()
    clear_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = clear_bytes[-1]
    clear_bytes = clear_bytes[:-padding_length]

    return clear_bytes.decode("utf-8")


def read_settings_security(file_path: Path) -> str | None:
    """Read and extract master password from settings-security.xml."""
    if not file_path.exists():
        return None

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        master_elem = root.find(".//master")
        if master_elem is not None:
            return master_elem.text
    except Exception as e:
        raise ValueError(f"Failed to read settings-security.xml: {e!s}") from e

    return None


def read_settings(file_path: Path) -> list[dict]:
    """Read server credentials from settings.xml."""
    servers = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for server in root.findall(".//server"):
            server_data = {
                "id": server.find("id").text if server.find("id") is not None else "",
                "username": server.find("username").text if server.find("username") is not None else "",
                "password": server.find("password").text if server.find("password") is not None else "",
            }
            servers.append(server_data)

    except Exception as e:
        raise ValueError(f"Failed to read settings.xml: {e!s}") from e

    return servers


def print_passwords(settings_file: Path, security_file: Path):
    """Print decrypted server credentials."""
    try:
        master_password = read_settings_security(security_file)
        if master_password:
            logger.info(f"Master password (raw): {master_password}")
            if isinstance(master_password, bytes):
                logger.info(f"Master password length: {len(master_password)} bytes")

        servers = read_settings(settings_file)

        if not servers:
            logger.info("No servers found in settings.xml")
            return

        if master_password:
            decrypted = decrypt(master_password, "settings.security")
            logger.info(f"Decrypted master password: {decrypted}")

        for server in servers:
            if not server["password"]:
                decoded_password = ""
            elif master_password is None:
                decoded_password = server["password"]
            else:
                try:
                    logger.debug(f"Decrypting password for {server['id']}:")
                    logger.debug(f"Encrypted password: {server['password']}")

                    decoded_password = decrypt(server["password"], decrypted)

                    logger.debug("Decryption successful")
                except Exception as e:
                    decoded_password = f"<Error decrypting: {e!s}>"

            logger.info(f"Credentials for server {server['id']}:")
            logger.info(f"Username: {server['username']}")
            logger.info(f"Password: {decoded_password}")
            logger.info("-" * 73)

    except Exception as e:
        logger.info(f"Error processing files: {e!s}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt Maven settings.xml passwords")
    parser.add_argument("-s", "--settings-security", help="Path to settings-security.xml file", default=Path.home() / ".m2/settings-security.xml", type=Path)
    parser.add_argument("-f", "--settings", help="Path to settings.xml file", default=Path.home() / ".m2/settings.xml", type=Path)

    args = parser.parse_args()

    if not args.settings.exists():
        logger.error(f"settings.xml file not found at {args.settings}")
        return

    print_passwords(args.settings, args.settings_security)


if __name__ == "__main__":
    main()
