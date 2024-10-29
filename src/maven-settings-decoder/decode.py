import argparse
import re
import xml.etree.ElementTree as ET
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# Links:
# https://github.com/codehaus-plexus/plexus-sec-dispatcher/blob/master/src/main/java/org/codehaus/plexus/components/secdispatcher/internal/cipher/AESGCMNoPadding.java
# https://github.com/codehaus-plexus/plexus-cipher/blob/f6bf735f66ee75038cdc2365f83b239fbd46cc14/src/main/java/org/codehaus/plexus/components/cipher/internal/AESGCMNoPadding.java
# https://github.com/apache/maven/blob/master/impl/maven-cli/src/main/java/org/apache/maven/cling/invoker/mvnenc/goals/Encrypt.java#L45
# https://github.com/apache/maven/blob/2a6fc5ab6766d0a6837422a78bab3040c32a8d8d/compat/maven-settings-builder/src/main/java/org/apache/maven/settings/crypto/MavenSecDispatcher.java#L42

def get_password_from_curly_braces(pwd: str) -> bytes | str:
    """Extract and decode password from Maven's curly brace format."""
    if not pwd:
        return pwd
    if match := re.search(r".*?[^\\]?\{(.*?[^\\])}.*", pwd):
        return base64.b64decode(match.group(1))
    return pwd


def pbkdf2_derive_key(password: bytes | str, salt: bytes) -> bytes:
    """Derive AES key using PBKDF2 with Maven's parameters."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=310000,
        backend=default_backend()
    )
    if isinstance(password, str):
        password = password.encode()
    return kdf.derive(password)


def aesgcm_decrypt(ciphertext: str, password: bytes | str) -> str:
    """Decrypt password using AES-GCM with Maven's format."""
    material = get_password_from_curly_braces(ciphertext)
    if isinstance(material, str):
        return material

    try:
        # Extract components:
        # First 12 bytes: IV (nonce)
        # Next 16 bytes: Salt
        # Last 16 bytes: Authentication tag
        # Rest: Actual ciphertext
        iv = material[:12]
        salt = material[12:28]
        
        # The actual ciphertext is between the salt and the auth tag
        ciphertext_with_tag = material[28:]
        
        # Derive key
        key = pbkdf2_derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        try:
            # Let AESGCM handle the authentication tag automatically
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
            return plaintext.decode('utf-8')
        except InvalidTag:
            # If that fails, try alternative tag placement
            # Some versions might append the tag at the end
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            # Manual verification might be needed here
            # This is a simplified version - you might need to adjust based on
            # your specific Maven version's behavior
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return plaintext.decode('utf-8')
            
    except Exception as e:
        raise ValueError(f"Failed to decrypt password: {str(e)}")


def read_settings_security(file_path: Path) -> bytes | str | None:
    """Read and extract master password from settings-security.xml."""
    if not file_path.exists():
        return None

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        master_elem = root.find('.//master')
        if master_elem is not None:
            return get_password_from_curly_braces(master_elem.text)
        return None
    except Exception as e:
        raise ValueError(f"Failed to read settings-security.xml: {str(e)}")


def read_settings(file_path: Path) -> list[dict]:
    """Read server credentials from settings.xml."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        servers = []
        
        for server in root.findall('.//server'):
            server_data = {
                'id': server.find('id').text if server.find('id') is not None else '',
                'username': server.find('username').text if server.find('username') is not None else '',
                'password': server.find('password').text if server.find('password') is not None else ''
            }
            servers.append(server_data)
        
        return servers
    except Exception as e:
        raise ValueError(f"Failed to read settings.xml: {str(e)}")


def print_passwords(settings_file: Path, security_file: Path, debug: bool = False):
    """Print decrypted server credentials."""
    try:
        master_password = read_settings_security(security_file)
        if debug and master_password:
            print(f"Master password (raw): {master_password}")
            if isinstance(master_password, bytes):
                print(f"Master password length: {len(master_password)} bytes")
        
        servers = read_settings(settings_file)
        
        if not servers:
            print("No servers found in settings.xml")
            return

        for server in servers:
            if not server['password']:
                decoded_password = ''
            elif master_password is None:
                decoded_password = server['password']
            else:
                try:
                    if debug:
                        print(f"\nDecrypting password for {server['id']}:")
                        print(f"Encrypted password: {server['password']}")
                    
                    decoded_password = aesgcm_decrypt(server['password'], master_password)
                    
                    if debug:
                        print(f"Decryption successful")
                except Exception as e:
                    decoded_password = f"<Error decrypting: {str(e)}>"
            
            print(f"\nCredentials for server {server['id']}:")
            print(f"Username: {server['username']}")
            print(f"Password: {decoded_password}")
            print("-" * 73)

    except Exception as e:
        print(f"Error processing files: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Decrypt Maven settings.xml passwords')
    parser.add_argument(
        '-s', '--settings-security',
        help='Path to settings-security.xml file',
        default=Path.home() / '.m2/settings-security.xml',
        type=Path
    )
    parser.add_argument(
        '-f', '--settings',
        help='Path to settings.xml file',
        default=Path.home() / '.m2/settings.xml',
        type=Path
    )
    parser.add_argument(
        '--decrypt',
        help='Decrypt a specific password using the master password'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )

    args = parser.parse_args()

    if args.decrypt:
        try:
            master_password = read_settings_security(args.settings_security)
            if not master_password:
                print("Error: Master password not found")
                return
            decrypted = aesgcm_decrypt(args.decrypt, master_password)
            print(f"Decrypted password: {decrypted}")
            return
        except Exception as e:
            print(f"Error decrypting password: {str(e)}")
            return

    if not args.settings.exists():
        print(f"Error: settings.xml file not found at {args.settings}")
        return

    print_passwords(args.settings, args.settings_security, args.debug)


if __name__ == '__main__':
    main()
