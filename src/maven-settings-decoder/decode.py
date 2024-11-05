from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ['MavenServer', 'MavenPasswordDecoder', 'MavenDecodeError']


@dataclass
class MavenServer:
    """
    Represents credentials for a Maven server.

    Attributes:
        id (str): Server identifier
        username (str): Username for authentication
        password (str): Encrypted or plain password
        decrypted_password (Optional[str]): Decrypted password if available
    """
    id: str
    username: str
    password: str
    decrypted_password: Optional[str] = None


class MavenDecodeError(ValueError):
    """Raised when there's an error during Maven password decoding operations."""
    pass


class MavenPasswordDecoder:
    """
    A class to handle decryption of passwords in Maven settings files.

    This class implements the Maven password encryption scheme used in settings.xml
    and settings-security.xml files. It supports both master password decryption
    and server password decryption.

    Example:
        >>> decoder = MavenPasswordDecoder()
        >>> servers = decoder.read_credentials()
        >>> for server in servers:
        ...     print(f"Server {server.id}: {server.decrypted_password}")
    """

    MASTER_PASSWORD_KEY = "settings.security"

    def __init__(
            self,
            settings_path: Path | str | None = None,
            security_path: Path | str | None = None
    ):
        """
        Initialize the decoder with paths to Maven settings files.

        Args:
            settings_path: Path to settings.xml (defaults to ~/.m2/settings.xml)
            security_path: Path to settings-security.xml (defaults to ~/.m2/settings-security.xml)
        """
        self.settings_path = Path(settings_path or Path.home() / ".m2/settings.xml")
        self.security_path = Path(security_path or Path.home() / ".m2/settings-security.xml")
        self._master_password: Optional[str] = None

    @staticmethod
    def _extract_password(pwd: str) -> bytes | str:
        """
        Extract and decode password from Maven's curly brace format.

        Args:
            pwd: Encoded password string potentially wrapped in curly braces

        Returns:
            Decoded password bytes or original string if no encoding detected
        """
        if not pwd:
            return pwd
        if match := re.search(r".*?[^\\]?\{(.*?[^\\])}.*", pwd):
            pwd = base64.b64decode(match.group(1))
        if isinstance(pwd, bytes):
            return pwd
        return pwd.encode('utf8')

    def _decrypt(self, encrypted_text: bytes | str, password: str) -> str:
        """
        Decrypt Maven encrypted text using the provided password.

        Args:
            encrypted_text: The encrypted text to decrypt
            password: Password to use for decryption

        Returns:
            Decrypted string

        Raises:
            MavenDecodeError: If decryption fails
        """
        try:
            if not isinstance(encrypted_text, bytes):
                encrypted_text = self._extract_password(encrypted_text)

            # Parse the encrypted data structure
            total_len = len(encrypted_text)
            salt = encrypted_text[:8]
            pad_len = encrypted_text[8]
            encrypted_length = total_len - 8 - 1 - pad_len
            encrypted_bytes = encrypted_text[9:9 + encrypted_length]

            # Generate key and IV
            key_and_iv = b""
            pwd_bytes = self._extract_password(password)

            while len(key_and_iv) < 32:
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(pwd_bytes)
                if salt:
                    digest.update(salt[:8])
                key_and_iv += digest.finalize()

            key = key_and_iv[:16]
            iv = key_and_iv[16:32]

            # Decrypt using AES-CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            clear_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_length = clear_bytes[-1]
            clear_bytes = clear_bytes[:-padding_length]

            return clear_bytes.decode("utf-8")

        except Exception as e:
            raise MavenDecodeError(f"Failed to decrypt: {str(e)}") from e

    def _read_servers(self) -> List[MavenServer]:
        """
        Read server credentials from settings.xml.

        Returns:
            List of MavenServer objects

        Raises:
            MavenDecodeError: If reading or parsing the settings file fails
        """
        try:
            tree = ET.parse(self.settings_path)
            root = tree.getroot()
            servers = []

            for server in root.findall(".//server"):
                server_data = MavenServer(
                    id=server.find("id").text if server.find("id") is not None else "",
                    username=server.find("username").text if server.find("username") is not None else "",
                    password=server.find("password").text if server.find("password") is not None else "",
                )
                servers.append(server_data)

            return servers

        except Exception as e:
            raise MavenDecodeError(f"Failed to read settings.xml: {str(e)}") from e

    def read_credentials(self) -> List[MavenServer]:
        """
        Read and decrypt all server credentials from Maven settings files.

        This method reads both the settings.xml and settings-security.xml files,
        decrypts the passwords using the master password if available, and returns
        a list of server credentials.

        Returns:
            List of MavenServer objects with decrypted passwords

        Raises:
            MavenDecodeError: If reading or decrypting fails
        """
        if not self.settings_path.exists():
            raise MavenDecodeError(f"settings.xml not found at {self.settings_path}")

        # Get master password if available
        self._master_password = self.get_master_password()

        # Read and decrypt server credentials
        servers = self._read_servers()

        for server in servers:
            if not server.password:
                server.decrypted_password = ""
            elif self._master_password is None:
                server.decrypted_password = server.password
            else:
                try:
                    server.decrypted_password = self._decrypt(
                        server.password,
                        self._master_password
                    )
                except Exception as e:
                    server.decrypted_password = f"<Error decrypting: {str(e)}>"

        return servers

    def get_raw_master_password(self) -> Optional[str]:
        """
        Get the encrypted master password from settings-security.xml.

        Returns:
            The encrypted master password string or None if not found

        Raises:
            MavenDecodeError: If reading the security file fails
        """

        if not self.security_path.exists():
            return None

        try:
            tree = ET.parse(self.security_path)
            root = tree.getroot()
            master_elem = root.find(".//master")

            if master_elem is not None and master_elem.text:
                return master_elem.text

        except Exception as e:
            raise MavenDecodeError(f"Failed to read settings-security.xml: {str(e)}") from e

        return None

    def get_master_password(self) -> Optional[str]:
        """
        Get the decrypted master password.

        Returns:
            The decrypted master password or None if not found

        Raises:
            MavenDecodeError: If decryption fails
        """
        raw_master = self.get_raw_master_password()
        if raw_master:
            return self._decrypt(raw_master, self.MASTER_PASSWORD_KEY)
        return None
