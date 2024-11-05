from pathlib import Path

import pytest

from maven_settings_decoder import MavenDecodeError, MavenPasswordDecoder, MavenServer


def test_maven_server_dataclass():
    """Test MavenServer dataclass initialization and attributes."""
    server = MavenServer(id="test", username="user", password="pass", decrypted_password="decrypted")

    assert server.id == "test"
    assert server.username == "user"
    assert server.password == "pass"
    assert server.decrypted_password == "decrypted"


class TestMavenPasswordDecoder:
    """Test suite for MavenPasswordDecoder class."""

    def test_initialization(self, mock_settings_xml, mock_security_xml):
        """Test decoder initialization with custom paths."""
        decoder = MavenPasswordDecoder(settings_path=mock_settings_xml, security_path=mock_security_xml)

        assert decoder.settings_path == mock_settings_xml
        assert decoder.security_path == mock_security_xml

    def test_initialization_default_paths(self):
        """Test decoder initialization with default paths."""
        decoder = MavenPasswordDecoder(None, None)

        assert decoder.settings_path == Path.home() / ".m2/settings.xml"
        assert decoder.security_path == Path.home() / ".m2/settings-security.xml"

    def test_extract_password_empty(self):
        """Test password extraction with empty input."""
        decoder = MavenPasswordDecoder()
        assert decoder._extract_password("") is None

    def test_extract_password_plain(self):
        """Test password extraction with plain text."""
        decoder = MavenPasswordDecoder()
        assert decoder._extract_password("plaintext") == b"plaintext"

    def test_extract_password_encrypted(self):
        """Test password extraction with encrypted format."""
        decoder = MavenPasswordDecoder()
        result = decoder._extract_password("{COQLCE6DU6GtcS5P=}")
        assert result == b"\x08\xe4\x0b\x08N\x83S\xa1\xadq.O"

    def test_read_master_password_missing_file(self, temp_dir):
        """Test reading master password with missing security file."""
        decoder = MavenPasswordDecoder(security_path=temp_dir / "nonexistent.xml")
        assert decoder.get_master_password() is None

    def test_read_master_password_without_master_pass(self, temp_dir):
        """Test reading master password with missing security file."""
        newfile = temp_dir / "dummy.xml"
        newfile.write_text("<settingsSecurity />")

        decoder = MavenPasswordDecoder(security_path=newfile)
        assert decoder.get_master_password() is None

    def test_read_master_password_invalid_xml(self, temp_dir):
        """Test reading master password with invalid XML."""
        security_file = temp_dir / "invalid-security.xml"
        security_file.write_text("invalid xml content")

        decoder = MavenPasswordDecoder(security_path=security_file)

        with pytest.raises(MavenDecodeError):
            decoder.get_master_password()

    def test_read_master_password(self, mock_security_xml):
        """Test reading master password with invalid XML."""
        decoder = MavenPasswordDecoder(security_path=mock_security_xml)

        assert decoder.get_master_password() == "master"

    def test_read_servers_missing_file(self, temp_dir):
        """Test reading servers with missing settings file."""
        decoder = MavenPasswordDecoder(settings_path=temp_dir / "nonexistent.xml")

        with pytest.raises(MavenDecodeError):
            decoder.read_credentials()

    def test_read_servers_invalid_xml(self, temp_dir):
        """Test reading servers with invalid XML."""
        settings_file = temp_dir / "invalid-settings.xml"
        settings_file.write_text("invalid xml content")

        decoder = MavenPasswordDecoder(settings_path=settings_file)

        with pytest.raises(MavenDecodeError):
            decoder.read_credentials()

    def test_read_credentials_no_master_password(self, mock_settings_xml):
        """Test reading credentials without master password."""
        decoder = MavenPasswordDecoder(mock_settings_xml)
        servers = decoder.read_credentials()

        assert len(servers) == 3
        assert all(server.decrypted_password == server.password for server in servers)

    def test_read_credentials_with_master_password(self, decoder):
        """Test reading credentials with master password."""
        servers = decoder.read_credentials()

        assert len(servers) == 3
        # Add specific assertions based on your encryption implementation

    def test_empty_server_password(self, decoder):
        """Test handling of empty server passwords."""
        servers = decoder.read_credentials()
        empty_server = next(s for s in servers if s.id == "server3")
        assert empty_server.decrypted_password == ""


class TestCommandLine:
    """Test suite for command line interface."""

    def test_main_missing_settings(self, tmp_path):
        """Test main function with missing settings file."""
        from maven_settings_decoder.__main__ import main

        args = ["--settings", str(tmp_path / "nonexistent.xml")]
        assert main(args) == 1

    def test_main_successful(self, mock_settings_xml, mock_security_xml):
        """Test main function with valid files."""
        from maven_settings_decoder.__main__ import main

        args = ["--settings", str(mock_settings_xml), "--security", str(mock_security_xml)]
        assert main(args) == 0

    def test_main_verbose(self, mock_settings_xml, mock_security_xml):
        """Test main function with verbose option."""
        from maven_settings_decoder.__main__ import main

        args = ["--settings", str(mock_settings_xml), "--security", str(mock_security_xml), "-v"]
        assert main(args) == 0
