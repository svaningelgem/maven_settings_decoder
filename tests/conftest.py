import tempfile
from pathlib import Path

import pytest

from maven_settings_decoder import (
    MavenPasswordDecoder
)


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as an integration test"
    )


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch, tmp_path):
    """Setup test environment for all tests."""
    monkeypatch.setenv("MAVEN_SETTINGS_PATH", str(tmp_path / "settings.xml"))
    monkeypatch.setenv("MAVEN_SECURITY_PATH", str(tmp_path / "settings-security.xml"))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_settings_xml(temp_dir):
    """Create a mock settings.xml file with test data."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
    <settings>
        <servers>
            <server>
                <id>server1</id>
                <username>testuser</username>
                <!-- testpass -->
                <password>{ERozWEamSJoHRBT+wVx51V2Emr9PazZR9txMntZPlJc=}</password>
            </server>
            <server>
                <id>server2</id>
                <username>plainuser</username>
                <password>plainpass</password>
            </server>
            <server>
                <id>server3</id>
                <username>emptyuser</username>
                <password></password>
            </server>
        </servers>
    </settings>
    """
    settings_file = temp_dir / "settings.xml"
    settings_file.write_text(content)
    return settings_file


@pytest.fixture
def mock_security_xml(temp_dir):
    """Create a mock settings-security.xml file with test data."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
    <settingsSecurity>
        <!-- password = master -->
        <master>{FyoLIiN2Fx8HpT8O0aBsTn2/s3pYmtLRRCpoWPzhN4A=}</master>
    </settingsSecurity>
    """
    security_file = temp_dir / "settings-security.xml"
    security_file.write_text(content)
    return security_file


@pytest.fixture
def decoder(mock_settings_xml, mock_security_xml):
    """Create a MavenPasswordDecoder instance with mock files."""
    return MavenPasswordDecoder(
        settings_path=mock_settings_xml,
        security_path=mock_security_xml
    )
