# Maven Settings Decoder

A Python tool to decrypt passwords in Maven settings files (`settings.xml` and `settings-security.xml`). This tool can help you retrieve encrypted credentials from Maven configuration files, which is particularly useful for debugging or auditing purposes.

## Features

- Decrypts master password from `settings-security.xml`
- Decrypts server passwords from `settings.xml`
- Support for both default and custom file paths
- Color-coded console output
- Verbose debugging mode
- Clear error messages and handling

## Installation

### From PyPI (Recommended)

```bash
pip install maven_settings_decoder
```

### From Source

```bash
git clone https://github.com/svaningelgem/maven_settings_decoder.git
cd maven_settings_decoder
pip install -e .
```

## Usage

### Command Line Interface

1. Using default paths (`~/.m2/settings.xml` and `~/.m2/settings-security.xml`):
```bash
maven-decoder
```

2. Specifying custom file paths:
```bash
maven-decoder --settings /path/to/settings.xml --security /path/to/settings-security.xml
```

3. Enable verbose output:
```bash
maven-decoder -v
```

4. Disable colored output:
```bash
maven-decoder --no-color
```

### Python API

```python
from maven_settings_decoder import MavenPasswordDecoder

# Initialize with default paths
decoder = MavenPasswordDecoder()

# Or specify custom paths
decoder = MavenPasswordDecoder(
    settings_path="/path/to/settings.xml",
    security_path="/path/to/settings-security.xml"
)

# Get master password
master_password = decoder.get_master_password()
print(f"Master password: {master_password}")

# Get all server credentials
servers = decoder.read_credentials()
for server in servers:
    print(f"Server: {server.id}")
    print(f"Username: {server.username}")
    print(f"Password: {server.decrypted_password}")
```

## Requirements

- Python 3.9+
- cryptography
- loguru

## How It Works

The tool implements Maven's password encryption scheme:

1. Reads the master password from `settings-security.xml`
2. Decrypts the master password using the default key "settings.security"
3. Uses the decrypted master password to decrypt server passwords in `settings.xml`
4. Handles various encryption formats and edge cases

## Command Line Options

```
usage: maven-decoder [-h] [-s SETTINGS] [--security SECURITY] [-v] [--no-color]

Decrypt passwords in Maven settings files

optional arguments:
  -h, --help            show this help message and exit
  -s SETTINGS, --settings SETTINGS
                        Path to settings.xml file (default: ~/.m2/settings.xml)
  --security SECURITY   Path to settings-security.xml file (default: ~/.m2/settings-security.xml)
  -v, --verbose        Enable verbose debug output (default: False)
  --no-color           Disable colored output (default: False)
```

## Exit Codes

- 0: Success
- 1: Error (file not found, decoding error, etc.)
- 130: User interrupted (Ctrl+C)
## Installation and Usage

### Installation

```bash
# Install from PyPI
pip install maven_settings_decoder

# Or using Poetry
poetry add maven_settings_decoder
```

### Command Line Usage

After installation, the `maven-decoder` command will be available in your environment:

```bash
# Show help
maven-decoder --help

# Decode with default paths
maven-decoder

# Decode with custom paths
maven-decoder --settings /path/to/settings.xml --security /path/to/settings-security.xml

# Enable verbose output
maven-decoder -v

# Disable colored output
maven-decoder --no-color
```

### Development Installation

For development:

```bash
# Clone the repository
git clone https://github.com/svaningelgem/maven_settings_decoder
cd maven_settings_decoder

# Install with Poetry in development mode
poetry install

# Run the script
poetry run maven-decoder --help

# Or activate the virtual environment and run directly
poetry shell
maven-decoder --help
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/svaningelgem/maven_settings_decoder.git
cd maven_settings_decoder

# Create and activate virtual environment (optional)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on the encryption scheme used in [Apache Maven](https://maven.apache.org/)
- Inspired by the Java implementation in [plexus-cipher](https://github.com/sonatype/plexus-cipher/)
- Implementation details derived from [Maven Settings Builder](https://github.com/apache/maven/tree/master/maven-settings-builder)

## Security

This tool is meant for legitimate use cases such as debugging and auditing. Please ensure you have the necessary permissions before attempting to decrypt passwords in Maven settings files.

Note: Never commit your decrypted passwords or master passwords to version control systems.

## Support

If you encounter any issues or have questions, please:

1. Check the [FAQ](docs/FAQ.md)
2. Search existing [issues](https://github.com/svaningelgem/maven_settings_decoder/issues)
3. Create a new issue if needed

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for all changes between versions.