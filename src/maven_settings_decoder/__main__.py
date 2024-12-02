#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from .decode import MavenDecodeError, MavenPasswordDecoder

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["main"]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """
    Parse command line arguments.

    Args:
        argv: List of arguments to parse. Defaults to sys.argv[1:]

    Returns:
        Parsed argument namespace

    """
    parser = argparse.ArgumentParser(description="Decrypt passwords in Maven settings files", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        "-s",
        "--settings",
        help="Path to settings.xml file",
        type=Path,
        default=Path.home() / ".m2/settings.xml",
    )

    parser.add_argument("--security", help="Path to settings-security.xml file", type=Path, default=Path.home() / ".m2/settings-security.xml")

    parser.add_argument("-v", "--verbose", help="Enable verbose debug output", action="store_true")

    return parser.parse_args(argv)


def display_master_password(decoder: MavenPasswordDecoder) -> None:
    """
    Display information about the master password if available.

    Args:
        decoder: Initialized MavenPasswordDecoder instance

    """
    if decoder.security_path.exists():
        logger.debug("Master Password Information:")
        logger.debug("=" * 50)

        try:
            raw_master = decoder.get_raw_master_password()
            if raw_master:
                logger.debug(f"Encrypted master password: {raw_master}")
                decrypted_master = decoder.get_master_password()
                logger.info(f"Decrypted master password: {decrypted_master}")
                logger.debug("-" * 50)
            else:
                logger.warning("No master password found in settings-security.xml")
        except MavenDecodeError as e:
            logger.error(f"Error reading master password: {e}")
    else:
        logger.debug(f"No settings-security.xml found at: {decoder.security_path}")


def main(argv: Sequence[str] | None = None) -> int:
    """
    Main entry point for the Maven password decoder script.

    Args:
        argv: List of command line arguments

    Returns:
        Exit code (0 for success, non-zero for errors)

    """
    args = parse_args(argv)

    if args.verbose:
        logger.level("DEBUG")

    try:
        # Initialize decoder with provided paths
        decoder = MavenPasswordDecoder(settings_path=args.settings, security_path=args.security)

        # Log file paths in debug mode
        logger.debug(f"Settings file: {args.settings}")
        logger.debug(f"Security file: {args.security}")

        # Verify settings.xml exists
        if not args.settings.exists():
            logger.error(f"settings.xml not found at: {args.settings}")
            return 1

        display_master_password(decoder)

        # Read and process credentials
        servers = decoder.read_credentials()

        if not servers:
            logger.warning("No server credentials found in settings.xml")
            return 0

        # Display results
        logger.info("Server Credentials:")
        logger.info("=" * 50)

        for server in servers:
            logger.info(f"Server ID: {server.id}")
            logger.info(f"Username: {server.username}")
            logger.info(f"Password: {server.decrypted_password}")
            logger.info("-" * 50)

    except MavenDecodeError as e:
        logger.error(f"Failed to decode Maven passwords: {e}")
        if args.verbose:
            logger.exception("Detailed error information:")
        return 1

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        return 130

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            logger.exception("Detailed error information:")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
