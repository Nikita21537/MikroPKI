"""Command-line interface for MicroPKI."""

import argparse
import sys
from pathlib import Path

from .ca import RootCA
from . import __version__


def validate_args(args):
    """Validate command line arguments."""
    errors = []

    # Validate subject
    if not args.subject:
        errors.append("--subject is required and must be non-empty")

    # Validate key type and size
    if args.key_type not in ['rsa', 'ecc']:
        errors.append(f"--key-type must be 'rsa' or 'ecc', got '{args.key_type}'")
    elif args.key_type == 'rsa' and args.key_size != 4096:
        errors.append(f"RSA key size must be 4096 bits, got {args.key_size}")
    elif args.key_type == 'ecc' and args.key_size != 384:
        errors.append(f"ECC key size must be 384 bits (P-384), got {args.key_size}")

    # Validate passphrase file
    passphrase_path = Path(args.passphrase_file)
    if not passphrase_path.exists():
        errors.append(f"Passphrase file not found: {args.passphrase_file}")
    elif not passphrase_path.is_file():
        errors.append(f"Passphrase path is not a file: {args.passphrase_file}")

    # Validate output directory
    out_dir = Path(args.out_dir)
    if out_dir.exists() and not out_dir.is_dir():
        errors.append(f"Output path exists but is not a directory: {args.out_dir}")

    # Validate validity days
    if args.validity_days <= 0:
        errors.append(f"Validity days must be positive, got {args.validity_days}")

    # Validate log file directory if provided
    if args.log_file:
        log_path = Path(args.log_file)
        log_dir = log_path.parent
        if log_dir.exists() and not log_dir.is_dir():
            errors.append(f"Log file directory exists but is not a directory: {log_dir}")

    return errors


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="MicroPKI - Minimal Public Key Infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'MicroPKI {__version__}'
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        help="Available commands"
    )

    # CA init subcommand
    ca_parser = subparsers.add_parser(
        "ca",
        help="Certificate Authority operations"
    )
    ca_subparsers = ca_parser.add_subparsers(
        dest="ca_command",
        help="CA subcommands"
    )

    init_parser = ca_subparsers.add_parser(
        "init",
        help="Initialize a new Root CA"
    )
    init_parser.add_argument(
        "--subject",
        required=True,
        help="Distinguished Name (e.g., '/CN=My Root CA' or 'CN=My Root CA,O=Demo')"
    )
    init_parser.add_argument(
        "--key-type",
        choices=['rsa', 'ecc'],
        default='rsa',
        help="Key type (default: rsa)"
    )
    init_parser.add_argument(
        "--key-size",
        type=int,
        default=4096,
        help="Key size in bits (RSA: 4096, ECC: 384) (default: 4096)"
    )
    init_parser.add_argument(
        "--passphrase-file",
        required=True,
        help="Path to file containing the passphrase for private key encryption"
    )
    init_parser.add_argument(
        "--out-dir",
        default="./pki",
        help="Output directory (default: ./pki)"
    )
    init_parser.add_argument(
        "--validity-days",
        type=int,
        default=3650,
        help="Validity period in days (default: 3650)"
    )
    init_parser.add_argument(
        "--log-file",
        help="Optional path to log file (logs to stderr if omitted)"
    )

    args = parser.parse_args()

    # Check if we have a valid command
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "ca" and args.ca_command == "init":
        # Validate arguments
        errors = validate_args(args)
        if errors:
            for error in errors:
                print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)

        try:
            # Initialize CA
            ca = RootCA(args.out_dir, args.log_file)
            ca.init_ca(
                subject=args.subject,
                key_type=args.key_type,
                key_size=args.key_size,
                passphrase_file=args.passphrase_file,
                validity_days=args.validity_days
            )
            print(f"Root CA successfully initialized in {args.out_dir}")
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Unknown command: {args.command} {getattr(args, 'ca_command', '')}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()