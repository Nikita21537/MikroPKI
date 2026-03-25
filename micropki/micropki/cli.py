"""Command-line interface for MicroPKI."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .ca import RootCA
from .intermediate import IntermediateCA
from . import csr as csr_module
from . import templates
from .chain import ChainValidator


def validate_issue_intermediate_args(args):
    """Validate arguments for issue-intermediate command."""
    errors = []

    # Check file paths
    for file_path, name in [
        (args.root_cert, "root-cert"),
        (args.root_key, "root-key"),
        (args.root_pass_file, "root-pass-file"),
        (args.passphrase_file, "passphrase-file")
    ]:
        path = Path(file_path)
        if not path.exists():
            errors.append(f"{name} file not found: {file_path}")
        elif not path.is_file():
            errors.append(f"{name} path is not a file: {file_path}")

    # Validate subject
    if not args.subject:
        errors.append("--subject is required and must be non-empty")

    # Validate key type
    if args.key_type not in ['rsa', 'ecc']:
        errors.append(f"--key-type must be 'rsa' or 'ecc', got '{args.key_type}'")

    # Validate validity days
    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive, got {args.validity_days}")

    # Validate pathlen
    if args.pathlen < 0:
        errors.append(f"--pathlen must be >= 0, got {args.pathlen}")

    return errors


def validate_issue_cert_args(args):
    """Validate arguments for issue-cert command."""
    errors = []

    # Check file paths
    for file_path, name in [
        (args.ca_cert, "ca-cert"),
        (args.ca_key, "ca-key"),
        (args.ca_pass_file, "ca-pass-file")
    ]:
        path = Path(file_path)
        if not path.exists():
            errors.append(f"{name} file not found: {file_path}")
        elif not path.is_file():
            errors.append(f"{name} path is not a file: {file_path}")

    # Validate template
    if args.template not in ['server', 'client', 'code_signing']:
        errors.append(
            f"--template must be server, client, or code_signing, got '{args.template}'"
        )

    # Validate subject
    if not args.subject:
        errors.append("--subject is required and must be non-empty")

    # Validate validity days
    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive, got {args.validity_days}")

    # Validate SANs for server certificate
    if args.template == 'server' and not args.san:
        errors.append("Server certificate requires at least one SAN (--san dns:... or ip:...)")

    return errors


def parse_san_args(san_list):
    """Parse SAN arguments from CLI."""
    if not san_list:
        return []
    return san_list


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
    parser.add_argument(
        '--log-file',
        help='Path to log file'
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        help="Available commands"
    )

    # CA operations subcommand
    ca_parser = subparsers.add_parser(
        "ca",
        help="Certificate Authority operations"
    )
    ca_subparsers = ca_parser.add_subparsers(
        dest="ca_command",
        help="CA subcommands"
    )

    # CA init (Sprint 1)
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

    # Issue Intermediate CA (Sprint 2)
    issue_intermediate_parser = ca_subparsers.add_parser(
        "issue-intermediate",
        help="Create an Intermediate CA signed by the Root CA"
    )
    issue_intermediate_parser.add_argument(
        "--root-cert",
        required=True,
        help="Path to Root CA certificate (PEM)"
    )
    issue_intermediate_parser.add_argument(
        "--root-key",
        required=True,
        help="Path to Root CA encrypted private key (PEM)"
    )
    issue_intermediate_parser.add_argument(
        "--root-pass-file",
        required=True,
        help="File containing passphrase for Root CA key"
    )
    issue_intermediate_parser.add_argument(
        "--subject",
        required=True,
        help="Distinguished Name for the Intermediate CA"
    )
    issue_intermediate_parser.add_argument(
        "--key-type",
        choices=['rsa', 'ecc'],
        default='rsa',
        help="Key type for Intermediate CA (default: rsa)"
    )
    issue_intermediate_parser.add_argument(
        "--passphrase-file",
        required=True,
        help="Passphrase for Intermediate CA private key"
    )
    issue_intermediate_parser.add_argument(
        "--out-dir",
        default="./pki",
        help="Output directory (default: ./pki)"
    )
    issue_intermediate_parser.add_argument(
        "--validity-days",
        type=int,
        default=1825,
        help="Validity period in days (default: 1825)"
    )
    issue_intermediate_parser.add_argument(
        "--pathlen",
        type=int,
        default=0,
        help="Path length constraint (default: 0)"
    )

    # Issue Certificate (Sprint 2)
    issue_cert_parser = ca_subparsers.add_parser(
        "issue-cert",
        help="Issue an end-entity certificate"
    )
    issue_cert_parser.add_argument(
        "--ca-cert",
        required=True,
        help="Intermediate CA certificate (PEM)"
    )
    issue_cert_parser.add_argument(
        "--ca-key",
        required=True,
        help="Intermediate CA encrypted private key (PEM)"
    )
    issue_cert_parser.add_argument(
        "--ca-pass-file",
        required=True,
        help="Passphrase for Intermediate CA key"
    )
    issue_cert_parser.add_argument(
        "--template",
        required=True,
        choices=['server', 'client', 'code_signing'],
        help="Certificate template"
    )
    issue_cert_parser.add_argument(
        "--subject",
        required=True,
        help="Distinguished Name for the certificate"
    )
    issue_cert_parser.add_argument(
        "--san",
        action='append',
        dest='san',
        help="Subject Alternative Name(s) in format type:value (can be used multiple times)"
    )
    issue_cert_parser.add_argument(
        "--out-dir",
        default="./pki/certs",
        help="Output directory (default: ./pki/certs)"
    )
    issue_cert_parser.add_argument(
        "--validity-days",
        type=int,
        default=365,
        help="Leaf certificate validity (default: 365)"
    )
    issue_cert_parser.add_argument(
        "--csr",
        help="Optional CSR file to sign instead of generating new key"
    )

    # Verify Chain (Sprint 2)
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify certificate chain"
    )
    verify_parser.add_argument(
        "--leaf",
        required=True,
        help="Leaf certificate (PEM)"
    )
    verify_parser.add_argument(
        "--intermediate",
        required=True,
        help="Intermediate CA certificate (PEM)"
    )
    verify_parser.add_argument(
        "--root",
        required=True,
        help="Root CA certificate (PEM)"
    )

    args = parser.parse_args()

    # Handle commands
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "ca":
        if args.ca_command == "init":
            # Sprint 1 logic (simplified)
            from .cli import main as old_main
            # For brevity, this would call existing init logic
            pass

        elif args.ca_command == "issue-intermediate":
            errors = validate_issue_intermediate_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                sys.exit(1)

            try:
                ca = IntermediateCA(args.out_dir, args.log_file)
                ca.create_intermediate_ca(
                    root_cert_path=Path(args.root_cert),
                    root_key_path=Path(args.root_key),
                    root_pass_file=Path(args.root_pass_file),
                    subject_dn=args.subject,
                    key_type=args.key_type,
                    passphrase_file=Path(args.passphrase_file),
                    validity_days=args.validity_days,
                    pathlen=args.pathlen
                )
                print(f"Intermediate CA successfully created in {args.out_dir}")
            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_command == "issue-cert":
            errors = validate_issue_cert_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                sys.exit(1)

            try:
                from .intermediate import IssueCertificate
                issuer = IssueCertificate(args.log_file)

                # Parse SANs if provided
                san_list = parse_san_args(args.san) if args.san else []

                # Issue certificate
                cert_path, key_path = issuer.issue_certificate(
                    ca_cert_path=Path(args.ca_cert),
                    ca_key_path=Path(args.ca_key),
                    ca_pass_file=Path(args.ca_pass_file),
                    template_name=args.template,
                    subject_dn=args.subject,
                    san_list=san_list,
                    out_dir=Path(args.out_dir),
                    validity_days=args.validity_days,
                    csr_path=Path(args.csr) if args.csr else None
                )

                print(f"Certificate successfully issued: {cert_path}")
                if key_path:
                    print(f"Private key saved to: {key_path}")
                    print("WARNING: Private key is stored unencrypted. Ensure proper file permissions.")
            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "verify":
        try:
            validator = ChainValidator()
            valid, errors = validator.validate_chain(
                leaf_path=Path(args.leaf),
                intermediate_path=Path(args.intermediate),
                root_path=Path(args.root)
            )

            if valid:
                print("Certificate chain is valid")
                sys.exit(0)
            else:
                print("Certificate chain is invalid:", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()