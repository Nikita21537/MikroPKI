import argparse
import sys
from pathlib import Path


from . import __version__
from .ca import RootCA
from .intermediate import IntermediateCA, IssueCertificate
from . import csr as csr_module
from . import templates
from .chain import ChainValidator
from .database import Database
from .logger import setup_logger
from .revocation import RevocationManager, CRLManager, RevocationReason
from .ocsp_responder import OCSPResponderServer


def validate_issue_intermediate_args(args):
    errors = []
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

    if not args.subject:
        errors.append("--subject is required and must be non-empty")

    if args.key_type not in ['rsa', 'ecc']:
        errors.append(f"--key-type must be 'rsa' or 'ecc', got '{args.key_type}'")

    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive, got {args.validity_days}")

    if args.pathlen < 0:
        errors.append(f"--pathlen must be >= 0, got {args.pathlen}")

    return errors


def validate_issue_cert_args(args):
    errors = []
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

    if args.template not in ['server', 'client', 'code_signing']:
        errors.append(
            f"--template must be server, client, or code_signing, got '{args.template}'"
        )

    if not args.subject:
        errors.append("--subject is required and must be non-empty")

    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive, got {args.validity_days}")

    if args.template == 'server' and not args.san:
        errors.append("Server certificate requires at least one SAN (--san dns:... or ip:...)")

    return errors


def validate_revoke_args(args):

    errors = []

    if not args.serial:
        errors.append("serial is required")

    if args.reason:
        reason_enum = RevocationReason.from_string(args.reason)
        if reason_enum is None:
            supported = [r.to_string() for r in RevocationReason]
            errors.append(f"Invalid revocation reason: {args.reason}. "
                          f"Supported: {', '.join(supported)}")

    return errors


def validate_gen_crl_args(args):

    errors = []

    if args.ca not in ['root', 'intermediate']:
        errors.append(f"--ca must be 'root' or 'intermediate', got '{args.ca}'")

    if args.next_update <= 0:
        errors.append(f"--next-update must be positive, got {args.next_update}")

    return errors


def parse_san_args(san_list):
    if not san_list:
        return []
    return san_list


def print_table_certificates(certs):
    if not certs:
        print("No certificates found")
        return

    print(f"{'Serial':<20} {'Subject':<40} {'Status':<10} {'Expires':<20}")
    print("-" * 90)
    for cert in certs:
        serial = cert['serial_hex'][:18] + ".." if len(cert['serial_hex']) > 20 else cert['serial_hex']
        subject = cert['subject'][:38] + ".." if len(cert['subject']) > 40 else cert['subject']
        expires = cert['not_after'][:10] if cert['not_after'] else "N/A"
        status = cert['status']
        if status == 'revoked':
            status = f"REVOKED"
        print(f"{serial:<20} {subject:<40} {status:<10} {expires:<20}")


def print_csv_certificates(certs):
    import csv
    import sys
    writer = csv.writer(sys.stdout)
    writer.writerow(
        ['serial_hex', 'subject', 'issuer', 'not_before', 'not_after', 'status', 'created_at', 'revocation_reason',
         'revocation_date'])
    for cert in certs:
        writer.writerow([
            cert['serial_hex'], cert['subject'], cert['issuer'],
            cert['not_before'], cert['not_after'], cert['status'],
            cert['created_at'], cert.get('revocation_reason', ''),
            cert.get('revocation_date', '')
        ])


def print_certificate_details(cert):
    print(f"Serial Number: {cert['serial_hex']}")
    print(f"Subject: {cert['subject']}")
    print(f"Issuer: {cert['issuer']}")
    print(f"Not Before: {cert['not_before']}")
    print(f"Not After: {cert['not_after']}")
    print(f"Status: {cert['status']}")
    if cert.get('revocation_reason'):
        print(f"Revocation Reason: {cert['revocation_reason']}")
    if cert.get('revocation_date'):
        print(f"Revocation Date: {cert['revocation_date']}")
    print(f"Created At: {cert['created_at']}")


def main():
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

    # Database commands
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_subparsers = db_parser.add_subparsers(dest="db_command", help="Database subcommands")

    init_db_parser = db_subparsers.add_parser("init", help="Initialize certificate database")
    init_db_parser.add_argument("--db-path", default="./pki/micropki.db", help="SQLite database path")

    # CA commands
    ca_parser = subparsers.add_parser("ca", help="Certificate Authority operations")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command", help="CA subcommands")

    # Root CA init
    init_parser = ca_subparsers.add_parser("init", help="Initialize a new Root CA")
    init_parser.add_argument("--subject", required=True, help="Distinguished Name")
    init_parser.add_argument("--key-type", choices=['rsa', 'ecc'], default='rsa')
    init_parser.add_argument("--key-size", type=int, default=4096)
    init_parser.add_argument("--passphrase-file", required=True)
    init_parser.add_argument("--out-dir", default="./pki")
    init_parser.add_argument("--validity-days", type=int, default=3650)

    # Issue Intermediate CA
    issue_intermediate_parser = ca_subparsers.add_parser(
        "issue-intermediate",
        help="Create an Intermediate CA signed by the Root CA"
    )
    issue_intermediate_parser.add_argument("--root-cert", required=True)
    issue_intermediate_parser.add_argument("--root-key", required=True)
    issue_intermediate_parser.add_argument("--root-pass-file", required=True)
    issue_intermediate_parser.add_argument("--subject", required=True)
    issue_intermediate_parser.add_argument("--key-type", choices=['rsa', 'ecc'], default='rsa')
    issue_intermediate_parser.add_argument("--passphrase-file", required=True)
    issue_intermediate_parser.add_argument("--out-dir", default="./pki")
    issue_intermediate_parser.add_argument("--validity-days", type=int, default=1825)
    issue_intermediate_parser.add_argument("--pathlen", type=int, default=0)

    # Issue Certificate
    issue_cert_parser = ca_subparsers.add_parser("issue-cert", help="Issue an end-entity certificate")
    issue_cert_parser.add_argument("--ca-cert", required=True)
    issue_cert_parser.add_argument("--ca-key", required=True)
    issue_cert_parser.add_argument("--ca-pass-file", required=True)
    issue_cert_parser.add_argument("--template", required=True, choices=['server', 'client', 'code_signing'])
    issue_cert_parser.add_argument("--subject", required=True)
    issue_cert_parser.add_argument("--san", action='append', dest='san')
    issue_cert_parser.add_argument("--out-dir", default="./pki/certs")
    issue_cert_parser.add_argument("--validity-days", type=int, default=365)
    issue_cert_parser.add_argument("--csr", help="Optional CSR file to sign instead of generating new key")

    # Sprint 4: Revoke certificate
    revoke_parser = ca_subparsers.add_parser("revoke", help="Revoke a certificate")
    revoke_parser.add_argument("serial", help="Certificate serial number (hex)")
    revoke_parser.add_argument("--reason", help="Revocation reason",
                               choices=['unspecified', 'keyCompromise', 'cACompromise',
                                        'affiliationChanged', 'superseded', 'cessationOfOperation',
                                        'certificateHold', 'removeFromCRL', 'privilegeWithdrawn',
                                        'aACompromise'])
    revoke_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    revoke_parser.add_argument("--out-dir", default="./pki", help="PKI directory")

    # Sprint 4: Generate CRL
    gen_crl_parser = ca_subparsers.add_parser("gen-crl", help="Generate Certificate Revocation List")
    gen_crl_parser.add_argument("--ca", required=True, choices=['root', 'intermediate'],
                                help="CA type to generate CRL for")
    gen_crl_parser.add_argument("--next-update", type=int, default=7,
                                help="Days until next CRL update (default: 7)")
    gen_crl_parser.add_argument("--out-file", help="Output file path (optional)")
    gen_crl_parser.add_argument("--out-dir", default="./pki", help="PKI directory")

    # Sprint 4: Check revoked
    check_revoked_parser = ca_subparsers.add_parser("check-revoked",
                                                    help="Check certificate revocation status")
    check_revoked_parser.add_argument("serial", help="Certificate serial number (hex)")
    check_revoked_parser.add_argument("--out-dir", default="./pki", help="PKI directory")

    # List certificates
    list_certs_parser = ca_subparsers.add_parser("list-certs", help="List certificates from database")
    list_certs_parser.add_argument("--status", choices=['valid', 'revoked', 'expired'], help="Filter by status")
    list_certs_parser.add_argument("--issuer", help="Filter by issuer (partial match)")
    list_certs_parser.add_argument("--limit", type=int, default=100, help="Maximum results")
    list_certs_parser.add_argument("--format", choices=['table', 'json', 'csv'], default='table', help="Output format")
    list_certs_parser.add_argument("--db-path", default="./pki/micropki.db", help="Database path")

    # Show certificate
    show_cert_parser = ca_subparsers.add_parser("show-cert", help="Show certificate by serial number")
    show_cert_parser.add_argument("serial", help="Certificate serial number (hex)")
    show_cert_parser.add_argument("--format", choices=['pem', 'text'], default='pem', help="Output format")
    show_cert_parser.add_argument("--db-path", default="./pki/micropki.db", help="Database path")

    # OCSP commands (Sprint 5)
    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP operations")
    ocsp_subparsers = ocsp_parser.add_subparsers(dest="ocsp_command", help="OCSP subcommands")

    # Issue OCSP certificate
    issue_ocsp_parser = ocsp_subparsers.add_parser("issue-ocsp-cert", help="Issue OCSP signing certificate")
    issue_ocsp_parser.add_argument("--ca-cert", required=True, help="CA certificate (PEM)")
    issue_ocsp_parser.add_argument("--ca-key", required=True, help="CA private key (PEM)")
    issue_ocsp_parser.add_argument("--ca-pass-file", required=True, help="CA passphrase file")
    issue_ocsp_parser.add_argument("--subject", required=True, help="Subject DN for OCSP responder")
    issue_ocsp_parser.add_argument("--key-type", choices=['rsa', 'ecc'], default='rsa')
    issue_ocsp_parser.add_argument("--key-size", type=int, default=2048, help="Key size (RSA:2048+, ECC:256/384)")
    issue_ocsp_parser.add_argument("--san", action='append', dest='san', help="SAN (dns:..., ip:..., uri:...)")
    issue_ocsp_parser.add_argument("--ocsp-url", help="OCSP responder URL for AIA extension")
    issue_ocsp_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory")
    issue_ocsp_parser.add_argument("--validity-days", type=int, default=365, help="Validity period in days")

    # OCSP serve command
    ocsp_serve_parser = ocsp_subparsers.add_parser("serve", help="Start OCSP responder server")
    ocsp_serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    ocsp_serve_parser.add_argument("--port", type=int, default=8081, help="TCP port")
    ocsp_serve_parser.add_argument("--db-path", default="./pki/micropki.db", help="SQLite database path")
    ocsp_serve_parser.add_argument("--responder-cert", required=True, help="OCSP signing certificate (PEM)")
    ocsp_serve_parser.add_argument("--responder-key", required=True, help="OCSP private key (PEM, unencrypted)")
    ocsp_serve_parser.add_argument("--ca-cert", required=True, help="Issuer CA certificate (PEM)")
    ocsp_serve_parser.add_argument("--cache-ttl", type=int, default=60, help="Response cache TTL in seconds")
    ocsp_serve_parser.add_argument("--log-file", help="Log file path")

    # Repository commands
    repo_parser = subparsers.add_parser("repo", help="Repository operations")
    repo_subparsers = repo_parser.add_subparsers(dest="repo_command", help="Repository subcommands")

    serve_parser = repo_subparsers.add_parser("serve", help="Start repository HTTP server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=8080, help="TCP port")
    serve_parser.add_argument("--db-path", default="./pki/micropki.db", help="Database path")
    serve_parser.add_argument("--cert-dir", default="./pki/certs", help="Certificate directory")
    serve_parser.add_argument("--out-dir", default="./pki", help="PKI directory for CRL files")

    status_parser = repo_subparsers.add_parser("status", help="Check repository server status")
    status_parser.add_argument("--host", default="127.0.0.1")
    status_parser.add_argument("--port", type=int, default=8080)

    # Verify chain
    verify_parser = subparsers.add_parser("verify", help="Verify certificate chain")
    verify_parser.add_argument("--leaf", required=True, help="Leaf certificate (PEM)")
    verify_parser.add_argument("--intermediate", required=True, help="Intermediate CA certificate (PEM)")
    verify_parser.add_argument("--root", required=True, help="Root CA certificate (PEM)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Database commands
    if args.command == "db":
        if args.db_command == "init":
            try:
                db = Database(args.db_path)
                print(f"Database initialized at {args.db_path}")
                logger = setup_logger(args.log_file)
                logger.info(f"Database initialized: {args.db_path}")
            except Exception as e:
                print(f"Error initializing database: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print("Unknown db command. Available: init", file=sys.stderr)
            sys.exit(1)

    # CA commands
    elif args.command == "ca":
        if args.ca_command == "init":
            try:
                ca = RootCA(args.out_dir, args.log_file)
                ca.init_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    validity_days=args.validity_days
                )
                print(f"Root CA successfully created in {args.out_dir}")

                # Автоматически инициализируем базу данных
                db_path = Path(args.out_dir) / "micropki.db"
                if not db_path.exists():
                    db = Database(str(db_path))
                    print(f"Database initialized at {db_path}")

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

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
                issuer = IssueCertificate(args.log_file)
                san_list = parse_san_args(args.san) if args.san else []

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

        # Sprint 4: Revoke certificate
        elif args.ca_command == "revoke":
            errors = validate_revoke_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                sys.exit(1)

            try:
                db_path = Path(args.out_dir) / "micropki.db"
                if not db_path.exists():
                    db_path = Path("./pki/micropki.db")

                db = Database(str(db_path))
                out_dir = Path(args.out_dir)
                revoke_mgr = RevocationManager(db, out_dir, setup_logger(args.log_file))

                success, message = revoke_mgr.revoke_certificate(
                    serial_hex=args.serial,
                    reason=args.reason,
                    force=args.force
                )

                print(message)
                sys.exit(0 if success else 1)

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        # Sprint 4: Generate CRL
        elif args.ca_command == "gen-crl":
            errors = validate_gen_crl_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                sys.exit(1)

            try:
                out_dir = Path(args.out_dir)
                db_path = out_dir / "micropki.db"

                if not db_path.exists():
                    print(f"Database not found: {db_path}", file=sys.stderr)
                    sys.exit(1)

                db = Database(str(db_path))
                crl_mgr = CRLManager(out_dir, db, setup_logger(args.log_file))

                # Определяем пути к файлам CA
                if args.ca == "root":
                    ca_cert_path = out_dir / "certs" / "ca.cert.pem"
                    ca_key_path = out_dir / "private" / "ca.key.pem"
                else:
                    ca_cert_path = out_dir / "certs" / "intermediate.cert.pem"
                    ca_key_path = out_dir / "private" / "intermediate.key.pem"

                # Поиск файла с паролем
                pass_file = out_dir.parent / "secrets" / f"{args.ca}.pass"
                if not pass_file.exists():
                    pass_file = out_dir.parent / "secrets" / f"{args.ca}_pass.txt"

                if not pass_file.exists():
                    print(f"Passphrase file not found for {args.ca} CA", file=sys.stderr)
                    sys.exit(1)

                out_file = Path(args.out_file) if args.out_file else None

                crl_path = crl_mgr.generate_crl(
                    ca_cert_path=ca_cert_path,
                    ca_key_path=ca_key_path,
                    ca_pass_file=pass_file,
                    ca_type=args.ca,
                    next_update_days=args.next_update,
                    out_file=out_file
                )

                print(f"CRL generated successfully: {crl_path}")

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        # Sprint 4: Check revoked
        elif args.ca_command == "check-revoked":
            try:
                out_dir = Path(args.out_dir)
                db_path = out_dir / "micropki.db"

                if not db_path.exists():
                    print(f"Database not found: {db_path}", file=sys.stderr)
                    sys.exit(1)

                db = Database(str(db_path))
                revoke_mgr = RevocationManager(db, out_dir, setup_logger(args.log_file))

                is_revoked, info = revoke_mgr.check_revoked(args.serial)

                if info is None:
                    print(f"Certificate with serial {args.serial} not found")
                    sys.exit(1)

                if is_revoked:
                    print(f"Certificate {args.serial} is REVOKED")
                    print(f"  Subject: {info['subject']}")
                    print(f"  Revocation Date: {info['revocation_date']}")
                    print(f"  Reason: {info['revocation_reason'] or 'unspecified'}")
                    sys.exit(0)
                else:
                    print(f"Certificate {args.serial} is VALID (not revoked)")
                    sys.exit(0)

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_command == "list-certs":
            try:
                db = Database(args.db_path)
                certs = db.list_certificates(status=args.status, limit=args.limit)

                if args.format == 'table':
                    print_table_certificates(certs)
                elif args.format == 'json':
                    import json
                    print(json.dumps(certs, indent=2, default=str))
                elif args.format == 'csv':
                    print_csv_certificates(certs)

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_command == "show-cert":
            try:
                db = Database(args.db_path)
                cert = db.get_certificate_by_serial(args.serial)

                if cert:
                    if args.format == 'pem':
                        print(cert['cert_pem'])
                    else:
                        print_certificate_details(cert)
                else:
                    print(f"Certificate with serial {args.serial} not found", file=sys.stderr)
                    sys.exit(1)
            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)
        else:
            print("Unknown ca command", file=sys.stderr)
            sys.exit(1)

    # Repository commands
    elif args.command == "repo":
        if args.repo_command == "serve":
            try:
                from .repository import RepositoryServer
                import logging

                logger = setup_logger(args.log_file)

                # Проверяем существование базы данных
                db_path = Path(args.db_path)
                if not db_path.exists():
                    print(f"Database not found at {args.db_path}. Run 'micropki db init' first.", file=sys.stderr)
                    sys.exit(1)

                db = Database(args.db_path)
                out_dir = Path(args.out_dir) if hasattr(args, 'out_dir') else Path("./pki")
                server = RepositoryServer(args.host, args.port, db, args.cert_dir, out_dir)
                server.start()

            except KeyboardInterrupt:
                print("\nServer stopped")
                sys.exit(0)
            except Exception as e:
                print(f"Error starting server: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.repo_command == "status":
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((args.host, args.port))
            if result == 0:
                print(f"Repository server is running on {args.host}:{args.port}")
            else:
                print(f"No repository server detected on {args.host}:{args.port}")
            sock.close()
        else:
            print("Unknown repo command. Available: serve, status", file=sys.stderr)
            sys.exit(1)

    # Verify chain
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

    # OCSP commands (Sprint 5)
    elif args.command == "ocsp":
        if args.ocsp_command == "issue-ocsp-cert":
            try:
                from .ocsp import create_ocsp_signing_certificate
                from .certificates import load_certificate, save_certificate
                from .crypto_utils import load_passphrase, load_encrypted_private_key
                from datetime import datetime, timezone
                from cryptography.hazmat.primitives import serialization

                # Validate inputs
                ca_cert_path = Path(args.ca_cert)
                ca_key_path = Path(args.ca_key)
                ca_pass_file = Path(args.ca_pass_file)
                out_dir = Path(args.out_dir)

                if not ca_cert_path.exists():
                    print(f"CA certificate not found: {ca_cert_path}", file=sys.stderr)
                    sys.exit(1)
                if not ca_key_path.exists():
                    print(f"CA key not found: {ca_key_path}", file=sys.stderr)
                    sys.exit(1)
                if not ca_pass_file.exists():
                    print(f"CA passphrase file not found: {ca_pass_file}", file=sys.stderr)
                    sys.exit(1)

                # Load CA
                ca_cert = load_certificate(ca_cert_path)
                ca_pass = load_passphrase(ca_pass_file)
                ca_key = load_encrypted_private_key(ca_key_path, ca_pass)

                # Create OCSP signing certificate
                cert, private_key = create_ocsp_signing_certificate(
                    issuer_cert=ca_cert,
                    issuer_key=ca_key,
                    subject_dn=args.subject,
                    validity_days=args.validity_days,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    san_list=args.san if args.san else [],
                    ocsp_url=args.ocsp_url
                )

                # Ensure output directory exists
                out_dir.mkdir(parents=True, exist_ok=True)

                # Save certificate
                cert_path = out_dir / "ocsp.cert.pem"
                save_certificate(cert, cert_path)

                # Save private key (unencrypted for OCSP responder)
                key_path = out_dir / "ocsp.key.pem"
                unencrypted_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(key_path, 'wb') as f:
                    f.write(unencrypted_key)

                # Set proper permissions
                import os
                try:
                    os.chmod(key_path, 0o600)
                except Exception:
                    pass

                print(f"OCSP signing certificate created:")
                print(f"  Certificate: {cert_path}")
                print(f"  Private key: {key_path}")
                print(f"  Serial: {hex(cert.serial_number)}")
                print(f"  Valid until: {cert.not_valid_after}")
                print()
                print("WARNING: Private key is stored unencrypted (required for OCSP responder).")
                print("Ensure proper file permissions (0600) are maintained.")

                # Also insert into database
                db_path = out_dir.parent / "micropki.db"
                if db_path.exists():
                    try:
                        from .database import Database
                        db = Database(str(db_path))
                        cert_data = {
                            'serial_hex': format(cert.serial_number, '016X'),
                            'subject': args.subject,
                            'issuer': ca_cert.subject.rfc4514_string(),
                            'not_before': cert.not_valid_before.isoformat(),
                            'not_after': cert.not_valid_after.isoformat(),
                            'cert_pem': cert.public_bytes(serialization.Encoding.PEM).decode(),
                            'status': 'valid',
                            'created_at': datetime.now(timezone.utc).isoformat()
                        }
                        db.insert_certificate(cert_data)
                        print(f"Certificate recorded in database")
                    except Exception as e:
                        print(f"Warning: Could not insert into database: {e}")

            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        elif args.ocsp_command == "serve":
            try:
                # Validate inputs
                db_path = Path(args.db_path)
                responder_cert = Path(args.responder_cert)
                responder_key = Path(args.responder_key)
                ca_cert = Path(args.ca_cert)

                if not db_path.exists():
                    print(f"Database not found: {db_path}", file=sys.stderr)
                    sys.exit(1)
                if not responder_cert.exists():
                    print(f"OCSP certificate not found: {responder_cert}", file=sys.stderr)
                    sys.exit(1)
                if not responder_key.exists():
                    print(f"OCSP private key not found: {responder_key}", file=sys.stderr)
                    sys.exit(1)
                if not ca_cert.exists():
                    print(f"CA certificate not found: {ca_cert}", file=sys.stderr)
                    sys.exit(1)

                # Create and start server
                server = OCSPResponderServer(
                    host=args.host,
                    port=args.port,
                    db_path=str(db_path),
                    responder_cert_path=responder_cert,
                    responder_key_path=responder_key,
                    ca_cert_path=ca_cert,
                    cache_ttl=args.cache_ttl,
                    log_file=args.log_file
                )

                server.start()

            except KeyboardInterrupt:
                print("\nOCSP Responder stopped")
                sys.exit(0)
            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)

        else:
            print("Unknown ocsp command. Available: issue-ocsp-cert, serve", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()