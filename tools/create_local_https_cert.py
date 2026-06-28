from __future__ import annotations

import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT_DIR = Path(__file__).resolve().parents[1]
TLS_DIR = ROOT_DIR / "security" / "local_tls"
DEFAULT_CERT_PATH = TLS_DIR / "localhost.crt"
DEFAULT_KEY_PATH = TLS_DIR / "localhost.key"
DEFAULT_DAYS = 397


def _restrict_owner_read(path: Path) -> None:
    """Restrict private-key permissions on POSIX hosts; Windows uses ACLs."""

    if os.name != "nt":
        path.chmod(0o600)


def ensure_local_https_cert(
    *,
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    force: bool = False,
    valid_days: int = DEFAULT_DAYS,
) -> tuple[Path, Path]:
    """Create a localhost-only self-signed certificate for Streamlit HTTPS.

    Args:
        cert_path: PEM certificate output path.
        key_path: PEM private-key output path.
        force: Replace existing cert/key when True.
        valid_days: Certificate validity window in days.

    Returns:
        Tuple of certificate path and private-key path.
    """

    if cert_path.exists() and key_path.exists() and not force:
        return cert_path, key_path

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JO"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DIFD Local Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _restrict_owner_read(key_path)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def main() -> None:
    """Create or rotate the local HTTPS certificate."""

    parser = argparse.ArgumentParser(description="Create a local HTTPS certificate for Streamlit.")
    parser.add_argument("--force", action="store_true", help="Replace the existing certificate and key.")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Certificate validity in days.")
    args = parser.parse_args()

    cert_path, key_path = ensure_local_https_cert(force=args.force, valid_days=args.days)
    print(f"Certificate: {cert_path}")
    print(f"Private key : {key_path}")
    print("Use run_app_https.py to launch Streamlit with these files.")


if __name__ == "__main__":
    main()
