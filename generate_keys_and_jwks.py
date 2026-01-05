import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(value: int) -> str:
    """Encode an integer using URL-safe base64 without padding."""
    byte_length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode("ascii")


def main() -> None:
    # Generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Write private key to PEM (PKCS8, unencrypted)
    pem_path = Path("ecw_private_key.pem")
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path.write_bytes(pem_bytes)

    # Build JWKS payload
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS384",
        "kid": "ecw-key-1",
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }
    jwks = {"keys": [jwk]}

    jwks_path = Path("jwks.json")
    jwks_path.write_text(json.dumps(jwks, indent=2))

    print(f"Saved private key: {pem_path.resolve()}")
    print(f"Saved JWKS: {jwks_path.resolve()}")


if __name__ == "__main__":
    main()