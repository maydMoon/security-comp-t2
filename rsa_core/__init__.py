"""Pacote rsa_core para geração e gerenciamento de chaves RSA."""

from rsa_core.exceptions import (
    RSAError,
    InvalidKeyError,
    KeyLengthError,
    SerializationError,
    InvalidHexError,
)
from rsa_core.math_utils import gcd, extended_gcd, mod_inverse
from rsa_core.primes import is_prime_miller_rabin, generate_prime
from rsa_core.keys import RSAPublicKey, RSAPrivateKey, generate_key_pair
from rsa_core.serialization import (
    int_to_hex,
    hex_to_int,
    export_public_key,
    export_public_key_file,
    export_private_key,
    export_private_key_file,
    import_public_key,
    import_public_key_file,
    import_private_key,
    import_private_key_file,
)

__all__ = [
    # Exceções
    "RSAError",
    "InvalidKeyError",
    "KeyLengthError",
    "SerializationError",
    "InvalidHexError",
    # Aritmética e Primalidade
    "gcd",
    "extended_gcd",
    "mod_inverse",
    "is_prime_miller_rabin",
    "generate_prime",
    # Modelos e Geração
    "RSAPublicKey",
    "RSAPrivateKey",
    "generate_key_pair",
    # Serialização e Deserialização
    "int_to_hex",
    "hex_to_int",
    "export_public_key",
    "export_public_key_file",
    "export_private_key",
    "export_private_key_file",
    "import_public_key",
    "import_public_key_file",
    "import_private_key",
    "import_private_key_file",
]
