"""Modelos de chave RSA, primitivas com CRT e gerador de par de chaves."""

from dataclasses import dataclass
from rsa_core.exceptions import InvalidKeyError, KeyLengthError
from rsa_core.math_utils import gcd, mod_inverse
from rsa_core.primes import generate_prime


@dataclass(frozen=True)
class RSAPublicKey:
    """
    Representação da chave pública RSA.

    Parâmetros:
    - n: Módulo RSA (produto dos primos p e q).
    - e: Expoente público (comumente 65537).
    - modulus_bits: bit_length(n), deve ser maior ou igual a 2048.
    """
    n: int
    e: int
    modulus_bits: int

    def __post_init__(self) -> None:
        if self.modulus_bits < 2048:
            raise KeyLengthError(
                f"modulus_bits deve ser no mínimo 2048. Valor recebido: {self.modulus_bits}"
            )
        if self.n.bit_length() != self.modulus_bits:
            raise KeyLengthError(
                f"modulus_bits ({self.modulus_bits}) não coincide com n.bit_length() ({self.n.bit_length()})"
            )
        if self.e <= 1 or self.e % 2 == 0:
            raise InvalidKeyError(f"Expoente público 'e' inválido: {self.e}")

    def rsa_ep(self, m: int) -> int:
        """
        Primitiva pública RSA (RFC 8017 / PKCS #1 v2.2):
            c = m^e mod n
        """
        if not (0 <= m < self.n):
            raise ValueError("O inteiro representativo 'm' deve estar no intervalo [0, n - 1].")
        return pow(m, self.e, self.n)


@dataclass(frozen=True)
class RSAPrivateKey:
    """
    Representação da chave privada RSA com parâmetros CRT (Teorema do Resto Chinês).

    Parâmetros:
    - n: Módulo RSA.
    - e: Expoente público.
    - d: Expoente privado.
    - p, q: Fatores primos de n (convenção p > q).
    - dp: d mod (p - 1).
    - dq: d mod (q - 1).
    - qInv: q^(-1) mod p.
    - modulus_bits: bit_length(n), deve ser maior ou igual a 2048.
    """
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qInv: int
    modulus_bits: int

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """
        Valida a coerência matemática de todos os parâmetros da chave privada.
        """
        if self.modulus_bits < 2048:
            raise KeyLengthError(
                f"modulus_bits deve ser no mínimo 2048. Valor recebido: {self.modulus_bits}"
            )
        if self.n.bit_length() != self.modulus_bits:
            raise KeyLengthError(
                f"modulus_bits ({self.modulus_bits}) não coincide com n.bit_length() ({self.n.bit_length()})"
            )
        if self.p * self.q != self.n:
            raise InvalidKeyError("Inconsistência nos fatores primos: p * q != n.")
        if self.p <= self.q:
            raise InvalidKeyError("Por convenção RFC 8017, p deve ser estritamente maior que q.")

        phi = (self.p - 1) * (self.q - 1)
        lambda_n = phi // gcd(self.p - 1, self.q - 1)
        if (self.e * self.d) % phi != 1 and (self.e * self.d) % lambda_n != 1:
            raise InvalidKeyError("Inconsistência entre e e d: (e * d) mod phi(n) != 1.")

        if self.dp != self.d % (self.p - 1):
            raise InvalidKeyError("Parâmetro CRT dp inconsistente com d mod (p - 1).")
        if self.dq != self.d % (self.q - 1):
            raise InvalidKeyError("Parâmetro CRT dq inconsistente com d mod (q - 1).")
        if (self.q * self.qInv) % self.p != 1:
            raise InvalidKeyError("Parâmetro CRT qInv inconsistente com q^-1 mod p.")

    def get_public_key(self) -> RSAPublicKey:
        """Extrai o par de chave pública correspondente."""
        return RSAPublicKey(n=self.n, e=self.e, modulus_bits=self.modulus_bits)

    def rsa_dp(self, c: int) -> int:
        """
        Primitiva privada RSA utilizando o algoritmo de Garner para aceleração por CRT:
            m1 = c^dp mod p
            m2 = c^dq mod q
            h = (qInv * (m1 - m2)) mod p
            m = m2 + h * q
        """
        if not (0 <= c < self.n):
            raise ValueError("O inteiro representativo 'c' deve estar no intervalo [0, n - 1].")

        m1 = pow(c, self.dp, self.p)
        m2 = pow(c, self.dq, self.q)
        h = (self.qInv * (m1 - m2)) % self.p
        return m2 + h * self.q


def generate_key_pair(modulus_bits: int = 2048, e: int = 65537) -> RSAPrivateKey:
    """
    Gera um par de chaves RSA com módulo de no mínimo 2048 bits.

    Atende às recomendações do NIST SP 800-56B Rev. 2 e FIPS 186-5:
    - modulus_bits >= 2048 (default: 2048).
    - Primos p e q gerados com modulus_bits // 2 bits via Miller-Rabin.
    - Proteção contra fatoração de Fermat: |p - q| > 2^(prime_bits - 100).
    - Ordenação canônica p > q.
    - Cálculo de d, dp, dq e qInv.
    """
    if modulus_bits < 2048:
        raise KeyLengthError(
            f"O tamanho do módulo deve ser de no mínimo 2048 bits. Solicitado: {modulus_bits}"
        )

    prime_bits = modulus_bits // 2
    fermat_diff_limit = 1 << (prime_bits - 100)

    while True:
        p = generate_prime(prime_bits, e=e)
        while True:
            q = generate_prime(prime_bits, e=e)
            if p != q and abs(p - q) > fermat_diff_limit:
                break

        # Convenção canônica: p > q
        if p < q:
            p, q = q, p

        n = p * q
        if n.bit_length() == modulus_bits:
            break

    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qInv = mod_inverse(q, p)

    return RSAPrivateKey(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=dp,
        dq=dq,
        qInv=qInv,
        modulus_bits=modulus_bits,
    )
