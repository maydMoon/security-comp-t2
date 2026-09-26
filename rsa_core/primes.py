"""Geração de números primos criptograficamente seguros e teste Miller-Rabin."""

import secrets
from rsa_core.math_utils import gcd


def _sieve_small_primes(limit: int = 2000) -> list[int]:
    """
    Gera lista de primos pequenos ímpares até o limite especificado para pré-filtragem rápida.
    """
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    for p in range(2, int(limit**0.5) + 1):
        if is_prime[p]:
            for multiple in range(p * p, limit + 1, p):
                is_prime[multiple] = False
    return [p for p, prime in enumerate(is_prime) if prime and p > 2]


_SMALL_PRIMES = tuple(_sieve_small_primes(2000))


def is_prime_miller_rabin(n: int, rounds: int = 64) -> bool:
    """
    Executa o teste probabilístico de primalidade de Miller-Rabin.

    Conforme especificações FIPS 186-5 e RFC 8017:
    - Para números ímpares n > 3, decompõe n - 1 = 2^s * d com d ímpar.
    - Realiza 'rounds' iterações independentes com bases aleatórias uniformes a in [2, n - 2].
    - Retorna True se n for provavelmente primo, False se for comprovadamente composto.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Decompor n - 1 em 2^s * d com d ímpar
    s = 0
    d = n - 1
    while d & 1 == 0:
        s += 1
        d >>= 1

    # Executar as rodadas com bases aleatórias uniformes
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def generate_prime(bits: int, e: int = 65537, rounds: int = 64) -> int:
    """
    Gera um número primo criptograficamente seguro com a quantidade especificada de bits.

    Atende às recomendações do NIST FIPS 186-5:
    1. Bit 0 fixado em 1 (garante número ímpar).
    2. Bits mais significativos (bits-1 e bits-2) fixados em 1 (garante magnitude adequada).
    3. Pré-filtragem por divisão com pequenos primos para alta performance.
    4. Garantia de que gcd(p - 1, e) == 1 para viabilidade do expoente RSA.
    5. Teste de Miller-Rabin com 64 rodadas (probabilidade de falso positivo < 2^-128).
    """
    if bits < 4:
        raise ValueError("O número de bits deve ser no mínimo 4.")

    while True:
        # Gera candidato aleatório usando CSPRNG
        cand = secrets.randbits(bits)
        # Fixa os dois bits mais altos e o bit menos significativo
        cand |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1

        # Pré-filtro rápido contra primos pequenos
        is_composite_small = False
        for p in _SMALL_PRIMES:
            if cand % p == 0 and cand != p:
                is_composite_small = True
                break

        if is_composite_small:
            continue

        # Condição de coprimalidade para chave RSA
        if gcd(cand - 1, e) != 1:
            continue

        # Teste probabilístico rigoroso
        if is_prime_miller_rabin(cand, rounds=rounds):
            return cand
