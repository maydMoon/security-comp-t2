"""Utilitários matemáticos para aritmética modular e teoria dos números."""


def gcd(a: int, b: int) -> int:
    """
    Calcula o Máximo Divisor Comum (MDC) entre a e b utilizando o algoritmo de Euclides.
    """
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Executa o Algoritmo Estendido de Euclides.

    Retorna uma tupla (g, x, y) tal que:
        a * x + b * y = g = gcd(a, b)
    com g >= 0.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if old_r < 0:
        return -old_r, -old_s, -old_t

    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """
    Calcula o inverso multiplicativo modular de 'a' em relação ao módulo 'm'.

    Retorna um valor x no intervalo [0, m - 1] tal que:
        (a * x) % m == 1

    Levanta ValueError caso a e m não sejam coprimos ou m <= 1.
    """
    if m <= 1:
        raise ValueError(f"O módulo deve ser maior que 1. Valor recebido: {m}")

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Inverso modular indefinido: {a} e {m} não são coprimos (mdc={g})")

    return x % m
