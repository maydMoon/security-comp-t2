# Convenções - Parte I
## Interface das chaves RSA

As chaves são exportadas em arquivos JSON codificados em UTF-8. Os blocos abaixo são modelos: os valores entre `< >` são substituídos na exportação.

`modulus_bits` é um número inteiro, sem aspas, igual a `bit_length(n)` e deve ser maior ou igual a 2048.

## Representação dos inteiros

Cada campo `<hex>` é uma string hexadecimal em minúsculas, sem prefixo `0x` e sem espaços. A string tem sempre um número par de dígitos; cada par representa um byte, em ordem big-endian.

- `n` e `d` ocupam exatamente `k = ceil(modulus_bits / 8)` bytes, com zeros à esquerda quando necessário.
- `e`, `p`, `q`, `dp`, `dq` e `qInv` ocupam o menor número possível de bytes, sem padding.

Exemplos: `43981` em dois bytes é `"abcd"`; `65537` em tamanho mínimo é `"010001"`.

## Chave pública

```text
{
  "algorithm": "RSA",
  "modulus_bits": <bit_length(n)>,
  "n": "<hex>",
  "e": "<hex>"
}
```

## Chave privada

```text
{
  "algorithm": "RSA",
  "modulus_bits": <bit_length(n)>,
  "n": "<hex>",
  "e": "<hex>",
  "d": "<hex>",
  "p": "<hex>",
  "q": "<hex>",
  "dp": "<hex>",
  "dq": "<hex>",
  "qInv": "<hex>"
}
```

Os parâmetros CRT são `dp = d mod (p - 1)`, `dq = d mod (q - 1)` e `qInv = q⁻¹ mod p`.

## Funções e Interfaces do Pacote rsa_core

O pacote `rsa_core` fornece os seguintes componentes para a implementação do esquema RSA-OAEP:

- **Primitivas Criptográficas**:
  - `RSAPublicKey.rsa_ep(m: int) -> int`: Operação pública $c = m^e \pmod n$ para cifrar o bloco representativo $m = \text{OS2IP}(EM)$.
  - `RSAPrivateKey.rsa_dp(c: int) -> int`: Operação privada $m = c^d \pmod n$ acelerada por CRT para recuperar $m$ a partir do ciphertext $c$.
- **Dimensões do Bloco**:
  - `key.modulus_bits` e `key.n`: Para calcular o tamanho do bloco $k = \lceil \text{modulus\_bits} / 8 \rceil$ e o limite máximo de mensagem ($k - 2 \cdot \text{hLen} - 2$).
- **Importação de Chaves**:
  - `import_public_key(data)` / `import_public_key_file(filepath)`: Carrega a chave pública para cifragem.
  - `import_private_key(data)` / `import_private_key_file(filepath)`: Carrega e valida a consistência da chave privada para decifragem.
- **Utilitários e Tratamento de Erros**:
  - `int_to_hex(val, exact_bytes)` / `hex_to_int(hex_str, exact_bytes)`: Conversão entre inteiros e formato hexadecimal padronizado.
  - `RSAError`: Exceção base para reportar falhas de verificação de padding e decodificação de forma segura.

