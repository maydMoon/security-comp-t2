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


# Parte II - RSA-OAEP

Pacote `rsa_oaep`, implementação de RSAES-OAEP (RFC 8017, Seção 7.1) sobre as chaves do `rsa_core`, com SHA3-256 como hash do OAEP e do MGF1.

## API

```python
from rsa_core import generate_key_pair
from rsa_oaep import encrypt, decrypt

priv = generate_key_pair()
ct = encrypt(priv.get_public_key(), b"mensagem", label=b"")   # k bytes
pt = decrypt(priv, ct, label=b"")
```

- `encrypt(pub, message, label=b"", hash_factory=hashlib.sha3_256) -> bytes`: ciphertext com exatamente `k = ceil(modulus_bits / 8)` bytes.
- `decrypt(priv, ciphertext, label=b"", hash_factory=hashlib.sha3_256) -> bytes`: devolve a mensagem ou lança `DecryptionError`.
- `max_message_length(k, hash_factory)`: `k - 2*hLen - 2`.
- `eme_oaep_encode(message, k, label, hash_factory, seed=None)` / `eme_oaep_decode(em, k, label, hash_factory)`: codificação EME-OAEP isolada (`seed` permite fixar a seed; se omitida, é gerada com `secrets`).
- `mgf1(seed, mask_len, hash_factory)`: MGF1 (RFC 8017, B.2.1).
- `DecryptionError`, `MessageTooLongError`: ambas derivam de `RSAError`.

Chave de tipo errado, ou `message`/`label`/`ciphertext` que não sejam `bytes`/`bytearray`, geram `TypeError`.

## Formato do bloco

```text
DB = lHash || PS || 0x01 || M               (k - hLen - 1 bytes)
maskedDB   = DB   xor MGF1(seed, k - hLen - 1)
maskedSeed = seed xor MGF1(maskedDB, hLen)
EM = 0x00 || maskedSeed || maskedDB         (k bytes)
```

`lHash = SHA3-256(label)`, `PS` são zeros e `seed` tem `hLen = 32` bytes aleatórios (`secrets`). O ciphertext é `I2OSP(OS2IP(EM)^e mod n, k)`.

## Erro único de decifragem

Qualquer falha na decifragem (tamanho errado, `c >= n`, byte inicial diferente de zero, `lHash` divergente, separador `0x01` ausente, lixo no `PS`) lança a mesma `DecryptionError("decryption error")`. Se o atacante distinguisse as causas, teria um oráculo de padding capaz de recuperar o texto claro com consultas adaptativas (ataque de Manger). Pelo mesmo motivo a verificação do bloco não sai cedo: a busca pelo separador percorre o `DB` inteiro, `lHash` é comparado com `hmac.compare_digest` e as condições são combinadas numa flag só. A operação privada usa blinding e confere `m^e mod n == c` antes de decodificar.

## Limite de mensagem

Com módulo de 2048 bits, `k = 256` e `hLen = 32`, logo o máximo é `256 - 2*32 - 2 = 190` bytes. Mensagens maiores geram `MessageTooLongError`.
