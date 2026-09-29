# Detalhes de implementação

Referências: RFC 8017 (PKCS #1 v2.2), NIST FIPS 186-5, NIST FIPS 202.

## Parte I – Chaves RSA (`rsa_core`)

### Representação dos inteiros

Cada campo `<hex>` é uma string hexadecimal em minúsculas, sem prefixo `0x` e sem espaços, com número par de dígitos (cada par é um byte, big-endian).

- `n` e `d` ocupam exatamente `k = ceil(modulus_bits / 8)` bytes, com zeros à esquerda quando necessário.
- `e`, `p`, `q`, `dp`, `dq` e `qInv` ocupam o menor número possível de bytes, sem padding.

Exemplos: `43981` em dois bytes é `"abcd"`; `65537` em tamanho mínimo é `"010001"`.

### Chave pública

```json
{
  "algorithm": "RSA",
  "modulus_bits": 2048,
  "n": "<hex>",
  "e": "<hex>"
}
```

`modulus_bits` é um inteiro (sem aspas), igual a `bit_length(n)`, e deve ser ≥ 2048.

### Chave privada

```json
{
  "algorithm": "RSA",
  "modulus_bits": 2048,
  "n": "<hex>", "e": "<hex>", "d": "<hex>",
  "p": "<hex>", "q": "<hex>",
  "dp": "<hex>", "dq": "<hex>", "qInv": "<hex>"
}
```

Parâmetros CRT: `dp = d mod (p − 1)`, `dq = d mod (q − 1)`, `qInv = q⁻¹ mod p`. A importação valida a consistência da chave (`p·q = n`, `e·d ≡ 1`, `dp`, `dq`, `qInv`).

### Interfaces principais

- `generate_key_pair(modulus_bits=2048, e=65537) -> RSAPrivateKey`
- `RSAPublicKey.rsa_ep(m)`: `c = m^e mod n`
- `RSAPrivateKey.rsa_dp(c)`: `m = c^d mod n`, com CRT (algoritmo de Garner)
- `import_public_key(_file)`, `import_private_key(_file)`, `export_public_key(_file)`, `export_private_key(_file)`
- `RSAError`: exceção base do projeto

## Parte II – RSA-OAEP (`rsa_oaep`)

RSAES-OAEP (RFC 8017, seção 7.1) com SHA3-256 como hash e como base do MGF1.

```
lHash      = SHA3-256(label)                      (label vazio por padrão)
DB         = lHash || PS || 0x01 || M             (k − hLen − 1 bytes; PS = zeros)
seed       = hLen bytes aleatórios
maskedDB   = DB   xor MGF1(seed, k − hLen − 1)
maskedSeed = seed xor MGF1(maskedDB, hLen)
EM         = 0x00 || maskedSeed || maskedDB       (k bytes)
c          = I2OSP(OS2IP(EM)^e mod n, k)
```

- `encrypt(pub, message, label=b"", hash_factory=hashlib.sha3_256) -> bytes`
- `decrypt(priv, ciphertext, label=b"", hash_factory=hashlib.sha3_256) -> bytes` (lança `DecryptionError`)
- Limite da mensagem: `k − 2·hLen − 2`; com 2048 bits e SHA3-256, **190 bytes**. Acima disso, `MessageTooLongError`.
- Tipos errados geram `TypeError`.

**Erro único.** Qualquer falha na decifragem (tamanho errado, `c ≥ n`, byte inicial diferente de zero, `lHash` divergente, separador `0x01` ausente, lixo em `PS`) lança a mesma `DecryptionError("decryption error")`. Se o atacante pudesse distinguir as causas, teria um oráculo de padding capaz de recuperar o texto claro com consultas adaptativas (ataque de Manger). Por isso a verificação do bloco não sai cedo, `lHash` é comparado com `hmac.compare_digest` e as condições são combinadas numa só flag. A operação privada usa blinding e confere `m^e mod n == c` antes de decodificar.

## Parte III – RSA-PSS (`rsa_pss`)

RSASSA-PSS (RFC 8017, seções 8.1 e 9.1) com SHA3-256 e MGF1 sobre SHA3-256.

**Assinatura**

1. `mHash = SHA3-256(arquivo)`.
2. `emBits = modulus_bits − 1` e `emLen = ceil(emBits / 8)`.
3. `salt`: 32 bytes aleatórios (`secrets`).
4. `M' = 0x00 * 8 || mHash || salt` e `H = SHA3-256(M')`.
5. `DB = PS || 0x01 || salt`, com `PS` de zeros.
6. `maskedDB = DB xor MGF1(H, emLen − hLen − 1)`; os `8·emLen − emBits` bits mais à esquerda são zerados, para garantir `EM < n`.
7. `EM = maskedDB || H || 0xBC`.
8. `s = EM^d mod n` (`rsa_dp`), escrita em `k` bytes. `sign()` devolve esses bytes; a função auxiliar `sign_and_encode()` os codifica em **Base64**.

**Verificação**

1. `verify()` recebe a assinatura em bytes e confere que tem exatamente `k` bytes; em seguida, interpreta esses bytes como `s` e rejeita se `s ≥ n`. Para assinaturas em Base64, `decode_and_verify()` faz a decodificação antes de chamar `verify()`.
2. `EM = s^e mod n` (`rsa_ep`).
3. Confere o byte final `0xBC` e os bits zerados à esquerda de `maskedDB`.
4. Recupera `DB`, confere os zeros e o separador `0x01` e extrai o `salt`.
5. Recalcula `H'` com o `mHash` do arquivo recebido e o `salt` extraído; compara com `H` (`hmac.compare_digest`).

A verificação **não decifra um hash**: o verificador calcula `mHash` a partir do arquivo que recebeu, reconstrói `M'` e confere a consistência. Se o arquivo, o salt ou a assinatura tiverem sido alterados, `H'` não bate com `H`.

## Parte IV – Envelope e verificação

```json
{
  "format": "RSA-PSS-SHA3-256",
  "content": "<arquivo em Base64>",
  "signature": "<assinatura em Base64>"
}
```

- `format` identifica o esquema `RSA-PSS-SHA3-256`; valor diferente do esperado rejeita o documento.
- `parse_envelope()` valida e decodifica o Base64 da assinatura, mas não seu tamanho RSA. `decode_and_verify()` decodifica a assinatura e `verify()` exige exatamente `k` bytes e rejeita o representante `s` se `s ≥ n`.
- A API PSS recebe diretamente bytes: `sign(chave_privada, mensagem)` produz a assinatura, e `verify(chave_publica, mensagem, assinatura)` devolve `True` ou `False`.
- O envelope JSON é codificado, interpretado e verificado em `integrity/envelope.py`, pelas funções `encode_envelope`, `parse_envelope` e `verify_document`. A demo e os testes da Parte IV ficam agrupados em `integrity/`; os testes importam o módulo do envelope diretamente, sem depender da lógica de apresentação.

### Testes

| Teste | Alteração | Esperado |
|---|---|---|
| Controle | nenhuma | `True` |
| (a) arquivo | 1 byte do conteúdo | `False` |
| (b) assinatura | 1 byte da assinatura | `False` |
| (c) chave pública | chave de outro par; módulo `n` alterado | `False` |
| Entradas inválidas | vazio, não-JSON, campo ausente, Base64 inválido, assinatura truncada | `False`, sem exceção |
| Salt | assinar duas vezes o mesmo arquivo | assinaturas diferentes, ambas válidas |

### Interoperabilidade (teste adicional)

Uma assinatura produzida pelo grupo é verificada com a biblioteca `cryptography`, usando `PSS(mgf=MGF1(SHA3_256()), salt_length=32)` e `SHA3_256()`. A biblioteca é usada **somente** nesse teste, nunca na implementação. <<Indicar o arquivo e o comando.>>