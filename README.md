# Assinatura Digital e Verificação Segura de Arquivos (RSA-OAEP e RSA-PSS)

CIC0201 – Segurança Computacional – 2026/2 · Trabalho de Implementação 2

<!-- **Grupo:** <<NOMES E MATRÍCULAS DOS 4 INTEGRANTES>> -->

Implementação, em Python, dos componentes de um sistema de assinatura digital baseado em RSA: geração de chaves com Miller-Rabin, cifragem RSA-OAEP, assinatura RSA-PSS, verificação e testes de adulteração. Tudo com SHA3-256. As primitivas RSA, o OAEP, o MGF1 e o PSS são implementados aqui, sem OpenSSL nem bibliotecas equivalentes.

## Requisitos

- Python 3.10 ou superior.
- Nenhuma dependência externa para o sistema (o SHA3-256 vem do `hashlib`).
- `cryptography` **somente** para o teste de interoperabilidade: `pip install cryptography`.

## Estrutura

```
rsa_core/      Parte I    Miller-Rabin, geração de chaves, CRT, importação/exportação (JSON)
rsa_oaep/      Parte II   RSA-OAEP, MGF1, I2OSP/OS2IP
rsa_pss/       Parte III   RSA-PSS e assinatura/verificação
integrity/     Parte IV   envelope, demonstração e testes de integridade
tests/                    testes de unidade para os demais componentes
docs/                     detalhes de implementação e análise de segurança
```

## Como executar

Sempre a partir da raiz do repositório.

**Testes**

```bash
python -m unittest discover -s integrity -p integrity_tests.py -v
```

**Demonstração guiada** (pausa entre as etapas; use `--no-pause` para rodar direto)

```bash
python -m integrity.integrity_demo
```

Na primeira execução a demo gera dois pares de chaves de 2048 bits, o que pode levar de alguns segundos a mais de um minuto. Elas ficam em `integrity/.demo_keys/`, diretório ignorado pelo Git, e são reutilizadas depois. Não têm proteção por senha: servem só para a demonstração.

**Uso em código**

```python
from rsa_core import generate_key_pair, export_private_key_file, export_public_key_file
from rsa_oaep import encrypt, decrypt
from rsa_pss import sign, verify

priv = generate_key_pair()                       # 2048 bits
pub = priv.get_public_key()
export_private_key_file(priv, "priv.json")
export_public_key_file(pub, "pub.json")

ct = encrypt(pub, b"mensagem curta")             # RSA-OAEP (máx. 190 bytes com 2048 bits)
assert decrypt(priv, ct) == b"mensagem curta"

content = b"conteudo do arquivo"
signature = sign(priv, content)                  # RSA-PSS: assinatura binária de k bytes
print("ARQUIVO ÍNTEGRO" if verify(pub, content, signature) else "ASSINATURA INVÁLIDA")
```

## Formatos

**Chaves** (JSON UTF-8, inteiros em hexadecimal minúsculo, big-endian):

```json
{ "algorithm": "RSA", "modulus_bits": 2048, "n": "<hex>", "e": "010001" }
```

A chave privada acrescenta `d`, `p`, `q`, `dp`, `dq` e `qInv`.

**Documento assinado** (JSON UTF-8):

```json
{
  "format": "<<VALOR REAL DO CAMPO format>>",
  "content": "<arquivo em Base64>",
  "signature": "<assinatura RSA-PSS em Base64>"
}
```

Convenções completas de tamanho e de representação em [`docs/implementacao.md`](docs/implementacao.md).
O envelope JSON acima é usado pela demonstração; a API `rsa_pss` recebe mensagem e assinatura em bytes por `sign(priv, message)` e `verify(pub, message, signature)`.

## Onde está cada item do enunciado

| Parte | O que pede | Onde | Como conferir |
|---|---|---|---|
| I | Miller-Rabin, chaves ≥ 2048 bits, import/export | `rsa_core/` | `tests/` · demo, etapa 2 |
| II | RSA-OAEP com SHA3-256, MGF1, detecção de erro | `rsa_oaep/` | `tests/` |
| III | RSA-PSS (salt, MGF1), assinatura em Base64 | `rsa_pss/` | `tests/` · demo, etapas 3 e 8 |
| IV | Parsing, verificação, adulteração (a), (b), (c) | `examples/`, `tests/` | `tests/` · demo, etapas 5 a 10 |
| V | Análise de segurança | [`docs/analise_seguranca.md`](docs/analise_seguranca.md) | leitura |
| — | Interoperabilidade (teste adicional) | <<CAMINHO DO TESTE>> | <<COMANDO>> |

## Decisões de projeto

- `e = 65537`; primos de 1024 bits com os dois bits mais altos fixados (o módulo tem sempre 2048 bits), `p > q` e `|p − q|` grande, para se proteger da fatoração de Fermat.
- Miller-Rabin com 64 rodadas e bases aleatórias, depois de um pré-filtro por primos pequenos. Aleatoriedade sempre via `secrets`.
- Operação privada com CRT (`dp`, `dq`, `qInv`).
- OAEP: uma única exceção genérica (`DecryptionError`) para qualquer falha, para não criar um oráculo de padding (ataque de Manger); varredura completa do bloco, `hmac.compare_digest` para `lHash`, blinding na operação privada e conferência de `m^e mod n == c` (protege contra falha no CRT).
- PSS: salt de 32 bytes, então assinar duas vezes o mesmo arquivo gera assinaturas diferentes, ambas válidas.
- `verify(pub, message, signature)` verifica a assinatura PSS sobre bytes. O parser do envelope e a contenção de erros de entrada são helpers locais da demonstração.

## Testes de adulteração

Cada teste altera uma única coisa e espera `False`: (a) um byte do arquivo, (b) um byte da assinatura, (c) a chave pública (outro par e módulo alterado). Há também entradas inválidas (vazio, não-JSON, campos ausentes, Base64 inválido, assinatura truncada) e a verificação de que o salt gera assinaturas distintas. Nos testes (a) e (b) o envelope adulterado continua bem formado, então quem rejeita é a verificação RSA-PSS, e não um erro de parsing.

## Limitações

O projeto é didático. Python e suas operações com inteiros grandes não garantem execução em tempo constante, então a proteção contra ataques de temporização é apenas uma redução de risco. As chaves privadas ficam em arquivos JSON sem criptografia, e não há certificado: a chave pública precisa ser obtida por um canal confiável.