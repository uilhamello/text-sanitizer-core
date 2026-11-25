# text-sanitizer-core

[![test](https://github.com/uilhamello/text-sanitizer-core/actions/workflows/test.yml/badge.svg)](https://github.com/uilhamello/text-sanitizer-core/actions/workflows/test.yml)

**Motor de mascaramento de dados pessoais e segredos em texto livre, com as regras que não
dependem de país.** As regras de cada país vêm em pacotes de região, como o
[text-sanitizer-br](https://github.com/uilhamello/text-sanitizer-br), que se plugam no core.
Offline e sem dependências.

Não é um sanitizador de HTML (contra XSS). É mascaramento de PII.

## Quando usar este pacote direto

Quase nunca: instale a região (`text-sanitizer-br`), que já traz o core. Use o core direto para
escrever uma região nova ou para montar várias regiões de uma vez:

```python
from text_sanitizer_core import build

s = build(["br", "eu"], ner=True)   # uma passada: core + regras de cada região
clean, report = s.sanitize(texto)    # report.masks (dict), report.blocked (list)
```

`build([])` usa só as regras do core.

## O que o core faz

| Ação | Alvo |
|---|---|
| **Mascara** | e-mail (também ofuscado: `[at]`, `%40`, "fulano at example dot com", sem TLD como `nome.sobrenome@intranet`), cartão (Luhn), IP, UUID, JWT, `Bearer`, tokens com prefixo conhecido (Slack, GitHub, Anthropic/OpenAI, Stripe, Google), `senha=`/`token=` (também em JSON e texto corrido), credencial e query string em URL, hex longo, IP com hífen em hostname (`ip-10-0-0-5.ec2.internal`), número de 6+ dígitos, `*_id=`/`userId=`/`uid=`, login (`login=`, `username:`, `@first.last`); nomes de pessoas com o modelo da região |
| **Bloqueia** | chave AWS, chave de service account GCP, PEM, connection string, string de alta entropia, `@` residual, texto acima de `max_chars`, região ou modelo de nomes ausente |

## Limites

- E-mail por extenso só é pego com TLD conhecido depois de "dot" (com, br, net, org, io...).
  Efeito colateral aceito: "look at this dot com" vira `<EMAIL>`.
- E-mail sem TLD exige ponto ou sublinhado no usuário (`nome.sobrenome@host`); `root@localhost` passa.
- Regex não substitui minimização: não leve o dado pessoal se não precisar dele.

## Escrever uma região

Uma região é um objeto `Region` registrado no grupo de entry points `text_sanitizers`:

```python
# text_sanitizer_eu/__init__.py
from text_sanitizer_core import Region

REGION = Region("eu", masks=[("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "<IBAN>")],
                ner_model="xx_ent_wiki_sm")
```

```toml
# pyproject.toml da região
[project.entry-points.text_sanitizers]
eu = "text_sanitizer_eu:REGION"
```

As máscaras da região rodam **entre** as do core: depois de segredos e e-mail, antes das regras
genéricas de número e IP, que senão comeriam pedaços de um documento.

**Fail secure:** região pedida e não instalada, região que falha ao carregar ou `ner=True` sem
modelo bloqueiam toda chamada. Nunca seguem sem a regra em silêncio.

## Desenvolvimento

```bash
git clone https://github.com/uilhamello/text-sanitizer-core.git && cd text-sanitizer-core
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Licença MIT.
