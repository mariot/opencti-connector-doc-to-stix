# OpenCTI connector: Doc to STIX

An **internal enrichment** connector. Pick an entity that has a document
attached (a report and its PDF, an intrusion set and an advisory about it), run
the enrichment, and the connector reads the document and adds what it states:

- intrusion sets, threat actors, campaigns, malware, tools;
- MITRE ATT&CK techniques (Enterprise, Mobile, ICS; old IDs mapped to current ones);
- CVEs, targeted sectors, countries and regions (OpenCTI's own reference names);
- indicators (STIX patterns) and observables;
- the relationships between them, only those OpenCTI accepts.

The extraction is [doc-to-stix](https://github.com/mariot/doc-to-stix): a
language model reads the text chunk by chunk under fixed rules, literal IDs and
IOCs are harvested by patterns, and a deterministic builder writes the STIX
with OpenCTI's deterministic IDs. Its eval set, scores and training log are in
that repository.

## What the enrichment does

| enriched entity | result |
|---|---|
| Report, Grouping, Case (incident, RFI, RFT) | every extracted object is added to the container |
| Intrusion set, threat actor, campaign, malware, tool, incident | if the document names the entity (name or alias), the extracted copy *is* the entity: "APT29 uses T1059.001" lands on your APT29. Objects left unlinked are related to the entity; indicators tied to nothing indicate it |

- Markings: every created object gets the entity's markings (what comes out of
  a TLP:AMBER document is TLP:AMBER).
- `max_tlp`: an entity marked above it is refused: its files are never sent to
  the model. With a local model nothing leaves your network anyway.
- Files: PDF, HTML, text, Markdown; the most recent first, `max_files` per run.
- Playbooks: the bundle always contains the enriched entity.
- Existing facts: OpenCTI merges an incoming relationship into an existing one
  with the same type and ends (ATT&CK's own "uses", say) without recording the
  incoming ID, so a container would lose that reference. For containers the
  connector looks those relationships up and references them too.
- Names: OpenCTI resolves an incoming name through the aliases of existing
  entities ("UNC1878" lands on FIN12 if FIN12 lists it), even where the
  document keeps them apart.

Tested end to end on OpenCTI 7.261008.0 (`tests/e2e.py`): a CERT-FR report on
Nobelium attached to a new report added 49 objects to it; attached to the
existing ATT&CK APT29 (which lists NOBELIUM as an alias), the facts landed on
APT29 (uses Cobalt Strike and Brute Ratel C4, targets France, Ukraine,
Diplomacy, indicators that indicate it).

## Model

- **Ollama** (default): `qwen3:30b-a3b`, the most accurate local model measured
  on doc-to-stix's 22-document gold set: **0.723** (entities F1 0.82,
  relationships 0.47, observables 0.88). A fine-tuned Qwen3-8B (LoRA v2b,
  distilled from it) scores 0.646 with a third of the memory; it is not
  published yet. Needs a 32k context (`OLLAMA_CONTEXT_LENGTH=32768`).
  Extraction takes a few minutes per document on a laptop-class GPU, which is
  why `auto` is off.
- **Claude**: set `DOC_TO_STIX_ANTHROPIC_API_KEY` and a Claude model name.

## Configuration

| parameter | env | default |
|---|---|---|
| `connector.scope` | `CONNECTOR_SCOPE` | Report, Grouping, Case-Incident, Case-Rfi, Case-Rft, Intrusion-Set, Threat-Actor-Group, Campaign, Malware, Tool, Incident |
| `connector.auto` | `CONNECTOR_AUTO` | false |
| `connector.max_tlp` | `CONNECTOR_MAX_TLP` | TLP:AMBER |
| `doc_to_stix.model` | `DOC_TO_STIX_MODEL` | qwen3:30b-a3b |
| `doc_to_stix.ollama_url` | `DOC_TO_STIX_OLLAMA_URL` | http://ollama:11434 |
| `doc_to_stix.anthropic_api_key` | `DOC_TO_STIX_ANTHROPIC_API_KEY` | (empty: Ollama) |
| `doc_to_stix.author` | `DOC_TO_STIX_AUTHOR` | doc-to-stix |
| `doc_to_stix.max_files` | `DOC_TO_STIX_MAX_FILES` | 1 |

## Run

Docker: `docker compose up -d` with the variables of `docker-compose.yml`.

Locally, against the OpenCTI of doc-to-stix (`infra/opencti`):

```
uv venv -p 3.12 && uv pip install -r src/requirements.txt pytest
cp config.yml.sample src/config.yml   # set the token, a connector UUID, ollama_url
MQ_HOST=localhost .venv/bin/python src/main.py
```

`MQ_HOST` points the connector at RabbitMQ when OpenCTI announces a host name
only its own Docker network resolves.

## Tests

```
.venv/bin/python -m pytest tests           # enrichment logic, no OpenCTI needed
python tests/e2e.py report.pdf APT29       # against a running OpenCTI + connector
```
