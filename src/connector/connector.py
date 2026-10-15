"""Doc to STIX: enrich an OpenCTI entity with what its attached document says.

The user picks an entity that has a file (a report and its PDF, an intrusion set
and an advisory about it) and runs the enrichment. The connector reads the file,
extracts threat actors, malware, tools, ATT&CK techniques, CVEs, targeted
sectors and countries, IOCs and the relationships between them (doc2stix), and
sends them back tied to the entity (enrich.py).
"""

import mimetypes
import tempfile
from pathlib import Path

from doc2stix import compact
from doc2stix.engine import AnthropicBackend, Engine, OllamaBackend
from doc2stix.extract import document_text
from pycti import OpenCTIConnectorHelper

from connector.enrich import enrichment_objects
from connector.settings import ConnectorSettings


class DocToStixConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        cfg = config.doc_to_stix
        if cfg.anthropic_api_key:
            import os

            os.environ.setdefault("ANTHROPIC_API_KEY", cfg.anthropic_api_key)
            backend = AnthropicBackend(cfg.model, None)
        else:
            backend = OllamaBackend(cfg.model, cfg.ollama_url)
        self.engine = Engine(backend)

    # -- OpenCTI plumbing ------------------------------------------------------

    def check_max_tlp(self, opencti_entity: dict) -> None:
        tlp = "TLP:CLEAR"
        for marking in opencti_entity.get("objectMarking") or []:
            if marking["definition_type"] == "TLP":
                tlp = marking["definition"]
        max_tlp = (
            f"TLP:{self.config.connector.max_tlp.upper()}"  # the settings hold "amber"
        )
        if not self.helper.check_max_tlp(tlp, max_tlp):
            raise ValueError(
                f"The entity is marked {tlp}, above the connector's max TLP ({max_tlp}): "
                "its files are not sent to the model."
            )

    def documents(self, opencti_entity: dict) -> list[tuple[str, bytes]]:
        """The entity's attached files the connector reads, most recent first."""
        files = []
        for f in opencti_entity.get("importFiles") or []:
            mime = (f.get("metaData") or {}).get("mimetype") or mimetypes.guess_type(
                f["name"]
            )[0]
            if mime in self.config.doc_to_stix.mime_types:
                files.append(f)
        files.sort(key=lambda f: f.get("lastModified") or "", reverse=True)
        out = []
        for f in files[: self.config.doc_to_stix.max_files]:
            url = f"{self.helper.opencti_url}/storage/get/{f['id']}"
            out.append(
                (f["name"], self.helper.api.fetch_opencti_file(url, binary=True))
            )
        return out

    def existing_relationship_ids(self, objects: list[dict]) -> list[str]:
        """IDs of relationships OpenCTI already holds for the extracted facts.

        OpenCTI merges an incoming relationship into an existing one with the same
        type and ends (ATT&CK's own "uses", say) without recording the incoming
        ID, so a container's reference to that ID is dropped. Referencing the
        existing relationship keeps the fact in the container."""
        cache: dict[str, str | None] = {}

        def internal(stix_id: str) -> str | None:
            if stix_id not in cache:
                obj = self.helper.api.stix_core_object.read(id=stix_id)
                cache[stix_id] = obj["id"] if obj else None
            return cache[stix_id]

        found = []
        for o in objects:
            if o["type"] != "relationship" or o["relationship_type"] == "based-on":
                continue
            src, tgt = internal(o["source_ref"]), internal(o["target_ref"])
            if not src or not tgt:
                continue  # an end is new: the relationship cannot exist yet
            for rel in self.helper.api.stix_core_relationship.list(
                fromId=src,
                toId=tgt,
                relationship_type=[o["relationship_type"]],
                first=5,
            ):
                if rel["standard_id"] != o["id"]:
                    found.append(rel["standard_id"])
        return found

    # -- the enrichment --------------------------------------------------------

    def extract(self, name: str, content: bytes, title: str) -> compact.Extraction:
        suffix = Path(name).suffix or ".txt"
        with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
            tmp.write(content)
            tmp.flush()
            text = document_text(Path(tmp.name))
        raw = self.engine.extract(text, title=title)
        return compact.parse(raw)

    def process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        self.check_max_tlp(opencti_entity)
        docs = self.documents(opencti_entity)
        if not docs:
            if not data.get("event_type"):  # playbook: hand the bundle on unchanged
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(data["stix_objects"])
                )
            return "No attached document to read (PDF, HTML, text)."
        title = opencti_entity.get("name") or docs[0][0]
        objects: dict[str, dict] = {}
        added, merged = 0, False
        for name, content in docs:
            self.helper.connector_logger.info("[DOC-TO-STIX] reading", {"file": name})
            ex = self.extract(name, content, title)
            result = enrichment_objects(stix_entity, ex, self.config.doc_to_stix.author)
            stix_entity = result.objects[0]  # a container gathers refs across files
            for o in result.objects:
                objects[o["id"]] = o
            added += result.added
            merged |= result.merged_into_entity
            for d in result.dropped:
                self.helper.connector_logger.debug(
                    "[DOC-TO-STIX] dropped", {"reason": d}
                )
        if "object_refs" in stix_entity:
            extra = self.existing_relationship_ids(list(objects.values()))
            stix_entity["object_refs"] = list(
                dict.fromkeys(stix_entity["object_refs"] + extra)
            )
        objects[stix_entity["id"]] = stix_entity
        bundle = self.helper.stix2_create_bundle(list(objects.values()))
        self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        return f"{added} objects from {len(docs)} document(s)" + (
            " (the document names this entity: its facts are attached to it)"
            if merged
            else ""
        )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
