"""End-to-end check against a running OpenCTI with the connector running.

Creates a report and an intrusion set, attaches the same document to both, asks
the connector to enrich each, waits for the work to finish, and prints what
OpenCTI holds afterwards.

    OPENCTI_URL=http://localhost:8088 OPENCTI_TOKEN=... CONNECTOR_ID=... \\
      python tests/e2e.py path/to/report.pdf "APT29"
"""

import os
import sys
import time
from pathlib import Path

from pycti import OpenCTIApiClient


def wait_for_work(api, entity_id: str, timeout: int = 1800) -> str:
    start = time.time()
    while time.time() - start < timeout:
        works = api.query(
            """query W($id: Any!) { works(filters: {mode: and, filterGroups: [],
               filters: [{key: "event_source_id", values: [$id]}]}) {
               edges { node { status messages { message } errors { message } } } } }""",
            {"id": entity_id},
        )["data"]["works"]["edges"]
        done = [w["node"] for w in works if w["node"]["status"] == "complete"]
        if done:
            node = done[0]
            msgs = [m["message"] for m in node["messages"] or []]
            errs = [e["message"] for e in node["errors"] or []]
            return f"messages={msgs} errors={errs}"
        time.sleep(10)
    return "timeout"


def main() -> None:
    doc, actor = Path(sys.argv[1]), sys.argv[2]
    api = OpenCTIApiClient(
        os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"], log_level="error"
    )
    connector_id = os.environ["CONNECTOR_ID"]
    stamp = time.strftime("%H%M%S")
    report = api.report.create(
        name=f"doc-to-stix e2e {stamp}",
        published="2024-06-19T00:00:00Z",
        report_types=["threat-report"],
    )
    iset = api.intrusion_set.create(name=actor)
    for entity in (report, iset):
        api.stix_domain_object.add_file(id=entity["id"], file_name=str(doc))
        api.stix_core_object.ask_enrichment(
            element_id=entity["id"], connector_id=connector_id
        )
    print("report:", wait_for_work(api, report["id"]))
    print("intrusion set:", wait_for_work(api, iset["id"]))
    time.sleep(20)  # the worker imports the bundle after the work completes
    r = api.report.read(id=report["id"])
    kinds = {}
    for o in r.get("objects") or []:
        kinds[o["entity_type"]] = kinds.get(o["entity_type"], 0) + 1
    print(f"report now holds {len(r.get('objectsIds') or [])} objects: {kinds}")
    rels = api.stix_core_relationship.list(fromId=iset["id"], first=500)
    by = {}
    for x in rels:
        key = f"{x['relationship_type']} {x['to']['entity_type']}"
        by[key] = by.get(key, 0) + 1
    print(f"{actor} now has {len(rels)} relationships: {by}")


if __name__ == "__main__":
    main()
