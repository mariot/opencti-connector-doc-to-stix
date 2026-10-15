"""The enrichment logic: what is sent back for a container and for an entity."""

import pycti
from doc2stix.compact import parse

from connector.enrich import enrichment_objects

EXTRACTION = {
    "entities": [
        {"type": "intrusion-set", "name": "APT 29", "aliases": ["Cozy Bear"]},
        {"type": "attack-pattern", "name": "PowerShell", "mitre_id": "T1059.001"},
        {"type": "malware", "name": "GraphicalProton"},
        {"type": "sector", "name": "Government"},
        {"type": "vulnerability", "name": "CVE-2023-42793"},
    ],
    "observables": [
        {"type": "domain-name", "value": "poetpages[.]com", "indicates": ["APT 29"]},
        {"type": "ipv4-addr", "value": "198.51.100.7"},
    ],
    "relationships": [
        {"source": "APT 29", "type": "uses", "target": "T1059.001"},
        {"source": "APT 29", "type": "uses", "target": "GraphicalProton"},
        {"source": "APT 29", "type": "targets", "target": "Government"},
    ],
}
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def report():
    return {
        "type": "report",
        "id": "report--11111111-1111-4111-8111-111111111111",
        "name": "SVR exploits TeamCity",
        "object_refs": ["identity--x"],
        "object_marking_refs": [TLP_AMBER],
    }


def intrusion_set(name="APT29", aliases=("Cozy Bear",)):
    return {
        "type": "intrusion-set",
        "id": pycti.IntrusionSet.generate_id(name),
        "name": name,
        "aliases": list(aliases),
    }


def test_container_gets_every_new_object_in_its_refs():
    r = enrichment_objects(report(), parse(EXTRACTION))
    entity = r.objects[0]
    ids = {o["id"] for o in r.objects[2:]}
    assert entity["id"] == report()["id"]
    assert "identity--x" in entity["object_refs"]  # what was there stays
    assert ids <= set(entity["object_refs"])
    assert r.added == len(ids)


def test_markings_of_the_entity_go_to_new_objects():
    r = enrichment_objects(report(), parse(EXTRACTION))
    assert all(o.get("object_marking_refs") == [TLP_AMBER] for o in r.objects[2:])


def test_entity_named_in_the_document_receives_its_facts():
    entity = intrusion_set()
    r = enrichment_objects(entity, parse(EXTRACTION))
    assert (
        r.merged_into_entity
    )  # "APT 29" in the document = the APT29 enriched (aliases match too)
    assert not any(
        o["type"] == "intrusion-set" and o["id"] != entity["id"] for o in r.objects
    )
    uses = [
        o
        for o in r.objects
        if o["type"] == "relationship" and o["relationship_type"] == "uses"
    ]
    assert uses and all(o["source_ref"] == entity["id"] for o in uses)
    for o in uses:  # ids recomputed for the new source
        assert o["id"] == pycti.StixCoreRelationship.generate_id(
            "uses", o["source_ref"], o["target_ref"]
        )


def test_unlinked_objects_are_related_to_the_entity():
    entity = intrusion_set("Midnight Blizzard", ())
    r = enrichment_objects(entity, parse(EXTRACTION))
    assert not r.merged_into_entity
    rels = [o for o in r.objects if o["type"] == "relationship"]
    cve = next(o for o in r.objects if o["type"] == "vulnerability")
    assert any(
        o["source_ref"] == entity["id"] and o["target_ref"] == cve["id"] for o in rels
    )
    # the IP's indicator indicated nothing: it now indicates the entity
    ind = next(
        o
        for o in r.objects
        if o["type"] == "indicator" and "198.51.100.7" in o["pattern"]
    )
    assert any(
        o["relationship_type"] == "indicates"
        and o["source_ref"] == ind["id"]
        and o["target_ref"] == entity["id"]
        for o in rels
    )
