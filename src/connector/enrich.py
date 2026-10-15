"""What the enrichment adds to the entity: pure functions, no OpenCTI calls.

The extraction (doc2stix compact format) becomes STIX objects (doc2stix.build),
then they are tied to the entity the user chose:

- a container (report, grouping, case): every new object goes into its
  object_refs, the way an analyst would file them in the report;
- any other entity (intrusion set, threat actor, campaign, malware, tool,
  incident): if the document names that entity (by its name or an alias), the
  extracted copy *is* the entity, so "APT29 uses T1059.001" lands on the APT29
  the user enriched; objects left unlinked are related to the entity, and
  indicators tied to nothing indicate it.

The entity's markings are copied to every new object: what comes out of a
TLP:AMBER document is TLP:AMBER.
"""

from dataclasses import dataclass

import pycti
from doc2stix import reference
from doc2stix.build import author_identity, build_objects, relationship
from doc2stix.compact import Extraction, family_type

CONTAINER_TYPES = {
    "report",
    "grouping",
    "case-incident",
    "case-rfi",
    "case-rft",
    "x-opencti-case-incident",
    "x-opencti-case-rfi",
    "x-opencti-case-rft",
}
# STIX type of the enriched entity -> (compact type, OpenCTI type)
ENTITY_TYPES = {
    "intrusion-set": ("intrusion-set", "Intrusion-Set"),
    "threat-actor": ("threat-actor", "Threat-Actor-Group"),
    "campaign": ("campaign", "Campaign"),
    "malware": ("malware", "Malware"),
    "tool": ("tool", "Tool"),
    "incident": (None, "Incident"),
}
SDO_OPENCTI_TYPE = {
    "intrusion-set": "Intrusion-Set",
    "threat-actor": "Threat-Actor-Group",
    "campaign": "Campaign",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "Attack-Pattern",
    "vulnerability": "Vulnerability",
    "indicator": "Indicator",
}


@dataclass
class Result:
    objects: list[dict]
    added: int
    merged_into_entity: bool
    dropped: list[str]


def is_container(stix_entity: dict) -> bool:
    return stix_entity["type"] in CONTAINER_TYPES or "object_refs" in stix_entity


def opencti_type_of(obj: dict) -> str | None:
    if obj["type"] == "identity":
        return {"class": "Sector", "organization": "Organization"}.get(
            obj.get("identity_class")
        )
    if obj["type"] == "location":
        return obj.get("x_opencti_location_type")
    if obj["type"] in SDO_OPENCTI_TYPE:
        return SDO_OPENCTI_TYPE[obj["type"]]
    return "Observable" if "value" in obj or "hashes" in obj else None


def enrichment_objects(
    stix_entity: dict, ex: Extraction, author: str = "doc-to-stix"
) -> Result:
    author_obj = author_identity(author)
    objects, dropped = build_objects(ex, author_obj["id"])
    markings = stix_entity.get("object_marking_refs") or []
    for o in objects:
        if markings:
            o["object_marking_refs"] = markings
    if is_container(stix_entity):
        entity = dict(stix_entity)
        refs = list(entity.get("object_refs") or [])
        new = [o["id"] for o in objects if o["id"] not in refs]
        entity["object_refs"] = refs + new
        return Result([entity, author_obj, *objects], len(new), False, dropped)
    return _attach_to_entity(stix_entity, ex, objects, author_obj, dropped)


def _attach_to_entity(stix_entity, ex, objects, author_obj, dropped) -> Result:
    entity_id = stix_entity["id"]
    compact_type, entity_otype = ENTITY_TYPES.get(stix_entity["type"], (None, None))
    names = [stix_entity.get("name", "")]
    names += stix_entity.get("aliases") or stix_entity.get("x_opencti_aliases") or []
    keys = {reference.name_key(n) for n in names if n}
    # 1. the extracted copy of the entity, if the document names it
    same = None
    if compact_type:
        for e, obj in zip(ex.entities, objects, strict=False):
            if family_type(e["type"]) != family_type(compact_type):
                continue
            if keys & {
                reference.name_key(n) for n in [e["name"], *e.get("aliases", [])]
            }:
                same = obj["id"]
                break
    out: list[dict] = []
    for o in objects:
        if o["id"] == same:
            continue
        if o["type"] == "relationship" and same in (o["source_ref"], o["target_ref"]):
            o = dict(o)
            o["source_ref"] = entity_id if o["source_ref"] == same else o["source_ref"]
            o["target_ref"] = entity_id if o["target_ref"] == same else o["target_ref"]
            o["id"] = pycti.StixCoreRelationship.generate_id(
                o["relationship_type"], o["source_ref"], o["target_ref"]
            )
        out.append(o)
    # 2. tie what is left unlinked to the entity
    # an indicator's based-on link to its own observable says nothing about the threat
    linked = {
        r[k]
        for r in out
        if r["type"] == "relationship" and r["relationship_type"] != "based-on"
        for k in ("source_ref", "target_ref")
    }
    allowed = reference.allowed_relationships()
    created_by = author_obj["id"]
    markings = stix_entity.get("object_marking_refs") or []
    extra = []
    for o in out:
        if o["type"] == "relationship" or o["id"] in linked:
            continue
        otype = opencti_type_of(o)
        if otype is None:
            continue
        if otype == "Indicator":
            ok = "indicates" in allowed.get(f"Indicator|{entity_otype}", [])
            rel = relationship(
                "indicates" if ok else "related-to", o["id"], entity_id, created_by
            )
        elif otype == "Observable":
            continue  # its indicator carries the link (indicator based-on observable)
        else:
            rel = relationship("related-to", entity_id, o["id"], created_by)
        if markings:
            rel["object_marking_refs"] = markings
        extra.append(rel)
    out += extra
    return Result([stix_entity, author_obj, *out], len(out), same is not None, dropped)
