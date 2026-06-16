#!/usr/bin/env python3
"""
patch_pipeline.py
Inserts a dynamic index routing rule into the Filebeat ingest pipeline
so alerts from agents with agent.labels.group set are routed to
wazuh-alerts-4.x-<group>-* indices.
Run at Docker build time inside the wazuh-manager image.
"""

import json
import os

PIPELINE_FILE = "/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json"

ROUTING_RULE = {
    "set": {
        "field": "fields.index_prefix",
        "value": "wazuh-alerts-4.x-{{agent.labels.group}}-",
        "if": "ctx?.agent?.labels?.group != null",
        "ignore_failure": False
    }
}

if not os.path.exists(PIPELINE_FILE):
    print(f"  [ERROR] Pipeline file not found: {PIPELINE_FILE}")
    exit(1)

with open(PIPELINE_FILE, "r") as f:
    data = json.load(f)

processors = data.get("processors", [])

# Check if already patched
already_patched = any(
    isinstance(p, dict)
    and "set" in p
    and p["set"].get("field") == "fields.index_prefix"
    and "agent.labels.group" in p["set"].get("value", "")
    for p in processors
)

if already_patched:
    print("  [SKIPPED]  pipeline.json (routing rule already present)")
else:
    # Find date_index_name processor position
    date_index_pos = next(
        (i for i, p in enumerate(processors) if isinstance(p, dict) and "date_index_name" in p),
        None
    )

    if date_index_pos is None:
        print("  [ERROR]  Could not find date_index_name processor in pipeline!")
        exit(1)

    processors.insert(date_index_pos, ROUTING_RULE)
    data["processors"] = processors

    with open(PIPELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  [PATCHED]  pipeline.json (routing rule inserted at position {date_index_pos})")

print("\nPipeline patching complete.")

