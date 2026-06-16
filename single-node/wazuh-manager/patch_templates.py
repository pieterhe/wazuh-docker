#!/usr/bin/env python3
"""
patch_templates.py
Adds agent.labels.group keyword mapping to all wazuh-states-inventory-* templates.
Run at Docker build time inside the wazuh-manager image.
"""

import json
import os
import glob

TEMPLATE_DIR = "/var/ossec/templates"

TEMPLATES = [
    "wazuh-states-inventory-system.json",
    "wazuh-states-inventory-system-update.json",
    "wazuh-states-inventory-packages.json",
    "wazuh-states-inventory-packages-update.json",
    "wazuh-states-inventory-processes.json",
    "wazuh-states-inventory-processes-update.json",
    "wazuh-states-inventory-ports.json",
    "wazuh-states-inventory-ports-update.json",
    "wazuh-states-inventory-networks.json",
    "wazuh-states-inventory-networks-update.json",
    "wazuh-states-inventory-interfaces.json",
    "wazuh-states-inventory-interfaces-update.json",
    "wazuh-states-inventory-protocols.json",
    "wazuh-states-inventory-protocols-update.json",
    "wazuh-states-inventory-hardware.json",
    "wazuh-states-inventory-hardware-update.json",
    "wazuh-states-inventory-hotfixes.json",
    "wazuh-states-inventory-hotfixes-update.json",
    "wazuh-states-inventory-users.json",
    "wazuh-states-inventory-users-update.json",
    "wazuh-states-inventory-services.json",
    "wazuh-states-inventory-services-update.json",
    "wazuh-states-inventory-groups.json",
    "wazuh-states-inventory-groups-update.json",
    "wazuh-states-inventory-browser-extensions.json",
    "wazuh-states-inventory-browser-extensions-update.json",
    "vd_states_template.json",
    "vd_states_update_mappings.json",
]

LABELS_MAPPING = {
    "type": "object",
    "dynamic": True,
    "properties": {
        "group": {"type": "keyword"}
    }
}


def add_labels(obj, filepath):
    """Recursively find agent.properties and inject labels mapping."""
    if isinstance(obj, dict):
        if (
            "agent" in obj
            and isinstance(obj["agent"], dict)
            and "properties" in obj["agent"]
        ):
            agent_props = obj["agent"]["properties"]
            if "labels" not in agent_props:
                agent_props["labels"] = LABELS_MAPPING
                return True  # patched
            else:
                return False  # already present
        for v in obj.values():
            if add_labels(v, filepath):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if add_labels(item, filepath):
                return True
    return False


patched = 0
skipped = 0
missing = 0

for tpl in TEMPLATES:
    filepath = os.path.join(TEMPLATE_DIR, tpl)
    if not os.path.exists(filepath):
        print(f"  [MISSING]  {tpl}")
        missing += 1
        continue

    with open(filepath, "r") as f:
        data = json.load(f)

    if add_labels(data, filepath):
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  [PATCHED]  {tpl}")
        patched += 1
    else:
        print(f"  [SKIPPED]  {tpl} (labels already present or agent block not found)")
        skipped += 1

print(f"\nTemplate patching complete: {patched} patched, {skipped} skipped, {missing} missing.")

