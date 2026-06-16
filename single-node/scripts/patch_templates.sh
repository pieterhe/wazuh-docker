#!/bin/sh
# ============================================================
# patch_wazuh_templates.sh
# Adds agent.labels.group mapping to all wazuh-states-inventory
# templates, then removes the indices and restarts the manager
# so they are recreated with the new mapping.
#
# Usage: sh patch_wazuh_templates.sh
# Compatible with Alpine sh (ash) on the Docker host.
# ============================================================

set -e

CONTAINER="single-node-wazuh.manager-1"
INDEXER_CONTAINER="single-node-wazuh.indexer-1"
INDEXER_URL="https://localhost:9200"
INDEXER_USER="admin"
INDEXER_PASS="ais;aCahze9vi#"   # <-- change to your actual password
BACKUP_DIR="./wazuh-templates-backup-$(date +%Y%m%d%H%M%S)"
TEMPLATE_DIR="/var/ossec/templates"

TEMPLATES="
wazuh-states-inventory-system.json
wazuh-states-inventory-system-update.json
wazuh-states-inventory-packages.json
wazuh-states-inventory-packages-update.json
wazuh-states-inventory-processes.json
wazuh-states-inventory-processes-update.json
wazuh-states-inventory-ports.json
wazuh-states-inventory-ports-update.json
wazuh-states-inventory-networks.json
wazuh-states-inventory-networks-update.json
wazuh-states-inventory-interfaces.json
wazuh-states-inventory-interfaces-update.json
wazuh-states-inventory-protocols.json
wazuh-states-inventory-protocols-update.json
wazuh-states-inventory-hardware.json
wazuh-states-inventory-hardware-update.json
wazuh-states-inventory-hotfixes.json
wazuh-states-inventory-hotfixes-update.json
wazuh-states-inventory-users.json
wazuh-states-inventory-users-update.json
wazuh-states-inventory-services.json
wazuh-states-inventory-services-update.json
wazuh-states-inventory-groups.json
wazuh-states-inventory-groups-update.json
wazuh-states-inventory-browser-extensions.json
wazuh-states-inventory-browser-extensions-update.json
vd_states_template.json
vd_states_update_mappings.json
"

# Python3 patch script — runs inside the Wazuh manager container (Debian-based, has python3)
# Written to a temp file inside the container, then executed
PATCH_PY='
import json, sys

filepath = sys.argv[1]

with open(filepath, "r") as f:
    data = json.load(f)

def add_labels(obj):
    if isinstance(obj, dict):
        if "agent" in obj and isinstance(obj["agent"], dict) and "properties" in obj["agent"]:
            agent_props = obj["agent"]["properties"]
            if "labels" not in agent_props:
                agent_props["labels"] = {
                    "type": "object",
                    "dynamic": True,
                    "properties": {
                        "group": {"type": "keyword"}
                    }
                }
                print("  -> Patched: " + filepath)
            else:
                print("  -> Already patched, skipping: " + filepath)
            return
        for v in obj.values():
            add_labels(v)
    elif isinstance(obj, list):
        for item in obj:
            add_labels(item)

add_labels(data)

with open(filepath, "w") as f:
    json.dump(data, f, indent=2)
'

echo "========================================"
echo " Wazuh Template Patcher"
echo "========================================"
echo ""

# 1. Backup templates locally
echo "[1/5] Backing up templates to $BACKUP_DIR ..."
mkdir -p "$BACKUP_DIR"
for tpl in $TEMPLATES; do
  tpl=$(echo "$tpl" | tr -d '[:space:]')
  [ -z "$tpl" ] && continue
  if docker exec "$CONTAINER" test -f "$TEMPLATE_DIR/$tpl" 2>/dev/null; then
    docker exec "$CONTAINER" cat "$TEMPLATE_DIR/$tpl" > "$BACKUP_DIR/$tpl"
    echo "  Backed up: $tpl"
  else
    echo "  Not found, skipping: $tpl"
  fi
done
echo "  Done -> $BACKUP_DIR"
echo ""

# 2. Copy patch script into the container once, then run it per file
echo "[2/5] Patching templates inside container ..."
docker exec "$CONTAINER" sh -c "cat > /tmp/patch_template.py" << PYEOF
$PATCH_PY
PYEOF

for tpl in $TEMPLATES; do
  tpl=$(echo "$tpl" | tr -d '[:space:]')
  [ -z "$tpl" ] && continue
  FULL_PATH="$TEMPLATE_DIR/$tpl"
  if docker exec "$CONTAINER" test -f "$FULL_PATH" 2>/dev/null; then
    docker exec "$CONTAINER" python3 /tmp/patch_template.py "$FULL_PATH"
  fi
done

# Clean up patch script from container
docker exec "$CONTAINER" rm -f /tmp/patch_template.py
echo ""

# 3. Backup index data (best-effort)
echo "[3/5] Backing up index data (best-effort) ..."
docker exec "$INDEXER_CONTAINER" curl -sk -u "$INDEXER_USER:$INDEXER_PASS" \
  "$INDEXER_URL/wazuh-states-inventory-*/_search?size=5000&pretty" \
  -o /tmp/wazuh-inventory-backup.json \
  && docker cp "$INDEXER_CONTAINER:/tmp/wazuh-inventory-backup.json" "$BACKUP_DIR/index-data-backup.json" \
  && echo "  Saved to $BACKUP_DIR/index-data-backup.json" \
  || echo "  Warning: index data backup failed (non-fatal)"
echo ""

# 4. Delete inventory indices
echo "[4/5] Deleting wazuh-states-inventory-* indices ..."
docker exec "$INDEXER_CONTAINER" curl -sk -u "$INDEXER_USER:$INDEXER_PASS" \
  -X DELETE "$INDEXER_URL/wazuh-states-inventory-*"
echo ""
echo "  Indices deleted."
echo ""

# 5. Restart manager
echo "[5/5] Restarting Wazuh manager ..."
docker restart "$CONTAINER"
echo "  Restarted $CONTAINER"
echo ""

echo "========================================"
echo " Done!"
echo ""
echo " Next steps:"
echo "  1. Wait ~1-2 min for agents to re-send inventory data"
echo ""
echo "  2. Verify the mapping:"
echo "     docker exec $INDEXER_CONTAINER curl -sk \\"
echo "       -u $INDEXER_USER:$INDEXER_PASS \\"
echo "       $INDEXER_URL/wazuh-states-inventory-system-*/_mapping?pretty \\"
echo "       | grep -A5 labels"
echo ""
echo "  3. Update your DLS rules to:"
echo '     {"term": {"agent.labels.group": "tenant_ph"}}'
echo "========================================"
