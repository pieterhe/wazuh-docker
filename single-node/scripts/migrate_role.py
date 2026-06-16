#!/usr/bin/env python3
"""
migrate_role.py
Migrates role_tenant_picard to tenant_picard_role (new naming convention).

What it does:
  1. Creates tenant_picard_role with the same permissions
  2. Creates the role mapping with the same users
  3. Deletes role_tenant_picard and its mapping

Usage:
  python3 migrate_role.py
  python3 migrate_role.py --dry-run
"""

import subprocess
import json
import sys

# ── Configuration ─────────────────────────────────────────────
INDEXER_URL       = "https://localhost:9200"
INDEXER_USER      = "admin"
INDEXER_PASS      = "ais;aCahze9vi#"
INDEXER_CONTAINER = "single-node-wazuh.indexer-1"

OLD_ROLE = "role_tenant_picard"
NEW_ROLE = "tenant_picard_role"
# ─────────────────────────────────────────────────────────────

DRY_RUN = "--dry-run" in sys.argv

SEP = "─" * 44

def sep():    print(f"\n{SEP}")
def ok(msg):  print(f"  [OK]  {msg}")
def log(msg): print(f"        {msg}")
def dry(msg): print(f"  [DRY] {msg}")
def err(msg): print(f"  [ERR] {msg}"); sys.exit(1)


def curl(method, endpoint, body=None):
    # Write credentials to a temp netrc file inside the container to avoid
    # special character shell-escaping issues with -u user:pass
    inner_cmd = f'curl -sk -X {method} --netrc-file /tmp/.netrc "{INDEXER_URL}{endpoint}"'
    if body:
        body_json = json.dumps(body).replace("'", "'\\''")  # escape single quotes
        inner_cmd += f" -H 'Content-Type: application/json' -d '{body_json}'"

    cmd = [
        "docker", "exec", INDEXER_CONTAINER, "sh", "-c",
        f"echo 'machine localhost login {INDEXER_USER} password {INDEXER_PASS}' > /tmp/.netrc && "
        f"chmod 600 /tmp/.netrc && "
        f"{inner_cmd} && "
        f"rm -f /tmp/.netrc"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


sep()
print(f" Role migration: {OLD_ROLE} → {NEW_ROLE}")
if DRY_RUN:
    print(" DRY RUN — no changes will be made")
sep()

# 1. Fetch existing role
log(f"Fetching existing role '{OLD_ROLE}' ...")
result = curl("GET", f"/_plugins/_security/api/roles/{OLD_ROLE}")
if OLD_ROLE not in result:
    err(f"Role '{OLD_ROLE}' not found. Nothing to migrate.")

role_def = result[OLD_ROLE]
ok(f"Role '{OLD_ROLE}' found")
log(f"  Cluster permissions : {role_def.get('cluster_permissions', [])}")
log(f"  Index permissions   : {len(role_def.get('index_permissions', []))} entries")
log(f"  Tenant permissions  : {len(role_def.get('tenant_permissions', []))} entries")

# 2. Fetch existing role mapping
log(f"Fetching role mapping for '{OLD_ROLE}' ...")
result = curl("GET", f"/_plugins/_security/api/rolesmapping/{OLD_ROLE}")
mapping_def = result.get(OLD_ROLE, {})
mapped_users = mapping_def.get("users", [])
ok(f"Role mapping found — users: {mapped_users}")

# 3. Create new role
new_role_body = {
    "cluster_permissions": role_def.get("cluster_permissions", []),
    "index_permissions": role_def.get("index_permissions", []),
    "tenant_permissions": role_def.get("tenant_permissions", [])
}

print()
log(f"Creating new role '{NEW_ROLE}' ...")
if DRY_RUN:
    dry(f"Would PUT /_plugins/_security/api/roles/{NEW_ROLE}")
    dry(json.dumps(new_role_body, indent=4))
else:
    result = curl("PUT", f"/_plugins/_security/api/roles/{NEW_ROLE}", new_role_body)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role '{NEW_ROLE}' created")
    else:
        err(f"Failed to create role: {result}")

# 4. Create new role mapping
log(f"Creating role mapping for '{NEW_ROLE}' with users {mapped_users} ...")
if DRY_RUN:
    dry(f"Would PUT /_plugins/_security/api/rolesmapping/{NEW_ROLE}")
    dry(json.dumps({"users": mapped_users}, indent=4))
else:
    result = curl("PUT", f"/_plugins/_security/api/rolesmapping/{NEW_ROLE}", {"users": mapped_users})
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role mapping for '{NEW_ROLE}' created")
    else:
        err(f"Failed to create role mapping: {result}")

# 5. Delete old role mapping
log(f"Deleting old role mapping '{OLD_ROLE}' ...")
if DRY_RUN:
    dry(f"Would DELETE /_plugins/_security/api/rolesmapping/{OLD_ROLE}")
else:
    result = curl("DELETE", f"/_plugins/_security/api/rolesmapping/{OLD_ROLE}")
    ok(f"Old role mapping '{OLD_ROLE}' deleted")

# 6. Delete old role
log(f"Deleting old role '{OLD_ROLE}' ...")
if DRY_RUN:
    dry(f"Would DELETE /_plugins/_security/api/roles/{OLD_ROLE}")
else:
    result = curl("DELETE", f"/_plugins/_security/api/roles/{OLD_ROLE}")
    ok(f"Old role '{OLD_ROLE}' deleted")

sep()
if DRY_RUN:
    print(" Dry run complete — no changes were made.")
    print(f" Run without --dry-run to apply.")
else:
    print(f" Migration complete.")
    print(f" '{OLD_ROLE}' → '{NEW_ROLE}'")
    print(f" Users {mapped_users} are now mapped to '{NEW_ROLE}'")
sep()
print()

