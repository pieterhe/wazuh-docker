#!/usr/bin/env python3
"""
tenant.py
Manages Wazuh tenants: create tenant groups, roles, and users.

Usage:
  sudo python3 tenant.py create-tenant <tenant_name>
  sudo python3 tenant.py add-user <tenant_name> <username> <password>
  sudo python3 tenant.py remove-user <tenant_name> <username>
  sudo python3 tenant.py delete-tenant <tenant_name>
  sudo python3 tenant.py list-tenants
  sudo python3 tenant.py list-users <tenant_name>
"""

import sys
import json
import subprocess
import base64

# ── Configuration ─────────────────────────────────────────────
WAZUH_API_URL     = "https://localhost:55000"
WAZUH_API_USER    = "wazuh-wui"
WAZUH_API_PASS    = "fea7Chahd[eeviquie"

INDEXER_URL       = "https://localhost:9200"
INDEXER_USER      = "admin"
INDEXER_PASS      = "ais;aCahze9vi#"

MANAGER_CONTAINER = "single-node-wazuh.manager-1"
INDEXER_CONTAINER = "single-node-wazuh.indexer-1"

# Role naming convention: tenant_{name}_role
ROLE_PREFIX = "tenant_"
ROLE_SUFFIX = "_role"
# ─────────────────────────────────────────────────────────────


# ── HTTP helpers ──────────────────────────────────────────────
def indexer(method, endpoint, body=None):
    """Call OpenSearch API via docker exec, using netrc to avoid password escaping issues."""
    inner = f'curl -sk -X {method} --netrc-file /tmp/.netrc "{INDEXER_URL}{endpoint}"'
    if body:
        body_escaped = json.dumps(body).replace("'", "'\\''")
        inner += f" -H 'Content-Type: application/json' -d '{body_escaped}'"
    cmd = [
        "docker", "exec", INDEXER_CONTAINER, "sh", "-c",
        f"echo 'machine localhost login {INDEXER_USER} password {INDEXER_PASS}' > /tmp/.netrc && "
        f"chmod 600 /tmp/.netrc && "
        f"{inner} ; "
        f"rm -f /tmp/.netrc"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


def wazuh_token():
    """Get Wazuh API JWT token."""
    creds = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
    inner = f'curl -sk -X POST -H "Authorization: Basic {creds}" "{WAZUH_API_URL}/security/user/authenticate"'
    cmd = ["docker", "exec", MANAGER_CONTAINER, "sh", "-c", inner]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)["data"]["token"]
    except (KeyError, TypeError, json.JSONDecodeError):
        raise RuntimeError(f"Failed to get Wazuh API token: {result.stdout.strip()}")


def wazuh(method, endpoint, body=None, content_type="application/json"):
    """Call Wazuh manager API via docker exec."""
    token = wazuh_token()
    if body:
        body_str = (json.dumps(body) if content_type == "application/json" else body).replace("'", "'\\''")
        inner = (
            f'curl -sk -X {method} '
            f'-H "Authorization: Bearer {token}" '
            f"-H 'Content-Type: {content_type}' "
            f"-d '{body_str}' "
            f'"{WAZUH_API_URL}{endpoint}"'
        )
    else:
        inner = f'curl -sk -X {method} -H "Authorization: Bearer {token}" "{WAZUH_API_URL}{endpoint}"'
    result = subprocess.run(["docker", "exec", MANAGER_CONTAINER, "sh", "-c", inner], capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


def role_name(tenant):
    return f"{ROLE_PREFIX}{tenant}{ROLE_SUFFIX}"


def tenant_from_role(role):
    if role.startswith(ROLE_PREFIX) and role.endswith(ROLE_SUFFIX):
        return role[len(ROLE_PREFIX):-len(ROLE_SUFFIX)]
    return None
# ─────────────────────────────────────────────────────────────


# ── Output helpers ────────────────────────────────────────────
SEP = "─" * 44

def sep():    print(f"\n{SEP}")
def ok(msg):  print(f"  [OK]  {msg}")
def log(msg): print(f"        {msg}")
def err(msg): print(f"  [ERR] {msg}"); sys.exit(1)
# ─────────────────────────────────────────────────────────────


# ── create-tenant ─────────────────────────────────────────────
def create_tenant(tenant):
    sep()
    print(f" Creating tenant: {tenant}")
    sep()

    # 1. Create Wazuh agent group
    log(f"Creating Wazuh agent group '{tenant}' ...")
    result = wazuh("POST", "/groups", {"group_id": tenant})
    if result.get("data", {}).get("affected_items"):
        ok(f"Agent group '{tenant}' created")
    else:
        log(f"Note: {result}")

    # 2. Upload agent.conf with label
    log(f"Uploading agent.conf with label group={tenant} ...")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<agent_config>\n'
        '  <labels>\n'
        f'    <label key="group">{tenant}</label>\n'
        '  </labels>\n'
        '</agent_config>'
    )
    result = wazuh("PUT", f"/groups/{tenant}/configuration", body=xml, content_type="application/xml")
    if "successfully" in str(result):
        ok("agent.conf uploaded")
    else:
        log(f"Note: {result}")

    # 3. Create OpenSearch role
    rname = role_name(tenant)
    log(f"Creating OpenSearch role '{rname}' ...")
    role = {
        "description": f"Role for tenant {tenant}",
        "cluster_permissions": ["cluster_composite_ops"],
        "index_permissions": [
            {
                # Alerts: restrict by index pattern (no DLS needed)
                "index_patterns": [f"wazuh-alerts-4.x-{tenant}-*"],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Monitoring: DLS by group field
                "index_patterns": ["wazuh-monitoring-*"],
                "dls": json.dumps({"term": {"group.keyword": tenant}}),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Inventory / IT Hygiene: DLS by agent label
                "index_patterns": ["wazuh-states-inventory-*"],
                "dls": json.dumps({"term": {"agent.labels.group": tenant}}),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Statistics: shared, no DLS
                "index_patterns": ["wazuh-statistics-*"],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            }
        ],
        "tenant_permissions": [
            {
                "tenant_patterns": [tenant],
                "allowed_actions": ["kibana_all_write"]
            }
        ]
    }
    result = indexer("PUT", f"/_plugins/_security/api/roles/{rname}", role)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role '{rname}' created")
    else:
        log(f"Note: {result}")

    sep()
    print(f" Tenant '{tenant}' is ready.")
    print(f" Add users with: sudo python3 tenant.py add-user {tenant} <username> <password>")
    sep()
    print()


# ── add-user ──────────────────────────────────────────────────
def add_user(tenant, username, password):
    sep()
    print(f" Adding user '{username}' to tenant '{tenant}'")
    sep()

    rname = role_name(tenant)

    # 1. Verify tenant role exists
    result = indexer("GET", f"/_plugins/_security/api/roles/{rname}")
    if rname not in result:
        err(f"Tenant '{tenant}' does not exist. Create it first with create-tenant.")

    # 2. Create or update OpenSearch user
    log(f"Creating OpenSearch user '{username}' ...")
    user = {
        "password": password,
        "opendistro_security_roles": [],
        "backend_roles": [],
        "attributes": {"tenant": tenant}
    }
    result = indexer("PUT", f"/_plugins/_security/api/internalusers/{username}", user)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"User '{username}' created")
    else:
        log(f"Note: {result}")

    # 3. Map user to tenant role (append, don't overwrite)
    log(f"Mapping '{username}' to role '{rname}' ...")
    existing = indexer("GET", f"/_plugins/_security/api/rolesmapping/{rname}")
    current_users = existing.get(rname, {}).get("users", [])
    if username not in current_users:
        current_users.append(username)

    result = indexer("PUT", f"/_plugins/_security/api/rolesmapping/{rname}", {"users": current_users})
    if result.get("status") in ("CREATED", "OK"):
        ok(f"User '{username}' mapped to '{rname}'")
    else:
        log(f"Note: {result}")

    sep()
    print(f" User '{username}' added to tenant '{tenant}'.")
    sep()
    print()


# ── remove-user ───────────────────────────────────────────────
def remove_user(tenant, username):
    sep()
    print(f" Removing user '{username}' from tenant '{tenant}'")
    sep()

    rname = role_name(tenant)

    log(f"Removing '{username}' from role mapping '{rname}' ...")
    existing = indexer("GET", f"/_plugins/_security/api/rolesmapping/{rname}")
    current_users = existing.get(rname, {}).get("users", [])
    if username not in current_users:
        log(f"User '{username}' is not mapped to '{rname}', nothing to do.")
    else:
        current_users.remove(username)
        result = indexer("PUT", f"/_plugins/_security/api/rolesmapping/{rname}", {"users": current_users})
        if result.get("status") in ("CREATED", "OK"):
            ok(f"User '{username}' removed from '{rname}'")
        else:
            log(f"Note: {result}")

    print()
    ans = input(f"  Also delete the OpenSearch user '{username}' entirely? (yes/no): ")
    if ans.strip().lower() == "yes":
        indexer("DELETE", f"/_plugins/_security/api/internalusers/{username}")
        ok(f"User '{username}' deleted")

    sep()
    print(" Done.")
    sep()
    print()


# ── delete-tenant ─────────────────────────────────────────────
def delete_tenant(tenant):
    sep()
    print(f" Deleting tenant: {tenant}")
    print(" WARNING: Removes the group, role and role mapping.")
    print(" Users are NOT deleted — remove them manually if needed.")
    sep()

    ans = input("  Are you sure? (yes/no): ")
    if ans.strip().lower() != "yes":
        print("  Aborted.")
        return

    rname = role_name(tenant)

    log(f"Deleting role mapping '{rname}' ...")
    indexer("DELETE", f"/_plugins/_security/api/rolesmapping/{rname}")
    ok("Role mapping deleted")

    log(f"Deleting role '{rname}' ...")
    indexer("DELETE", f"/_plugins/_security/api/roles/{rname}")
    ok("Role deleted")

    log(f"Deleting Wazuh agent group '{tenant}' ...")
    wazuh("DELETE", "/groups", {"groups_list": [tenant]})
    ok("Agent group deleted")

    sep()
    print(f" Tenant '{tenant}' deleted.")
    sep()
    print()


# ── list-tenants ──────────────────────────────────────────────
def list_tenants():
    sep()
    print(" Tenants:")
    sep()

    roles = indexer("GET", "/_plugins/_security/api/roles/")
    tenants = sorted([
        tenant_from_role(r)
        for r in roles
        if tenant_from_role(r) is not None
    ])

    if tenants:
        for t in tenants:
            rname = role_name(t)
            mapping = indexer("GET", f"/_plugins/_security/api/rolesmapping/{rname}")
            users = mapping.get(rname, {}).get("users", [])
            user_str = ", ".join(users) if users else "no users"
            print(f"  {t}  ({user_str})")
    else:
        print("  No tenants found.")
    print()


# ── list-users ────────────────────────────────────────────────
def list_users(tenant):
    sep()
    print(f" Users in tenant '{tenant}':")
    sep()

    rname = role_name(tenant)
    mapping = indexer("GET", f"/_plugins/_security/api/rolesmapping/{rname}")
    users = mapping.get(rname, {}).get("users", [])
    if users:
        for u in users:
            print(f"  - {u}")
    else:
        print("  No users found.")
    print()


# ── Main ──────────────────────────────────────────────────────
def usage():
    print(__doc__)
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    command = sys.argv[1]

    if command == "create-tenant":
        if len(sys.argv) != 3: usage()
        create_tenant(sys.argv[2])

    elif command == "add-user":
        if len(sys.argv) != 5: usage()
        add_user(sys.argv[2], sys.argv[3], sys.argv[4])

    elif command == "remove-user":
        if len(sys.argv) != 4: usage()
        remove_user(sys.argv[2], sys.argv[3])

    elif command == "delete-tenant":
        if len(sys.argv) != 3: usage()
        delete_tenant(sys.argv[2])

    elif command == "list-tenants":
        list_tenants()

    elif command == "list-users":
        if len(sys.argv) != 3: usage()
        list_users(sys.argv[2])

    else:
        usage()

