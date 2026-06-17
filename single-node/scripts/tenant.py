#!/usr/bin/env python3
"""
tenant.py
Manages Wazuh tenants: create tenant groups, roles, and users.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  sudo python3 tenant.py create-tenant <tenant_name>
  sudo python3 tenant.py add-user <tenant_name> <username>
  sudo python3 tenant.py remove-user <tenant_name> <username>
  sudo python3 tenant.py delete-tenant <tenant_name>
  sudo python3 tenant.py list-tenants
  sudo python3 tenant.py list-users <tenant_name>
  sudo python3 tenant.py sync-role <tenant_name>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NEW TENANT LIFECYCLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1. Create the tenant:
      sudo python3 tenant.py create-tenant <tenant_name>
    Creates:
      - Wazuh agent group '<tenant_name>'
      - agent.conf with label: group=<tenant_name>
      - OpenSearch role 'tenant_<tenant_name>_role'
      - Wazuh API policy, role and rule scoped to the group

 2. Add a dashboard user:
      sudo python3 tenant.py add-user <tenant_name> <username>
    Creates the OpenSearch user and maps them to the tenant role.

 3. Enroll agents into the tenant group:
    In the Wazuh dashboard (as admin), assign agents to the '<tenant_name>' group.
    The agents will automatically receive the group label from agent.conf.

 4. Sync the role after agents are enrolled:
      sudo python3 tenant.py sync-role <tenant_name>
    Updates:
      - Inventory/vulnerability DLS with current agent IDs
      - Kibana alerts index pattern for all tenant users
    Run this again whenever agents are added or removed from the group.

 5. Tenant users access the dashboard via:
      https://<tenant_name>.zeroed.nl
    Caddy automatically injects the correct tenant header.
    DNS is handled by the wildcard *.zeroed.nl record.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 - Alert isolation: Filebeat routes alerts to wazuh-alerts-4.x-<tenant>-*
   Old alerts in wazuh-alerts-4.x-* are protected by agent.id DLS.
 - Inventory/IT Hygiene: isolated by agent.id DLS (Wazuh does not write
   group labels to inventory indices — see github.com/wazuh/wazuh/issues/33098)
 - Monitoring: isolated by group.keyword DLS
 - Run sync-role after any agent group membership change.
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


def group_name(tenant):
    """The Wazuh group name is always tenant_<name>."""
    return f"tenant_{tenant}"


def tenant_from_role(role):
    if role.startswith(ROLE_PREFIX) and role.endswith(ROLE_SUFFIX):
        return role[len(ROLE_PREFIX):-len(ROLE_SUFFIX)]
    return None


def get_agent_ids_for_group(tenant):
    """Get all agent IDs that belong to the tenant group."""
    result = wazuh("GET", f"/agents?groups_list={group_name(tenant)}&limit=500")
    agents = result.get("data", {}).get("affected_items", [])
    return [a["id"] for a in agents]


def inventory_dls(agent_ids):
    """Build DLS query for inventory indices based on agent IDs."""
    if not agent_ids:
        return json.dumps({"match_none": {}})
    if len(agent_ids) == 1:
        return json.dumps({"term": {"agent.id": agent_ids[0]}})
    return json.dumps({"terms": {"agent.id": agent_ids}})


def get_kibana_tenant_index(tenant):
    """Find the kibana index for a given tenant name.
    
    OpenSearch strips underscores from tenant names in kibana index names:
    e.g. tenant_picard -> tenantpicard, so we need to try both the raw
    tenant name and the full OpenSearch tenant name (tenant_{name}).
    """
    result = indexer("GET", "/_cat/indices/.kibana_*?h=index&format=json")
    if not isinstance(result, list):
        return None

    # Kibana strips underscores from tenant names in index names
    # e.g. tenant_picard -> tenantpicard
    candidates = [
        group_name(tenant).replace("_", "").lower(),   # tenant_picard -> tenantpicard
        tenant.replace("_", "").lower(),               # picard -> picard (fallback)
    ]

    for item in result:
        idx = item.get("index", "").lower()
        for candidate in candidates:
            if f"_{candidate}_" in idx:
                return item.get("index")
    return None


def update_kibana_alerts_pattern(username, tenant):
    """Update the wazuh-alerts-* index pattern in the tenant's kibana space."""
    kibana_index = get_kibana_tenant_index(tenant)
    if not kibana_index:
        log(f"Could not find kibana index for tenant '{tenant}' — skipping index pattern update")
        log("A user must log in first to create the kibana space, then run sync-role")
        return False

    result = indexer("POST", f"/{kibana_index}/_update/index-pattern:wazuh-alerts-*", {
        "doc": {
            "index-pattern": {
                "title": f"wazuh-alerts-4.x-{tenant}-*"
            }
        }
    })
    if result.get("result") in ("updated", "noop"):
        ok(f"Kibana alerts index pattern updated to 'wazuh-alerts-4.x-{tenant}-*'")
        return True
    else:
        log(f"Note: {result}")
        return False
# ─────────────────────────────────────────────────────────────


# ── Output helpers ────────────────────────────────────────────
SEP = "─" * 44

def sep():    print(f"\n{SEP}")
def ok(msg):  print(f"  [OK]  {msg}")
def log(msg): print(f"        {msg}")
def err(msg): print(f"  [ERR] {msg}"); sys.exit(1)
# ─────────────────────────────────────────────────────────────


# ── build_role ────────────────────────────────────────────────
def build_role(tenant, agent_ids):
    """Build the OpenSearch role definition for a tenant."""
    return {
        "description": f"Role for tenant {tenant}",
        "cluster_permissions": ["cluster_composite_ops"],
        "index_permissions": [
            {
                # Alerts: tenant-specific index — no DLS needed
                # Filebeat dynamic routing puts alerts here using agent.labels.group
                "index_patterns": [f"wazuh-alerts-4.x-{group_name(tenant)}-*"],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Alerts: old/default index — DLS by agent.id as safety net
                # Covers pre-routing alerts and raw Discover access
                "index_patterns": ["wazuh-alerts-4.x-*"],
                "dls": inventory_dls(agent_ids),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Monitoring: DLS by Wazuh group field
                "index_patterns": ["wazuh-monitoring-*"],
                "dls": json.dumps({"term": {"group.keyword": group_name(tenant)}}),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Inventory / IT Hygiene: DLS by agent.id
                # Wazuh server does not write labels to inventory indices
                "index_patterns": ["wazuh-states-inventory-*"],
                "dls": inventory_dls(agent_ids),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                # Vulnerabilities: DLS by agent.id (same reason as inventory)
                "index_patterns": ["wazuh-states-vulnerabilities-*"],
                "dls": inventory_dls(agent_ids),
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
                "tenant_patterns": [group_name(tenant)],
                "allowed_actions": ["kibana_all_write"]
            }
        ]
    }
# ─────────────────────────────────────────────────────────────


# ── create-tenant ─────────────────────────────────────────────
def create_tenant(tenant):
    sep()
    print(f" Creating tenant: {tenant}")
    sep()

    # 1. Create Wazuh agent group
    log(f"Creating Wazuh agent group '{group_name(tenant)}' ...")
    result = wazuh("POST", "/groups", {"group_id": group_name(tenant)})
    if result.get("data", {}).get("affected_items"):
        ok(f"Agent group '{tenant}' created")
    else:
        log(f"Note: {result}")

    # 2. Upload agent.conf with label
    log(f"Uploading agent.conf with label group={group_name(tenant)} ...")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<agent_config>\n'
        '  <labels>\n'
        f'    <label key="group">{group_name(tenant)}</label>\n'
        '  </labels>\n'
        '</agent_config>'
    )
    result = wazuh("PUT", f"/groups/{group_name(tenant)}/configuration", body=xml, content_type="application/xml")
    if "successfully" in str(result):
        ok("agent.conf uploaded")
    else:
        log(f"Note: {result}")

    # 3. Look up agent IDs for this group (likely empty at creation time)
    log(f"Looking up agents in group '{tenant}' ...")
    agent_ids = get_agent_ids_for_group(tenant)
    if agent_ids:
        ok(f"Found agents: {agent_ids}")
    else:
        log("No agents yet — inventory DLS will be set to match-none until agents are added")

    # 4. Create OpenSearch role
    rname = role_name(tenant)
    log(f"Creating OpenSearch role '{rname}' ...")
    role = build_role(tenant, agent_ids)
    result = indexer("PUT", f"/_plugins/_security/api/roles/{rname}", role)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role '{rname}' created")
    else:
        log(f"Note: {result}")

    # 5. Create Wazuh API policy
    log(f"Creating Wazuh API policy for '{tenant}' ...")
    wazuh_policy = {
        "name": f"pol_{tenant}",
        "policy": {
            "actions": [
                "agent:read", "group:read", "ciscat:read", "sca:read",
                "syscheck:read", "syscollector:read", "rootcheck:read",
                "mitre:read", "rules:read", "decoders:read", "lists:read",
                "cluster:status", "manager:read"
            ],
            "resources": [
                f"agent:group:{group_name(tenant)}",
                f"group:id:{group_name(tenant)}"
            ],
            "effect": "allow"
        }
    }
    result = wazuh("POST", "/security/policies", wazuh_policy)
    policy_id = result.get("data", {}).get("affected_items", [{}])[0].get("id")
    if policy_id:
        ok(f"Wazuh API policy created (id={policy_id})")
    else:
        log(f"Note: {result}")

    # 6. Create Wazuh API role
    log(f"Creating Wazuh API role for '{tenant}' ...")
    result = wazuh("POST", "/security/roles", {"name": f"wazuh_{tenant}"})
    wazuh_role_id = result.get("data", {}).get("affected_items", [{}])[0].get("id")
    if wazuh_role_id:
        ok(f"Wazuh API role created (id={wazuh_role_id})")
    else:
        log(f"Note: {result}")

    # 7. Link policy to role
    if policy_id and wazuh_role_id:
        log(f"Linking policy to Wazuh API role ...")
        result = wazuh("POST", f"/security/roles/{wazuh_role_id}/policies?policy_ids={policy_id}")
        if result.get("error") == 0:
            ok("Policy linked to role")
        else:
            log(f"Note: {result}")

    # 8. Create Wazuh API rule
    log(f"Creating Wazuh API rule for '{tenant}' ...")
    wazuh_rule = {
        "name": f"map_{tenant}",
        "rule": {"FIND": {"user_name": f"__placeholder_{tenant}__"}}
    }
    result = wazuh("POST", "/security/rules", wazuh_rule)
    rule_id = result.get("data", {}).get("affected_items", [{}])[0].get("id")
    if rule_id:
        ok(f"Wazuh API rule created (id={rule_id}) — update it when adding users")
    else:
        log(f"Note: {result}")

    # 9. Link rule to role
    if rule_id and wazuh_role_id:
        log(f"Linking rule to Wazuh API role ...")
        result = wazuh("POST", f"/security/roles/{wazuh_role_id}/rules?rule_ids={rule_id}")
        if result.get("error") == 0:
            ok("Rule linked to role")
        else:
            log(f"Note: {result}")

    sep()
    print(f" Tenant '{tenant}' is ready.")
    print(f" Add users with: sudo python3 tenant.py add-user {tenant} <username> <password>")
    print(f" After adding agents, run: sudo python3 tenant.py sync-role {tenant}")
    sep()
    print()


# ── sync-role ─────────────────────────────────────────────────
def sync_role(tenant):
    """Update inventory DLS and kibana index patterns based on current group members."""
    sep()
    print(f" Syncing role for tenant: {tenant}")
    sep()

    rname = role_name(tenant)

    # Verify role exists
    result = indexer("GET", f"/_plugins/_security/api/roles/{rname}")
    if rname not in result:
        err(f"Tenant '{tenant}' does not exist.")

    # Get current agent IDs
    log(f"Looking up agents in group '{tenant}' ...")
    agent_ids = get_agent_ids_for_group(tenant)
    if agent_ids:
        ok(f"Found agents: {agent_ids}")
    else:
        log("No agents in group — inventory DLS will be set to match-none")

    # Rebuild and update role
    log(f"Updating role '{rname}' ...")
    role = build_role(tenant, agent_ids)
    result = indexer("PUT", f"/_plugins/_security/api/roles/{rname}", role)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role '{rname}' updated with agent IDs: {agent_ids}")
    else:
        log(f"Note: {result}")

    # Update kibana index pattern for the tenant space (shared by all users in the tenant)
    log(f"Updating kibana index pattern for tenant '{tenant}' ...")
    update_kibana_alerts_pattern(None, tenant)

    sep()
    print(f" Sync complete.")
    sep()
    print()


# ── add-user ──────────────────────────────────────────────────
def generate_password():
    """Generate a strong random password."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#%^&*"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(20))
        if (any(c.islower() for c in pwd) and
            any(c.isupper() for c in pwd) and
            any(c.isdigit() for c in pwd) and
            any(c in "!@#%^&*" for c in pwd)):
            return pwd


def add_user(tenant, username):
    sep()
    print(f" Adding user '{username}' to tenant '{tenant}'")
    sep()

    rname = role_name(tenant)

    # 1. Verify tenant role exists
    result = indexer("GET", f"/_plugins/_security/api/roles/{rname}")
    if rname not in result:
        err(f"Tenant '{tenant}' does not exist. Create it first with create-tenant.")

    # 2. Generate password
    password = generate_password()

    # 3. Create OpenSearch user
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

    # 4. Map user to tenant role (append, don't overwrite)
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
    print()
    print(f"  ┌─────────────────────────────────────────┐")
    print(f"  │  CREDENTIALS — print once, store safely  │")
    print(f"  │  Username : {username:<29} │")
    print(f"  │  Password : {password:<29} │")
    print(f"  │  URL      : https://{tenant}.zeroed.nl{chr(32) * max(0, 17 - len(tenant))}│")
    print(f"  └─────────────────────────────────────────┘")
    print()
    print(f"  After the user logs in for the first time, run:")
    print(f"  sudo python3 tenant.py sync-role {tenant}")
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

    log(f"Deleting Wazuh agent group '{group_name(tenant)}' ...")
    wazuh("DELETE", "/groups", {"groups_list": [group_name(tenant)]})
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
            agent_ids = get_agent_ids_for_group(t)
            user_str = ", ".join(users) if users else "no users"
            agent_str = ", ".join(agent_ids) if agent_ids else "no agents"
            print(f"  {t}  (users: {user_str} | agents: {agent_str})")
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
        if len(sys.argv) != 4: usage()
        add_user(sys.argv[2], sys.argv[3])

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

    elif command == "sync-role":
        if len(sys.argv) != 3: usage()
        sync_role(sys.argv[2])

    else:
        usage()

