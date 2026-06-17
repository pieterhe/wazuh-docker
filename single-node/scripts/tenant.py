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
  sudo python3 tenant.py enroll-agent <tenant_name> <agent_name>
  sudo python3 tenant.py delete-agent <tenant_name> <agent_name>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NEW TENANT LIFECYCLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1. Create the tenant:
      sudo python3 tenant.py create-tenant <tenant_name>
    Creates:
      - Wazuh agent group 'tenant_<tenant_name>'
      - agent.conf with label: group=tenant_<tenant_name>
      - OpenSearch role 'tenant_<tenant_name>_role'
      - Wazuh API policy, role and rule scoped to the group

 2. Add a dashboard user:
      sudo python3 tenant.py add-user <tenant_name> <username>
    Creates the OpenSearch user with a generated password and maps
    them to the tenant role. Password is printed once — store safely.
    After the user logs in for the first time, run sync-role.

 3. Pre-register an agent for the tenant:
      sudo python3 tenant.py enroll-agent <tenant_name> <agent_name>
    Generates a one-time OS-aware install script served at:
      https://<tenant_name>.zeroed.nl/register/<agent_name>
    Tenant runs: curl -s https://<tenant>.zeroed.nl/register/<agent_name> | bash
    Script deletes itself after use.
    After the agent connects, run sync-role to update the DLS.

 4. Delete a pre-registered agent (if not yet used):
      sudo python3 tenant.py delete-agent <tenant_name> <agent_name>

 5. Sync the role after agents connect or users log in:
      sudo python3 tenant.py sync-role <tenant_name>
    Updates:
      - Inventory/vulnerability DLS with current agent IDs
      - Kibana alerts index pattern for all tenant users
    Run this again whenever agents are added or removed from the group.

 6. Tenant users access the dashboard via:
      https://<tenant_name>.zeroed.nl
    Caddy automatically injects the correct tenant header.
    DNS is handled by the wildcard *.zeroed.nl record.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 - Alert isolation: Filebeat routes alerts to wazuh-alerts-4.x-tenant_<name>-*
   Old alerts in wazuh-alerts-4.x-* are protected by agent.id DLS.
 - Inventory/IT Hygiene: isolated by agent.id DLS (Wazuh does not write
   group labels to inventory indices — see github.com/wazuh/wazuh/issues/33098)
 - Monitoring: isolated by group.keyword DLS
 - Run sync-role after any agent group membership change.
"""

import sys
import os
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

WAZUH_VERSION     = "4.14.4"
MANAGER_HOST      = "tuxido.zeroed.nl"
REGISTER_DIR      = "/usr/local/ISGservices/register"

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
    result = wazuh("GET", f"/agents?group={group_name(tenant)}&limit=500")
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
    e.g. tenant_picard -> tenantpicard
    """
    result = indexer("GET", "/_cat/indices/.kibana_*?h=index&format=json")
    if not isinstance(result, list):
        return None
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
                "title": f"wazuh-alerts-4.x-{group_name(tenant)}-*"
            }
        }
    })
    if result.get("result") in ("updated", "noop"):
        ok(f"Kibana alerts index pattern updated to 'wazuh-alerts-4.x-{group_name(tenant)}-*'")
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
                "index_patterns": [f"wazuh-alerts-4.x-{group_name(tenant)}-*"],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                "index_patterns": ["wazuh-alerts-4.x-*"],
                "dls": inventory_dls(agent_ids),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                "index_patterns": ["wazuh-monitoring-*"],
                "dls": json.dumps({"term": {"group.keyword": group_name(tenant)}}),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                "index_patterns": ["wazuh-states-inventory-*"],
                "dls": inventory_dls(agent_ids),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
                "index_patterns": ["wazuh-states-vulnerabilities-*"],
                "dls": inventory_dls(agent_ids),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:data/read/search"]
            },
            {
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
        ok(f"Agent group '{group_name(tenant)}' created")
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

    # 3. Look up agent IDs (likely empty at creation time)
    log(f"Looking up agents in group '{group_name(tenant)}' ...")
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
        "name": f"pol_{group_name(tenant)}",
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
    result = wazuh("POST", "/security/roles", {"name": f"wazuh_{group_name(tenant)}"})
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
        "name": f"map_{group_name(tenant)}",
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
    print(f" Add users with: sudo python3 tenant.py add-user {tenant} <username>")
    print(f" Enroll agents with: sudo python3 tenant.py enroll-agent {tenant} <agent_name>")
    sep()
    print()


# ── sync-role ─────────────────────────────────────────────────
def sync_role(tenant):
    """Update inventory DLS and kibana index patterns based on current group members."""
    sep()
    print(f" Syncing role for tenant: {tenant}")
    sep()

    rname = role_name(tenant)

    result = indexer("GET", f"/_plugins/_security/api/roles/{rname}")
    if rname not in result:
        err(f"Tenant '{tenant}' does not exist.")

    log(f"Looking up agents in group '{group_name(tenant)}' ...")
    agent_ids = get_agent_ids_for_group(tenant)
    if agent_ids:
        ok(f"Found agents: {agent_ids}")
    else:
        log("No agents in group — inventory DLS will be set to match-none")

    log(f"Updating role '{rname}' ...")
    role = build_role(tenant, agent_ids)
    result = indexer("PUT", f"/_plugins/_security/api/roles/{rname}", role)
    if result.get("status") in ("CREATED", "OK"):
        ok(f"Role '{rname}' updated with agent IDs: {agent_ids}")
    else:
        log(f"Note: {result}")

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

    result = indexer("GET", f"/_plugins/_security/api/roles/{rname}")
    if rname not in result:
        err(f"Tenant '{tenant}' does not exist. Create it first with create-tenant.")

    password = generate_password()

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

    log(f"Updating kibana index pattern for tenant '{tenant}' ...")
    update_kibana_alerts_pattern(None, tenant)

    sep()
    print(f" User '{username}' added to tenant '{tenant}'.")
    print()
    print(f"  ┌─────────────────────────────────────────┐")
    print(f"  │  CREDENTIALS — print once, store safely  │")
    print(f"  │  Username : {username:<29} │")
    print(f"  │  Password : {password:<29} │")
    print(f"  │  URL      : https://{tenant}.zeroed.nl  │")
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


# ── enroll-agent ──────────────────────────────────────────────
def generate_register_script(tenant, agent_name, agent_key):
    """Generate a self-contained OS-aware install script."""
    v = WAZUH_VERSION
    m = MANAGER_HOST

    script = f"""#!/bin/sh
# Wazuh agent install script for {agent_name} (tenant: {tenant})
# One-time use — generated by tenant.py enroll-agent
# Run as a normal user with sudo privileges.

MANAGER="{m}"
AGENT_NAME="{agent_name}"
AGENT_KEY="{agent_key}"
VERSION="{v}"

step() {{ echo "  [ ] $1..."; }}
ok()   {{ echo "  [✓] $1"; }}
fail() {{ echo "  [✗] $1"; exit 1; }}

echo ""
echo "  Wazuh Agent Enrollment"
echo "  Agent : $AGENT_NAME"
echo "  Server: $MANAGER"
echo ""

OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" = "Linux" ]; then
    if [ -f /etc/debian_version ]; then
        DISTRO="Debian/Ubuntu"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        DISTRO="RPM"
    else
        fail "Unsupported Linux distribution"
    fi
    ok "Detected: Linux ($DISTRO, $ARCH)"

    step "Adding Wazuh repository"
    if [ "$DISTRO" = "Debian/Ubuntu" ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \\
            --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import > /dev/null 2>&1
        sudo chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \\
            | sudo tee /etc/apt/sources.list.d/wazuh.list > /dev/null
        sudo apt-get update -qq > /dev/null 2>&1
    else
        sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH > /dev/null 2>&1
        sudo tee /etc/yum.repos.d/wazuh.repo > /dev/null << 'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
    fi
    ok "Repository added"

    step "Installing Wazuh agent $VERSION"
    if [ "$DISTRO" = "Debian/Ubuntu" ]; then
        sudo WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \\
            apt-get install -y -qq wazuh-agent=$VERSION-1 > /dev/null 2>&1 \\
            || fail "Installation failed"
    else
        sudo WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \\
            yum install -y -q wazuh-agent-$VERSION-1 > /dev/null 2>&1 \\
            || fail "Installation failed"
    fi
    ok "Agent installed"

    step "Importing agent key"
    echo "y" | sudo /var/ossec/bin/manage_agents -i "$AGENT_KEY" > /dev/null 2>&1 \\
        || fail "Key import failed"
    ok "Key imported"

    step "Starting Wazuh agent"
    sudo systemctl enable wazuh-agent > /dev/null 2>&1
    sudo systemctl restart wazuh-agent > /dev/null 2>&1 \\
        || fail "Failed to start agent"
    ok "Agent started"

elif [ "$OS" = "Darwin" ]; then
    ok "Detected: macOS ($ARCH)"

    if [ "$ARCH" = "arm64" ]; then
        PKG="wazuh-agent-$VERSION-1.arm64.pkg"
    else
        PKG="wazuh-agent-$VERSION-1.intel64.pkg"
    fi

    step "Downloading Wazuh agent"
    curl -s -o /tmp/wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/$PKG" \\
        || fail "Download failed"
    ok "Downloaded"

    step "Installing Wazuh agent"
    echo "WAZUH_MANAGER='$MANAGER'" > /tmp/wazuh_envs
    sudo installer -pkg /tmp/wazuh-agent.pkg -target / > /dev/null 2>&1 \\
        || fail "Installation failed"
    rm -f /tmp/wazuh-agent.pkg /tmp/wazuh_envs
    ok "Agent installed"

    step "Importing agent key"
    echo "y" | sudo /Library/Ossec/bin/manage_agents -i "$AGENT_KEY" > /dev/null 2>&1 \\
        || fail "Key import failed"
    ok "Key imported"

    step "Starting Wazuh agent"
    sudo /Library/Ossec/bin/wazuh-control start > /dev/null 2>&1 \\
        || fail "Failed to start agent"
    ok "Agent started"

else
    fail "Unsupported OS: $OS. For Windows, contact your administrator."
fi

echo ""
echo "  Enrollment complete! Your system is now being monitored."
echo ""
"""
    return script


def enroll_agent(tenant, agent_name):
    sep()
    print(f" Enrolling agent '{agent_name}' for tenant '{tenant}'")
    sep()

    # 1. Pre-register agent via Wazuh API
    log(f"Registering agent '{agent_name}' ...")
    result = wazuh("POST", "/agents", {"name": agent_name})

    if result.get("error") != 0:
        err(f"Failed to register agent: {result}")

    agent_id  = result["data"]["id"]
    agent_key = result["data"]["key"]
    ok(f"Agent registered: id={agent_id}")

    # 2. Assign agent to tenant group
    log(f"Assigning agent to group '{group_name(tenant)}' ...")
    result = wazuh("PUT", f"/agents/{agent_id}/group/{group_name(tenant)}")
    if result.get("error") == 0:
        ok(f"Agent assigned to group '{group_name(tenant)}'")
    else:
        log(f"Note: {result}")

    # 3. Generate install script
    log("Generating install script ...")
    script = generate_register_script(tenant, agent_name, agent_key)

    # 4. Save to register directory
    script_dir = os.path.join(REGISTER_DIR, tenant)
    os.makedirs(script_dir, exist_ok=True)
    script_path = os.path.join(script_dir, agent_name)
    with open(script_path, 'w') as f:
        f.write(script)
    os.chmod(script_path, 0o644)
    ok(f"Script saved to {script_path}")

    sep()
    print(f" Agent '{agent_name}' ready for tenant '{tenant}'.")
    print()
    print(f"  Send this ONE command to the tenant:")
    print()
    print(f"  curl -s https://{tenant}.zeroed.nl/register/{agent_name} | bash")
    print()
    print(f"  The script is OS-aware (Linux Debian/RPM, macOS Intel/Apple Silicon).")
    print(f"  After the agent connects, run:")
    print(f"  sudo python3 tenant.py sync-role {tenant}")
    sep()
    print()


# ── delete-agent ──────────────────────────────────────────────
def delete_agent(tenant, agent_name):
    sep()
    print(f" Deleting pre-registered agent '{agent_name}' for tenant '{tenant}'")
    sep()

    # Remove script file
    script_path = os.path.join(REGISTER_DIR, tenant, agent_name)
    if os.path.exists(script_path):
        os.remove(script_path)
        ok(f"Script deleted: {script_path}")
    else:
        log(f"No script found at {script_path}")

    # Remove from Wazuh regardless of status
    log(f"Looking up agent '{agent_name}' in Wazuh ...")
    result = wazuh("GET", f"/agents?name={agent_name}")
    agents = result.get("data", {}).get("affected_items", [])
    if agents:
        aid = agents[0]["id"]
        status = agents[0].get("status", "unknown")
        log(f"Found agent {aid} (status: {status})")
        # Use appropriate status filter for deletion
        if status == "never_connected":
            delete_url = f"/agents?agents_list={aid}&older_than=0s&status=never_connected"
        else:
            delete_url = f"/agents?agents_list={aid}&older_than=0s&status={status}"
        result = wazuh("DELETE", delete_url)
        if result.get("error") == 0:
            ok(f"Agent {aid} deleted from Wazuh")
        else:
            log(f"Note: {result}")
    else:
        log("Agent not found in Wazuh")

    sep()
    print(f" Done.")
    sep()
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

    elif command == "enroll-agent":
        if len(sys.argv) != 4: usage()
        enroll_agent(sys.argv[2], sys.argv[3])

    elif command == "delete-agent":
        if len(sys.argv) != 4: usage()
        delete_agent(sys.argv[2], sys.argv[3])

    else:
        usage()

