import json
import requests
import urllib3
import argparse
from requests.auth import HTTPBasicAuth
from copy import deepcopy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================================
# CLI MODES
# ==========================================================

parser = argparse.ArgumentParser()

parser.add_argument("--apply", action="store_true")
parser.add_argument("--check", action="store_true")

args = parser.parse_args()

APPLY = args.apply
CHECK = args.check
DRY_RUN = not APPLY
ALLOW_EMPTY_TENANTS = True

# ==========================================================
# CONFIG
# ==========================================================

WAZUH_API = "https://localhost:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "MyS3cr37P450r.*-"

OPENSEARCH_API = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "ais;aCahze9vi#"

VERIFY_SSL = False

TENANT_PREFIX = "tenant_"
ROLE_PREFIX = "role_"

# ==========================================================
# BASE ROLE TEMPLATE
# ==========================================================

BASE_ROLE_TEMPLATE = {
        "reserved": False,
        "hidden": False,
        "cluster_permissions": [
            "cluster_composite_ops"
            ],
        "index_permissions": [
            {
                "index_patterns": [
                    "wazuh-alerts*",
                    "wazuh-states-*"
                    ],
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "read",
                    "write"
                    ]
                },
            {
                "index_patterns": [
                    "wazuh-monitoring*"
                    ],
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "read",
                    "write"
                    ]
                }
            ],
        "tenant_permissions": [],
        "static": False
        }

# ==========================================================
# HELPERS (CONTROL PLANE CORE)
# ==========================================================

def normalize_group_config(raw):
    if not raw:
        return {"config": {"labels": []}}

    cfg = raw.get("config", {})

    return {
        "config": {
            "labels": cfg.get("labels", [])
        }
    }

def build_dls(agent_ids):
    if not agent_ids:
        return {
            "term": {
                "_id": "__no_access__"
            }
        }

    return {
        "terms": {
            "agent.id": agent_ids
        }
    }

def normalize(obj):
    return json.dumps(obj, sort_keys=True)


def diff_roles(old_role, new_role):
    old = normalize(old_role)
    new = normalize(new_role)

    if old == new:
        return False, None

    return True, {
            "old": old,
            "new": new
            }


def write_audit(tenant, role_name, diff):
    if not diff:
        return

    entry = {
            "tenant": tenant,
            "role": role_name,
            "diff": diff
            }

    with open("audit_log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def safe_agent_list(agent_ids, tenant):
    if not agent_ids:
        if ALLOW_EMPTY_TENANTS:
            print("  [INFO] Empty tenant → using deny-all DLS")
            return []
        raise ValueError(f"[SAFETY] Empty agent list for {tenant}")

    return agent_ids

def build_group_label(tenant):
    return {
            "labels": [
                {
                    "label": [
                        {
                            "key": "group",
                            "value": tenant
                            }
                        ]
                    }
                ]
            }


def get_current_group_label(group_cfg):
    try:
        return group_cfg["config"]["labels"]
    except Exception:
        return []

def group_label_needs_update(current_labels, tenant):
    if not current_labels:
        return True

    try:
        label = current_labels[0]["label"][0]
        return not (
                label.get("key") == "group" and
                label.get("value") == tenant
                )
    except Exception:
        return True



# ==========================================================
# WAZUH
# ==========================================================

def get_wazuh_token():
    r = requests.post(
            f"{WAZUH_API}/security/user/authenticate",
            auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
            verify=VERIFY_SSL
            )
    r.raise_for_status()
    return r.json()["data"]["token"]


def get_groups(token):
    r = requests.get(
            f"{WAZUH_API}/groups",
            headers={"Authorization": f"Bearer {token}"},
            verify=VERIFY_SSL
            )
    r.raise_for_status()

    return [g["name"] for g in r.json()["data"]["affected_items"]]


def get_agent_ids(token, group):
    r = requests.get(
            f"{WAZUH_API}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"group": group, "select": "id"},
            verify=VERIFY_SSL
            )
    r.raise_for_status()

    return sorted([a["id"] for a in r.json()["data"]["affected_items"]])

def get_group_configuration(token, group):
    r = requests.get(
            f"{WAZUH_API}/groups/{group}",
            headers={"Authorization": f"Bearer {token}"},
            verify=VERIFY_SSL
            )
    r.raise_for_status()
    return r.json()["data"]["affected_items"][0]


def put_group_label(token, group, payload):
    r = requests.put(
            f"{WAZUH_API}/groups/{group}",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            verify=VERIFY_SSL
            )
    r.raise_for_status()

# ==========================================================
# OPENSEARCH
# ==========================================================

def get_role(role_name):
    r = requests.get(
            f"{OPENSEARCH_API}/_plugins/_security/api/roles/{role_name}",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            verify=VERIFY_SSL
            )

    if r.status_code == 404:
        return None

    r.raise_for_status()
    return r.json()

def sanitize_role(role):
    role = deepcopy(role)

    role.pop("reserved", None)
    role.pop("hidden", None)
    role.pop("static", None)

    return role

def put_role(role_name, role_body):
    if DRY_RUN:
        print(f"  [DRY-RUN] PUT {role_name}")
        return

    r = requests.put(
            f"{OPENSEARCH_API}/_plugins/_security/api/roles/{role_name}",
            auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
            json=sanitize_role(role_body),
            verify=VERIFY_SSL
            )

    if not r.ok:
        print("\nOpenSearch response:")
        print(r.text)

    r.raise_for_status()
# ==========================================================
# ROLE RESOLUTION
# ==========================================================

def ensure_role(role_name):
    role_data = get_role(role_name)

    if role_data is None:
        print(f"  Role missing → creating {role_name}")
        return deepcopy(BASE_ROLE_TEMPLATE), True

    return role_data[role_name], False

# ==========================================================
# CONTROL PLANE SYNC
# ==========================================================

def sync_group(token, tenant):

    cfg = get_group_configuration(token, tenant)
    labels = normalize_group_config(cfg)["config"]["labels"]

    if not group_label_needs_update(labels, tenant):
        print("  Group label OK")
        return

    print("  Updating group label")

    payload = build_group_label(tenant)

    if CHECK:
        print("  [CHECK] group update skipped")
        return

    if DRY_RUN:
        print("  [DRY-RUN] group update skipped")
        return

    put_group_label(token, tenant, payload)


def sync_tenant(token, tenant):

    role_name = f"{ROLE_PREFIX}{tenant}"

    print(f"\n=== {tenant} ===")
    print(f"Role: {role_name}")

    agent_ids = safe_agent_list(get_agent_ids(token, tenant), tenant)
    print(f"Agents: {agent_ids}")

    current_role, created = ensure_role(role_name)

    desired_role = deepcopy(current_role)
    desired_role["tenant_permissions"] = [
            {
                "tenant_patterns": [tenant],
                "allowed_actions": [
                    "kibana_all_write"
                    ]
                }
            ]

    dls_obj = build_dls(agent_ids)


    for perm in desired_role.get("index_permissions", []):
        patterns = perm.get("index_patterns", [])
        is_monitoring = any(p.startswith("wazuh-monitoring") for p in patterns)

        if is_monitoring:
            perm["dls"] = json.dumps({
               "bool": {
                   "must": {
                       "match": {
                           "group": tenant
                           }
                       }
                   }
               }, indent=2)
        else:
            perm["dls"] = json.dumps(dls_obj, indent=2)
    changed, diff = diff_roles(current_role, desired_role)

    write_audit(tenant, role_name, diff)

    if not changed:
        print("  No drift detected")
        return

    print("  Drift detected")

    if CHECK:
        print("  [CHECK] changes detected but not applied")
        return

    if DRY_RUN:
        print("  [DRY-RUN] changes detected but not applied")
        return

    put_role(role_name, desired_role)
    print("  Role updated")

# ==========================================================
# MAIN LOOP
# ==========================================================

def main():
    print(f"DRY_RUN={DRY_RUN} CHECK={CHECK}")

    token = get_wazuh_token()
    groups = get_groups(token)

    tenants = [g for g in groups if g.startswith(TENANT_PREFIX)]

    print(f"Found tenants: {len(tenants)}")

    for tenant in sorted(tenants):
        try:
            sync_tenant(token, tenant)
        except Exception as e:
            print(f"[ERROR][TENANT] {tenant}: {e}")

        try:
            sync_group(token, tenant)
        except Exception as e:
            print(f"[ERROR][GROUP] {tenant}: {e}")


if __name__ == "__main__":
    main()
