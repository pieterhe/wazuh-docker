#!/usr/bin/env python3
"""
Wazuh SCA checks importer.

Leest alle actuele SCA-checks van alle actieve Windows-agents uit de
Wazuh Server API en schrijft per agent/policy/check één actueel document
naar de OpenSearch-index `wazuh-sca-checks`.

Benodigd:
    pip install requests opensearch-py

Uitvoeren:
    cd /opt/wazuh-sca-importer
    source venv/bin/activate
    python sca_import_checks.py
"""

from __future__ import annotations

import getpass
import sys
from datetime import datetime, timezone
from typing import Any

import requests
import urllib3
from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import OpenSearchException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API_URL = "https://127.0.0.1:55000"
INDEXER_HOST = "127.0.0.1"
INDEXER_PORT = 9200
INDEX_NAME = "wazuh-sca-checks"
API_PAGE_SIZE = 500


def wazuh_authenticate(username: str, password: str) -> str:
    response = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(username, password),
        params={"raw": "true"},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    return response.text.strip().strip('"')


def wazuh_get(path: str, token: str) -> dict[str, Any]:
    response = requests.get(
        f"{WAZUH_API_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=120,
    )
    response.raise_for_status()
    return response.json()


def create_or_update_index_mapping(client: OpenSearch) -> None:
    properties = {
        "@timestamp": {"type": "date"},
        "collected_at": {"type": "date"},
        "scan_end": {"type": "date"},
        "agent": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
            }
        },
        "os": {
            "properties": {
                "name": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "version": {"type": "keyword"},
            }
        },
        "endpoint_type": {"type": "keyword"},
        "policy": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "score": {"type": "integer"},
                "passed": {"type": "integer"},
                "failed": {"type": "integer"},
                "invalid": {"type": "integer"},
                "total_checks": {"type": "integer"},
            }
        },
        "check": {
            "properties": {
                "id": {"type": "integer"},
                "title": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 4096,
                        }
                    },
                },
                "result": {"type": "keyword"},
                "description": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 4096,
                        }
                    },
                },
                "rationale": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 4096,
                        }
                    },
                },
                "reason": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 4096,
                        }
                    },
                },
                "remediation": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 4096,
                        }
                    },
                },
                "command": {"type": "text"},
                "condition": {"type": "keyword"},
                "references": {"type": "keyword", "ignore_above": 2048},
            }
        },
        "compliance": {
            "type": "nested",
            "properties": {
                "key": {"type": "keyword"},
                "value": {"type": "keyword"},
            },
        },
        "cis_control": {"type": "keyword"},
        "cis_section": {"type": "keyword"},
        "is_failed": {"type": "boolean"},
        "is_passed": {"type": "boolean"},
        "is_not_applicable": {"type": "boolean"},
    }

    if not client.indices.exists(index=INDEX_NAME):
        client.indices.create(
            index=INDEX_NAME,
            body={
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
                "mappings": {"properties": properties},
            },
        )
        print(f"Index aangemaakt: {INDEX_NAME}")
        return

    client.indices.put_mapping(
        index=INDEX_NAME,
        body={"properties": properties},
    )
    print(f"Mapping gecontroleerd/bijgewerkt: {INDEX_NAME}")


def extract_cis_values(compliance: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    cis_control: str | None = None
    cis_section: str | None = None

    for item in compliance:
        if str(item.get("key", "")).lower() != "cis":
            continue

        value = str(item.get("value", "")).strip()
        if not value:
            continue

        cis_control = value
        parts = value.split(".")
        cis_section = ".".join(parts[:2]) if len(parts) >= 2 else value
        break

    return cis_control, cis_section


def get_all_checks(agent_id: str, policy_id: str, token: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    offset = 0

    while True:
        response = wazuh_get(
            f"/sca/{agent_id}/checks/{policy_id}?offset={offset}&limit={API_PAGE_SIZE}",
            token,
        )
        data = response["data"]
        batch = data.get("affected_items", [])
        checks.extend(batch)

        total = int(data.get("total_affected_items") or len(checks))
        offset += len(batch)

        if not batch or offset >= total:
            break

    return checks


def main() -> None:
    print("=== Wazuh API ===")
    wazuh_username = input("Wazuh API username [wazuh-wui]: ").strip() or "wazuh-wui"
    wazuh_password = getpass.getpass("Wazuh API password: ")

    print("\n=== Wazuh Indexer ===")
    indexer_username = input("Indexer username [admin]: ").strip() or "admin"
    indexer_password = getpass.getpass("Indexer password: ")

    token = wazuh_authenticate(wazuh_username, wazuh_password)

    indexer = OpenSearch(
        hosts=[{"host": INDEXER_HOST, "port": INDEXER_PORT}],
        http_auth=(indexer_username, indexer_password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=120,
    )

    if not indexer.ping():
        raise RuntimeError("Kan geen verbinding maken met de Wazuh Indexer")

    create_or_update_index_mapping(indexer)

    agents_response = wazuh_get(
        "/agents?status=active&select=id,name,os.name,os.version",
        token,
    )
    agents = agents_response["data"]["affected_items"]

    collected_at = datetime.now(timezone.utc).isoformat()
    total_indexed = 0

    for agent in agents:
        os_data = agent.get("os", {})
        os_name = str(os_data.get("name", ""))

        if "Windows" not in os_name:
            continue

        agent_id = str(agent["id"])
        agent_name = str(agent["name"])
        endpoint_type = "server" if "Server" in os_name else "workstation"

        sca_response = wazuh_get(f"/sca/{agent_id}", token)
        policies = sca_response["data"].get("affected_items", [])

        if not policies:
            print(f"{agent_name} ({agent_id}): geen SCA-data")
            continue

        for policy in policies:
            policy_id = str(policy.get("policy_id") or "unknown")
            policy_name = policy.get("name")
            scan_end = policy.get("end_scan") or collected_at

            checks = get_all_checks(agent_id, policy_id, token)

            actions = []
            for check in checks:
                result = str(check.get("result") or "unknown").lower()
                compliance = check.get("compliance") or []
                cis_control, cis_section = extract_cis_values(compliance)
                check_id = int(check.get("id") or 0)

                document = {
                    "@timestamp": scan_end,
                    "collected_at": collected_at,
                    "scan_end": scan_end,
                    "agent": {"id": agent_id, "name": agent_name},
                    "os": {"name": os_name, "version": os_data.get("version")},
                    "endpoint_type": endpoint_type,
                    "policy": {
                        "id": policy_id,
                        "name": policy_name,
                        "score": int(policy.get("score") or 0),
                        "passed": int(policy.get("pass") or 0),
                        "failed": int(policy.get("fail") or 0),
                        "invalid": int(policy.get("invalid") or 0),
                        "total_checks": int(policy.get("total_checks") or 0),
                    },
                    "check": {
                        "id": check_id,
                        "title": check.get("title"),
                        "result": result,
                        "description": check.get("description"),
                        "rationale": check.get("rationale"),
                        "reason": check.get("reason"),
                        "remediation": check.get("remediation"),
                        "command": check.get("command"),
                        "condition": check.get("condition"),
                        "references": check.get("references"),
                    },
                    "compliance": compliance,
                    "cis_control": cis_control,
                    "cis_section": cis_section,
                    "is_failed": result == "failed",
                    "is_passed": result == "passed",
                    "is_not_applicable": result in {"not applicable", "not_applicable", "not-applicable"},
                }

                document_id = f"{agent_id}-{policy_id}-{check_id}"
                actions.append({
                    "_op_type": "index",
                    "_index": INDEX_NAME,
                    "_id": document_id,
                    "_source": document,
                })

            if actions:
                success_count, errors = helpers.bulk(
                    indexer,
                    actions,
                    refresh=True,
                    raise_on_error=False,
                    request_timeout=120,
                )
                total_indexed += success_count
                print(f"{agent_name} ({agent_id}) / {policy_id}: {success_count} checks geïndexeerd")
                if errors:
                    print(f"Waarschuwing: {len(errors)} documenten niet geïndexeerd", file=sys.stderr)
            else:
                print(f"{agent_name} ({agent_id}) / {policy_id}: geen checks gevonden")

    print(f"\nKlaar. {total_indexed} actuele SCA-checks geïndexeerd.")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as exc:
        print(f"Wazuh API-fout: {exc}", file=sys.stderr)
        sys.exit(1)
    except OpenSearchException as exc:
        print(f"Indexer-fout: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyError as exc:
        print(f"Onverwachte API-response; ontbrekend veld: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Fout: {exc}", file=sys.stderr)
        sys.exit(1)
