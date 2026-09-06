#!/usr/bin/env python3
"""
Wazuh SCA summary importer.

Leest de actuele SCA-samenvatting van alle actieve Windows-agents uit de
Wazuh Server API en schrijft per agent/policy één actueel document naar
de OpenSearch-index `wazuh-sca-summary`.

Benodigd:
    pip install requests opensearch-py

Uitvoeren:
    source /opt/wazuh-sca-importer/venv/bin/activate
    python /opt/wazuh-sca-importer/sca_import_summary.py
"""

from __future__ import annotations

import getpass
import sys
from datetime import datetime, timezone
from typing import Any

import requests
import urllib3
from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API_URL = "https://127.0.0.1:55000"
INDEXER_HOST = "127.0.0.1"
INDEXER_PORT = 9200
INDEX_NAME = "wazuh-sca-summary"


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
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def create_or_update_index_mapping(client: OpenSearch) -> None:
    properties = {
        "@timestamp": {"type": "date"},
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
            }
        },
        "score": {"type": "integer"},
        "passed": {"type": "integer"},
        "failed": {"type": "integer"},
        "invalid": {"type": "integer"},
        "total_checks": {"type": "integer"},
        "passed_percentage": {"type": "float"},
        "failed_percentage": {"type": "float"},
        "scan_start": {"type": "date"},
        "scan_end": {"type": "date"},
        "collected_at": {"type": "date"},
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


def percentage(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((value / total) * 100, 2)


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
        timeout=60,
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
    indexed_count = 0

    for agent in agents:
        os_data = agent.get("os", {})
        os_name = str(os_data.get("name", ""))

        if "Windows" not in os_name:
            continue

        agent_id = str(agent["id"])
        agent_name = str(agent["name"])

        sca_response = wazuh_get(f"/sca/{agent_id}", token)
        policies = sca_response["data"]["affected_items"]

        if not policies:
            print(f"{agent_name} ({agent_id}): geen SCA-data")
            continue

        for policy in policies:
            total_checks = int(policy.get("total_checks") or 0)
            passed = int(policy.get("pass") or 0)
            failed = int(policy.get("fail") or 0)
            invalid = int(policy.get("invalid") or 0)

            endpoint_type = "server" if "Server" in os_name else "workstation"
            policy_id = str(policy.get("policy_id") or "unknown")

            document = {
                "@timestamp": policy.get("end_scan") or collected_at,
                "agent": {
                    "id": agent_id,
                    "name": agent_name,
                },
                "os": {
                    "name": os_name,
                    "version": os_data.get("version"),
                },
                "endpoint_type": endpoint_type,
                "policy": {
                    "id": policy_id,
                    "name": policy.get("name"),
                },
                "score": int(policy.get("score") or 0),
                "passed": passed,
                "failed": failed,
                "invalid": invalid,
                "total_checks": total_checks,
                "passed_percentage": percentage(passed, total_checks),
                "failed_percentage": percentage(failed, total_checks),
                "scan_start": policy.get("start_scan"),
                "scan_end": policy.get("end_scan"),
                "collected_at": collected_at,
            }

            # Eén actueel document per agent en policy.
            # Bij een volgende run wordt ditzelfde document bijgewerkt.
            document_id = f"{agent_id}-{policy_id}"

            indexer.index(
                index=INDEX_NAME,
                id=document_id,
                body=document,
                refresh=True,
            )

            indexed_count += 1
            print(
                f"{agent_name} ({agent_id}): "
                f"{document['score']}% - {failed} failed"
            )

    print(f"\nKlaar. {indexed_count} actuele documenten geïndexeerd.")


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

