#!/usr/bin/env python3
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
TENANT_GROUP_PREFIX = "tenant_"
SCA_INDEX_PREFIX = "wazuh-sca-summary-"
AGENT_LIMIT = 500


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


def percentage(value: int, total: int) -> float:
    return 0.0 if total <= 0 else round((value / total) * 100, 2)


def get_tenant_groups(agent: dict[str, Any]) -> list[str]:
    raw_groups = agent.get("group", [])
    if isinstance(raw_groups, str):
        groups = [raw_groups]
    elif isinstance(raw_groups, list):
        groups = [str(group) for group in raw_groups]
    else:
        groups = []

    return sorted({
        group.strip()
        for group in groups
        if group.strip().startswith(TENANT_GROUP_PREFIX)
    })


def get_target_index(agent: dict[str, Any]) -> tuple[str | None, str | None]:
    tenant_groups = get_tenant_groups(agent)

    if not tenant_groups:
        return None, None

    if len(tenant_groups) > 1:
        raise ValueError(
            "meerdere tenantgroepen gevonden: " + ", ".join(tenant_groups)
        )

    tenant_group = tenant_groups[0]
    return tenant_group, f"{SCA_INDEX_PREFIX}{tenant_group}"


def main() -> None:
    print("=== Wazuh API ===")
    wazuh_username = input(
        "Wazuh API username [wazuh-wui]: "
    ).strip() or "wazuh-wui"
    wazuh_password = getpass.getpass("Wazuh API password: ")

    print("\n=== Wazuh Indexer ===")
    indexer_username = input(
        "Indexer username [admin]: "
    ).strip() or "admin"
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

    agents_response = wazuh_get(
        f"/agents?status=active&limit={AGENT_LIMIT}",
        token,
    )
    agents = agents_response["data"]["affected_items"]

    collected_at = datetime.now(timezone.utc).isoformat()
    indexed_count = 0
    skipped_non_windows = 0
    skipped_no_tenant = 0
    skipped_multiple_tenants = 0
    skipped_missing_index = 0
    skipped_no_sca = 0
    index_exists_cache: dict[str, bool] = {}

    print(f"\nActieve agents gevonden: {len(agents)}")
    print("Start multi-tenant SCA-import...\n")

    for agent in agents:
        os_data = agent.get("os") or {}
        os_name = str(os_data.get("name", ""))

        if "windows" not in os_name.lower():
            skipped_non_windows += 1
            continue

        agent_id = str(agent.get("id", "unknown"))
        agent_name = str(agent.get("name", "unknown"))

        try:
            tenant_group, index_name = get_target_index(agent)
        except ValueError as exc:
            skipped_multiple_tenants += 1
            print(f"[OVERSLAGEN] {agent_name} ({agent_id}): {exc}")
            continue

        if tenant_group is None or index_name is None:
            skipped_no_tenant += 1
            print(
                f"[OVERSLAGEN] {agent_name} ({agent_id}): "
                "geen tenantgroep gevonden"
            )
            continue

        if index_name not in index_exists_cache:
            index_exists_cache[index_name] = bool(
                indexer.indices.exists(index=index_name)
            )

        if not index_exists_cache[index_name]:
            skipped_missing_index += 1
            print(
                f"[OVERSLAGEN] {agent_name} ({agent_id}): "
                f"index '{index_name}' bestaat niet"
            )
            continue

        sca_response = wazuh_get(f"/sca/{agent_id}", token)
        policies = sca_response["data"].get("affected_items", [])

        if not policies:
            skipped_no_sca += 1
            print(f"[GEEN SCA] {agent_name} ({agent_id}) -> {tenant_group}")
            continue

        for policy in policies:
            total_checks = int(policy.get("total_checks") or 0)
            passed = int(policy.get("pass") or 0)
            failed = int(policy.get("fail") or 0)
            invalid = int(policy.get("invalid") or 0)
            endpoint_type = (
                "server" if "server" in os_name.lower() else "workstation"
            )
            policy_id = str(policy.get("policy_id") or "unknown")

            document = {
                "@timestamp": policy.get("end_scan") or collected_at,
                "agent": {"id": agent_id, "name": agent_name},
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

            document_id = f"{agent_id}-{policy_id}"

            indexer.index(
                index=index_name,
                id=document_id,
                body=document,
                refresh=True,
            )

            indexed_count += 1
            print(
                f"[OK] {agent_name} ({agent_id}) -> {index_name}: "
                f"{document['score']}% - {failed} failed"
            )

    print("\n=== Resultaat ===")
    print(f"Geïndexeerde documenten : {indexed_count}")
    print(f"Geen Windows-agent       : {skipped_non_windows}")
    print(f"Geen tenantgroep         : {skipped_no_tenant}")
    print(f"Meerdere tenantgroepen   : {skipped_multiple_tenants}")
    print(f"Ontbrekende tenantindex  : {skipped_missing_index}")
    print(f"Geen SCA-data            : {skipped_no_sca}")


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
        print(
            f"Onverwachte API-response; ontbrekend veld: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"Fout: {exc}", file=sys.stderr)
        sys.exit(1)
