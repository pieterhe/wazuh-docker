#!/usr/bin/env python3

import argparse
import configparser
import json
import os
import re
import sys

import requests
import urllib3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")


def normalize_tenant_name(value):
    tenant = str(value).strip()

    if not re.fullmatch(r"tenant_[A-Za-z0-9_-]+", tenant):
        raise ValueError(
            "Invalid tenant name. Use for example: tenant_picard"
        )

    return tenant


def load_config():
    config = configparser.ConfigParser()

    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Config file not found: {CONFIG_FILE}")

    config.read(CONFIG_FILE)
    return config


def as_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def wazuh_api_login(config):
    api_url = config["wazuh_api"]["url"].rstrip("/")
    username = config["wazuh_api"]["username"]
    password = config["wazuh_api"]["password"]
    verify_ssl = as_bool(config["wazuh_api"].get("verify_ssl", "false"))

    response = requests.post(
        f"{api_url}/security/user/authenticate",
        params={"raw": "true"},
        auth=(username, password),
        verify=verify_ssl,
        timeout=30,
    )

    response.raise_for_status()

    token = response.text.strip()

    if not token:
        raise RuntimeError("Wazuh API returned an empty authentication token.")

    return token


def collect_endpoints(config, token):
    api_url = config["wazuh_api"]["url"].rstrip("/")
    tenant = config["tenant"]["name"]
    verify_ssl = as_bool(config["wazuh_api"].get("verify_ssl", "false"))

    response = requests.get(
        f"{api_url}/groups/{tenant}/agents",
        headers={
            "Authorization": f"Bearer {token}"
        },
        params={
            "limit": 500
        },
        verify=verify_ssl,
        timeout=30,
    )

    response.raise_for_status()

    payload = response.json()
    agents = payload["data"]["affected_items"]

    active = 0
    disconnected = 0
    agent_ids = []

    for agent in agents:
        agent_id = agent.get("id")

        if agent_id:
            agent_ids.append(agent_id)

        status = str(agent.get("status", "")).lower()

        if status == "active":
            active += 1
        elif status == "disconnected":
            disconnected += 1

    return {
        "total": len(agents),
        "active": active,
        "disconnected": disconnected,
        "agent_ids": agent_ids,
    }


def indexer_request(config, index, body):
    indexer_url = config["indexer"]["url"].rstrip("/")
    username = config["indexer"]["username"]
    password = config["indexer"]["password"]
    verify_ssl = as_bool(config["indexer"].get("verify_ssl", "false"))

    response = requests.get(
        f"{indexer_url}/{index}/_search",
        auth=(username, password),
        headers={
            "Content-Type": "application/json"
        },
        json=body,
        verify=verify_ssl,
        timeout=60,
    )

    response.raise_for_status()
    return response.json()


def collect_configuration(config):
    tenant = config["tenant"]["name"]

    summary_index = f"wazuh-sca-summary-{tenant}"

    # Read the tenant-specific SCA summaries. These documents are the
    # authoritative source for which endpoints belong in the SCA section.
    summary_body = {
        "size": 500,
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "policy.id",
            "policy.name",
            "score",
            "passed",
            "failed",
            "invalid",
            "total_checks",
            "passed_percentage",
            "failed_percentage",
            "scan_start",
            "scan_end"
        ],
        "query": {
            "match_all": {}
        },
        "sort": [
            {
                "passed_percentage": {
                    "order": "asc"
                }
            }
        ]
    }

    summary_payload = indexer_request(
        config,
        summary_index,
        summary_body,
    )

    endpoint_compliance = []
    sca_agent_ids = []
    compliance_values = []

    for hit in (
        summary_payload
        .get("hits", {})
        .get("hits", [])
    ):
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        policy = source.get("policy", {})

        agent_id = agent.get("id")
        agent_name = agent.get("name")

        if agent_id:
            sca_agent_ids.append(str(agent_id))

        passed_percentage = source.get("passed_percentage")

        if passed_percentage is None:
            passed_percentage = source.get("score", 0)

        try:
            compliance = float(passed_percentage or 0)
        except (TypeError, ValueError):
            compliance = 0.0

        compliance_values.append(compliance)

        endpoint_compliance.append({
            "agent_id": agent_id,
            "endpoint": agent_name,
            "compliance": round(compliance, 2),
            "passed": int(source.get("passed", 0) or 0),
            "failed": int(source.get("failed", 0) or 0),
            "invalid": int(source.get("invalid", 0) or 0),
            "total_checks": int(source.get("total_checks", 0) or 0),
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "scan_end": source.get("scan_end"),
        })

    assessed = len({
        item["agent_id"]
        for item in endpoint_compliance
        if item.get("agent_id")
    })

    if compliance_values:
        average = sum(compliance_values) / len(compliance_values)
    else:
        average = 0.0

    # The detailed SCA checks live in a shared index. Tenant isolation is
    # enforced here by filtering only on agent IDs obtained from the
    # tenant-specific summary index above.
    top_failed_checks = []

    if sca_agent_ids:
        checks_index = "wazuh-sca-checks"

        failed_checks_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "terms": {
                                "agent.id": sorted(set(sca_agent_ids))
                            }
                        },
                        {
                            "term": {
                                "is_failed": True
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "top_failed_checks": {
                    "terms": {
                        "field": "check.id",
                        "size": 10,
                        "order": {
                            "_count": "desc"
                        }
                    },
                    "aggs": {
                        "title": {
                            "terms": {
                                "field": "check.title.keyword",
                                "size": 1
                            }
                        },
                        "endpoints": {
                            "terms": {
                                "field": "agent.name.keyword",
                                "size": 100
                            }
                        }
                    }
                }
            }
        }

        failed_payload = indexer_request(
            config,
            checks_index,
            failed_checks_body,
        )

        for bucket in (
            failed_payload
            .get("aggregations", {})
            .get("top_failed_checks", {})
            .get("buckets", [])
        ):
            title_buckets = (
                bucket
                .get("title", {})
                .get("buckets", [])
            )

            title = (
                title_buckets[0].get("key")
                if title_buckets
                else f"SCA check {bucket.get('key')}"
            )

            endpoint_buckets = (
                bucket
                .get("endpoints", {})
                .get("buckets", [])
            )

            endpoints = [
                endpoint_bucket.get("key")
                for endpoint_bucket in endpoint_buckets
                if endpoint_bucket.get("key")
            ]

            top_failed_checks.append({
                "check_id": bucket.get("key"),
                "title": title,
                "affected_endpoints": len(endpoints),
                "failure_count": int(bucket.get("doc_count", 0)),
                "endpoints": endpoints,
            })

    return {
        "average_compliance": round(float(average), 1),
        "assessed_endpoints": int(assessed),
        "endpoint_compliance": endpoint_compliance,
        "top_failed_checks": top_failed_checks,
    }


def collect_vulnerabilities(config, agent_ids):
    if not agent_ids:
        return {
            "critical": 0,
            "high": 0,
        }

    index = "wazuh-states-vulnerabilities-wazuh.manager"

    body = {
        "size": 0,
        "query": {
            "terms": {
                "agent.id": agent_ids
            }
        },
        "aggs": {
            "severity": {
                "filters": {
                    "filters": {
                        "critical": {
                            "term": {
                                "vulnerability.severity": "Critical"
                            }
                        },
                        "high": {
                            "term": {
                                "vulnerability.severity": "High"
                            }
                        }
                    }
                }
            }
        }
    }

    payload = indexer_request(config, index, body)

    buckets = (
        payload.get("aggregations", {})
        .get("severity", {})
        .get("buckets", {})
    )

    return {
        "critical": int(
            buckets.get("critical", {}).get("doc_count", 0)
        ),
        "high": int(
            buckets.get("high", {}).get("doc_count", 0)
        ),
    }

def collect_vulnerability_details(config, agent_ids):
    if not agent_ids:
        return {
            "top_endpoints": []
        }

    index = "wazuh-states-vulnerabilities-wazuh.manager"

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "terms": {
                            "agent.id": agent_ids
                        }
                    },
                    {
                        "terms": {
                            "vulnerability.severity": [
                                "Critical",
                                "High"
                            ]
                        }
                    }
                ]
            }
        },
        "aggs": {
            "endpoints": {
                "terms": {
                    "field": "agent.name",
                    "size": 20,
                    "order": {
                        "_count": "desc"
                    }
                },
                "aggs": {
                    "critical": {
                        "filter": {
                            "term": {
                                "vulnerability.severity": "Critical"
                            }
                        }
                    },
                    "high": {
                        "filter": {
                            "term": {
                                "vulnerability.severity": "High"
                            }
                        }
                    }
                }
            }
        }
    }

    payload = indexer_request(config, index, body)

    buckets = (
        payload.get("aggregations", {})
        .get("endpoints", {})
        .get("buckets", [])
    )

    top_endpoints = []

    for bucket in buckets:
        critical = int(
            bucket.get("critical", {}).get("doc_count", 0)
        )

        high = int(
            bucket.get("high", {}).get("doc_count", 0)
        )

        top_endpoints.append({
            "endpoint": bucket.get("key"),
            "critical": critical,
            "high": high,
            "total": critical + high,
        })

    return {
        "top_endpoints": top_endpoints
    }


def collect_security_activity(config):
    tenant = config["tenant"]["name"]
    period_start = config["report"]["period_start"]
    period_end = config["report"]["period_end"]

    index = f"wazuh-alerts-4.x-{tenant}-*"

    period_filter = {
        "range": {
            "@timestamp": {
                "gte": period_start,
                "lt": period_end
            }
        }
    }

    # Keep the existing counters exactly as they were used by the report.
    summary_body = {
        "size": 0,
        "query": period_filter,
        "aggs": {
            "defender_threat_detections": {
                "filter": {
                    "term": {
                        "rule.id": "62123"
                    }
                }
            },
            "endpoint_isolations": {
                "filter": {
                    "term": {
                        "rule.groups": "endpoint_isolated"
                    }
                }
            },
            "active_responses": {
                "filter": {
                    "bool": {
                        "filter": [
                            {
                                "term": {
                                    "rule.id": "657"
                                }
                            },
                            {
                                "term": {
                                    "data.command": "add"
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    summary_payload = indexer_request(config, index, summary_body)
    aggregations = summary_payload.get("aggregations", {})

    defender_count = int(
        aggregations
        .get("defender_threat_detections", {})
        .get("doc_count", 0)
    )

    isolation_count = int(
        aggregations
        .get("endpoint_isolations", {})
        .get("doc_count", 0)
    )

    active_response_count = int(
        aggregations
        .get("active_responses", {})
        .get("doc_count", 0)
    )

    # Defender details: what threat, how often and on which endpoint(s).
    defender_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    period_filter,
                    {
                        "term": {
                            "rule.id": "62123"
                        }
                    }
                ]
            }
        },
        "aggs": {
            "threats": {
                "terms": {
                    "field": "data.win.eventdata.threat Name",
                    "size": 50,
                    "missing": "Unknown threat"
                },
                "aggs": {
                    "endpoints": {
                        "terms": {
                            "field": "agent.name",
                            "size": 50,
                            "missing": "Unknown endpoint"
                        }
                    },
                    "severities": {
                        "terms": {
                            "field": "data.win.eventdata.severity Name",
                            "size": 10,
                            "missing": "Unknown"
                        }
                    }
                }
            }
        }
    }

    defender_payload = indexer_request(config, index, defender_body)

    defender_details = []

    for threat_bucket in (
        defender_payload
        .get("aggregations", {})
        .get("threats", {})
        .get("buckets", [])
    ):
        endpoints = [
            {
                "endpoint": endpoint_bucket.get("key"),
                "count": int(endpoint_bucket.get("doc_count", 0)),
            }
            for endpoint_bucket in (
                threat_bucket
                .get("endpoints", {})
                .get("buckets", [])
            )
        ]

        severities = [
            {
                "severity": severity_bucket.get("key"),
                "count": int(severity_bucket.get("doc_count", 0)),
            }
            for severity_bucket in (
                threat_bucket
                .get("severities", {})
                .get("buckets", [])
            )
        ]

        defender_details.append({
            "threat": threat_bucket.get("key"),
            "count": int(threat_bucket.get("doc_count", 0)),
            "endpoints": endpoints,
            "severities": severities,
        })

    # Active Response details. The current environment records these as
    # rule 657 + data.command=add, with the executed program in
    # data.parameters.program.
    active_response_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    period_filter,
                    {
                        "term": {
                            "rule.id": "657"
                        }
                    },
                    {
                        "term": {
                            "data.command": "add"
                        }
                    }
                ]
            }
        },
        "aggs": {
            "programs": {
                "terms": {
                    "field": "data.parameters.program",
                    "size": 50,
                    "missing": "Unknown active response"
                },
                "aggs": {
                    "endpoints": {
                        "terms": {
                            "field": "agent.name",
                            "size": 50,
                            "missing": "Unknown endpoint"
                        }
                    }
                }
            }
        }
    }

    active_response_payload = indexer_request(
        config,
        index,
        active_response_body,
    )

    active_response_details = []

    for program_bucket in (
        active_response_payload
        .get("aggregations", {})
        .get("programs", {})
        .get("buckets", [])
    ):
        endpoints = [
            {
                "endpoint": endpoint_bucket.get("key"),
                "count": int(endpoint_bucket.get("doc_count", 0)),
            }
            for endpoint_bucket in (
                program_bucket
                .get("endpoints", {})
                .get("buckets", [])
            )
        ]

        active_response_details.append({
            "response": program_bucket.get("key"),
            "count": int(program_bucket.get("doc_count", 0)),
            "endpoints": endpoints,
        })

    # Isolation details. The screenshots show the useful context in
    # data.win.eventdata.data as a structured-looking text value. We keep
    # the raw context in the collector output so the report generator can
    # show the reason/threat without losing information.
    isolation_body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [
                    period_filter,
                    {
                        "term": {
                            "rule.groups": "endpoint_isolated"
                        }
                    }
                ]
            }
        },
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "rule.id",
            "rule.description",
            "data.win.system.computer",
            "data.win.eventdata.data"
        ],
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    isolation_payload = indexer_request(config, index, isolation_body)

    isolation_details = []

    for hit in (
        isolation_payload
        .get("hits", {})
        .get("hits", [])
    ):
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        rule = source.get("rule", {})
        win = source.get("data", {}).get("win", {})
        system = win.get("system", {})
        eventdata = win.get("eventdata", {})

        isolation_details.append({
            "timestamp": source.get("@timestamp"),
            "endpoint": agent.get("name"),
            "agent_id": agent.get("id"),
            "computer": system.get("computer"),
            "rule_id": rule.get("id"),
            "description": rule.get("description"),
            "context": eventdata.get("data"),
        })

    return {
        "defender_threat_detections": defender_count,
        "endpoint_isolations": isolation_count,
        "active_responses": active_response_count,
        "defender_threat_details": defender_details,
        "active_response_details": active_response_details,
        "endpoint_isolation_details": isolation_details,
    }


def build_report(config):
    tenant = config["tenant"]["name"]
    period_start = config["report"]["period_start"]
    period_end = config["report"]["period_end"]

    print(f"Collecting report data for: {tenant}")

    print("  [1/4] Endpoint information...")
    token = wazuh_api_login(config)
    endpoints = collect_endpoints(config, token)

    print("  [2/4] Configuration compliance...")
    configuration = collect_configuration(config)

    print("  [3/4] Vulnerabilities...")
    vulnerabilities = collect_vulnerabilities(
        config,
        endpoints["agent_ids"],
    )

    vulnerability_details = collect_vulnerability_details(
        config,
        endpoints["agent_ids"],
    )

    vulnerabilities["top_endpoints"] = (
        vulnerability_details["top_endpoints"]
    ) 

    print("  [4/4] Security activity...")
    security_activity = collect_security_activity(config)

    return {
        "tenant": tenant,
        "reporting_period": {
            "from": period_start,
            "to": period_end,
        },
        "endpoints": {
            "total": endpoints["total"],
            "active": endpoints["active"],
            "disconnected": endpoints["disconnected"],
        },
        "configuration": {
            "average_compliance": configuration["average_compliance"],
            "assessed_endpoints": configuration["assessed_endpoints"],
            "total_endpoints": endpoints["total"],
            "endpoint_compliance": configuration["endpoint_compliance"],
            "top_failed_checks": configuration["top_failed_checks"],
        },
        "vulnerabilities": vulnerabilities,
        "security_activity": security_activity,
    }


def save_report(config, report):
    output_dir = config["report"]["output_dir"]

    if not os.path.isabs(output_dir):
        output_dir = os.path.join(BASE_DIR, output_dir)

    tenant = report["tenant"]

    os.makedirs(output_dir, exist_ok=True)

    filename = os.path.join(
        output_dir,
        f"{tenant}-collector-test.json"
    )

    with open(filename, "w", encoding="utf-8") as handle:
        json.dump(
            report,
            handle,
            indent=4,
            ensure_ascii=False,
        )

    return filename


def main():
    parser = argparse.ArgumentParser(
        description="Collect Wazuh report data for a specific tenant."
    )
    parser.add_argument(
        "tenant",
        help="Tenant name, for example: tenant_picard",
    )
    args = parser.parse_args()

    try:
        tenant = normalize_tenant_name(args.tenant)
        config = load_config()

        if "tenant" not in config:
            config.add_section("tenant")

        # The command-line tenant is authoritative. This removes the need
        # for a separate collector/config file per tenant.
        config["tenant"]["name"] = tenant

        if (
            not as_bool(config["indexer"].get("verify_ssl", "false"))
            or not as_bool(config["wazuh_api"].get("verify_ssl", "false"))
        ):
            urllib3.disable_warnings(
                urllib3.exceptions.InsecureRequestWarning
            )

        report = build_report(config)
        output_file = save_report(config, report)

        print()
        print("======================================")
        print("WAZUH REPORT COLLECTOR - TEST RESULT")
        print("======================================")
        print(json.dumps(report, indent=4))
        print()
        print(f"Tenant: {tenant}")
        print(f"Saved to: {output_file}")

    except requests.exceptions.ConnectionError as exc:
        print()
        print("ERROR: Connection failed.")
        print(exc)
        sys.exit(1)

    except requests.exceptions.HTTPError as exc:
        print()
        print("ERROR: HTTP request failed.")
        print(exc)

        if exc.response is not None:
            print(exc.response.text)

        sys.exit(1)

    except Exception as exc:
        print()
        print(f"ERROR: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
