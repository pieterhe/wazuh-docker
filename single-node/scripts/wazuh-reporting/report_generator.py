#!/usr/bin/env python3

import argparse
import json
import os
import re
from datetime import datetime, timedelta

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

INPUT_FILE = None
OUTPUT_FILE = None


def configure_paths(tenant):
    global INPUT_FILE, OUTPUT_FILE

    # The tenant argument is expected to use the same exact naming
    # convention as the collector output, for example: tenant_picard.
    tenant = tenant.strip()

    if not re.fullmatch(r"tenant_[A-Za-z0-9_-]+", tenant):
        raise ValueError(
            "Invalid tenant name. Use for example: tenant_picard"
        )

    INPUT_FILE = os.path.join(
        OUTPUT_DIR,
        f"{tenant}-collector-test.json",
    )

    OUTPUT_FILE = os.path.join(
        OUTPUT_DIR,
        f"{tenant}-security-report.pdf",
    )

    return tenant


def load_report_data():
    with open(INPUT_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def customer_name_from_tenant(tenant):
    if tenant.startswith("tenant_"):
        tenant = tenant[len("tenant_"):]
    return tenant.replace("_", " ").title()


def format_report_date(value):
    # Input example: 2026-08-01T00:00:00Z
    try:
        dt = datetime.strptime(value[:10], "%Y-%m-%d")
        months = {
            1: "January",
            2: "February",
            3: "March",
            4: "April",
            5: "May",
            6: "June",
            7: "July",
            8: "August",
            9: "September",
            10: "October",
            11: "November",
            12: "December",
        }
        return f"{dt.day} {months[dt.month]} {dt.year}"
    except Exception:
        return value


def format_report_end_date(value):
    # The collector uses an exclusive end date. For display, show the final included day.
    try:
        dt = datetime.strptime(value[:10], "%Y-%m-%d") - timedelta(days=1)
        months = {
            1: "January",
            2: "February",
            3: "March",
            4: "April",
            5: "May",
            6: "June",
            7: "July",
            8: "August",
            9: "September",
            10: "October",
            11: "November",
            12: "December",
        }
        return f"{dt.day} {months[dt.month]} {dt.year}"
    except Exception:
        return value


def build_pdf(data):
    doc = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Wazuh Security Report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=12,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=8,
    )

    cover_label_style = ParagraphStyle(
        "CoverLabel",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#707070"),
        spaceAfter=2,
    )

    cover_value_style = ParagraphStyle(
        "CoverValue",
        parent=styles["Normal"],
        fontSize=12,
        leading=15,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#222222"),
        spaceAfter=10,
    )

    cover_tagline_style = ParagraphStyle(
        "CoverTagline",
        parent=styles["Normal"],
        fontSize=12,
        leading=16,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#4F4F4F"),
        spaceAfter=14,
    )

    cover_body_style = ParagraphStyle(
        "CoverBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#4A4A4A"),
    )

    cover_footer_style = ParagraphStyle(
        "CoverFooter",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#777777"),
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=18,
        spaceBefore=8,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=13,
    )

    kpi_label_style = ParagraphStyle(
        "KpiLabel",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#666666"),
        spaceAfter=3,
    )

    kpi_value_style = ParagraphStyle(
        "KpiValue",
        parent=styles["Normal"],
        fontSize=20,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#222222"),
    )

    kpi_sub_style = ParagraphStyle(
        "KpiSub",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#666666"),
    )

    kpi_critical_value_style = ParagraphStyle(
        "KpiCriticalValue",
        parent=kpi_value_style,
        textColor=colors.HexColor("#C62828"),
    )

    kpi_high_value_style = ParagraphStyle(
        "KpiHighValue",
        parent=kpi_value_style,
        textColor=colors.HexColor("#E6A700"),
    )

    activity_label_style = ParagraphStyle(
        "ActivityLabel",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#666666"),
    )

    activity_value_style = ParagraphStyle(
        "ActivityValue",
        parent=styles["Normal"],
        fontSize=18,
        leading=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#222222"),
    )

    story = []

    # ------------------------------------------------------------
    # Cover
    # ------------------------------------------------------------

    tenant = data["tenant"]
    customer_name = customer_name_from_tenant(tenant)
    period_from = data["reporting_period"]["from"]
    period_to = data["reporting_period"]["to"]
    period_from_display = format_report_date(period_from)
    period_to_display = format_report_end_date(period_to)

    story.append(Spacer(1, 24 * mm))
    story.append(
        Paragraph(
            "SECURITY REPORT",
            title_style,
        )
    )
    story.append(Spacer(1, 3 * mm))

    divider = Table([[""]], colWidths=[155 * mm], rowHeights=[1.2 * mm])
    divider.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#D9D9D9")),
                ("BOX", (0, 0), (-1, -1), 0, colors.white),
            ]
        )
    )
    story.append(divider)
    story.append(Spacer(1, 14 * mm))

    cover_meta = Table(
        [
            [
                Paragraph("CUSTOMER", cover_label_style),
                Paragraph("REPORTING PERIOD", cover_label_style),
            ],
            [
                Paragraph(customer_name, cover_value_style),
                Paragraph(
                    f"{period_from_display} - {period_to_display}",
                    cover_value_style,
                ),
            ],
        ],
        colWidths=[78 * mm, 78 * mm],
    )
    cover_meta.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(cover_meta)
    story.append(Spacer(1, 20 * mm))

    story.append(
        Paragraph(
            "Security monitoring &amp; posture assessment",
            cover_tagline_style,
        )
    )

    story.append(
        Paragraph(
            "This report provides an objective overview of the security posture, "
            "configuration compliance, vulnerabilities and detected security activity "
            "for the monitored environment during the selected reporting period.",
            cover_body_style,
        )
    )

    story.append(Spacer(1, 42 * mm))
    story.append(
        Paragraph(
            "Generated by ISGservices",
            cover_footer_style,
        )
    )
    story.append(
        Paragraph(
            "Powered by Wazuh",
            cover_footer_style,
        )
    )

    story.append(PageBreak())

    # ------------------------------------------------------------
    # Security Overview
    # ------------------------------------------------------------

    story.append(
        Paragraph(
            "Security Overview",
            heading_style,
        )
    )

    endpoints = data["endpoints"]
    configuration = data["configuration"]
    vulnerabilities = data["vulnerabilities"]
    activity = data["security_activity"]

    total_endpoints = max(int(configuration["total_endpoints"]), 0)
    assessed_endpoints = int(configuration["assessed_endpoints"])
    sca_coverage = (
        (assessed_endpoints / total_endpoints) * 100
        if total_endpoints
        else 0.0
    )

    def make_kpi_card(label, value, subtitle="", value_style=None):
        return Table(
            [
                [Paragraph(label.upper(), kpi_label_style)],
                [Paragraph(str(value), value_style or kpi_value_style)],
                [Paragraph(subtitle or "&nbsp;", kpi_sub_style)],
            ],
            colWidths=[50 * mm],
            rowHeights=[8 * mm, 13 * mm, 10 * mm],
        )

    top_cards = [
        make_kpi_card(
            "Endpoints",
            endpoints["total"],
            f'{endpoints["active"]} active / {endpoints["disconnected"]} disconnected',
        ),
        make_kpi_card(
            "Configuration compliance",
            f'{configuration["average_compliance"]:.1f}%',
            "Average assessed endpoint score",
        ),
        make_kpi_card(
            "SCA coverage",
            f"{assessed_endpoints} / {total_endpoints}",
            f"{sca_coverage:.0f}% of endpoints assessed",
        ),
    ]

    top_kpis = Table(
        [top_cards],
        colWidths=[53 * mm, 53 * mm, 53 * mm],
        hAlign="LEFT",
    )
    top_kpis.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (2, 0), (2, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(top_kpis)
    story.append(Spacer(1, 8 * mm))

    vuln_cards = Table(
        [[
            make_kpi_card(
                "Critical vulnerabilities",
                f'{vulnerabilities["critical"]:,}',
                "Current vulnerability state",
                kpi_critical_value_style,
            ),
            make_kpi_card(
                "High vulnerabilities",
                f'{vulnerabilities["high"]:,}',
                "Current vulnerability state",
                kpi_high_value_style,
            ),
        ]],
        colWidths=[79.5 * mm, 79.5 * mm],
        hAlign="LEFT",
    )
    vuln_cards.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(vuln_cards)
    story.append(Spacer(1, 9 * mm))

    story.append(
        Paragraph(
            "Security Activity",
            heading_style,
        )
    )

    activity_cards = Table(
        [[
            Table(
                [
                    [Paragraph("DEFENDER THREAT DETECTIONS", activity_label_style)],
                    [Paragraph(str(activity["defender_threat_detections"]), activity_value_style)],
                ],
                colWidths=[50 * mm],
                rowHeights=[9 * mm, 13 * mm],
            ),
            Table(
                [
                    [Paragraph("ENDPOINT ISOLATIONS", activity_label_style)],
                    [Paragraph(str(activity["endpoint_isolations"]), activity_value_style)],
                ],
                colWidths=[50 * mm],
                rowHeights=[9 * mm, 13 * mm],
            ),
            Table(
                [
                    [Paragraph("ACTIVE RESPONSES", activity_label_style)],
                    [Paragraph(str(activity["active_responses"]), activity_value_style)],
                ],
                colWidths=[50 * mm],
                rowHeights=[9 * mm, 13 * mm],
            ),
        ]],
        colWidths=[53 * mm, 53 * mm, 53 * mm],
        hAlign="LEFT",
    )
    activity_cards.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (2, 0), (2, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(activity_cards)
    story.append(Spacer(1, 10 * mm))

    summary_text = (
        f"Wazuh bevat momenteel {endpoints['total']} endpoints voor deze tenant. "
        f"Hiervan {'is' if endpoints['active'] == 1 else 'zijn'} {endpoints['active']} "
        f"endpoint{' actief' if endpoints['active'] == 1 else 's actief'} en "
        f"{'is' if endpoints['disconnected'] == 1 else 'zijn'} {endpoints['disconnected']} "
        f"endpoint{' niet verbonden' if endpoints['disconnected'] == 1 else 's niet verbonden'}. "
        f"De gemiddelde configuratiecompliance bedraagt {configuration['average_compliance']:.1f}% over "
        f"{assessed_endpoints} beoordeelde endpoint{'s' if assessed_endpoints != 1 else ''}, "
        f"wat overeenkomt met een SCA-dekking van {sca_coverage:.0f}%. "
        f"De huidige kwetsbaarheidsstatus bevat {vulnerabilities['critical']:,} kritieke en "
        f"{vulnerabilities['high']:,} hoge kwetsbaarheden. "
        f"Tijdens de rapportageperiode registreerde Wazuh "
        f"{activity['defender_threat_detections']} Microsoft Defender-dreigingsdetecties, "
        f"{activity['endpoint_isolations']} endpoint-isolaties en "
        f"{activity['active_responses']} uitgevoerde Active Responses."
    )

    story.append(Paragraph(summary_text, normal_style))
    story.append(PageBreak())

    # ------------------------------------------------------------
    # Vulnerability Overview
    # ------------------------------------------------------------

    story.append(
        Paragraph(
            "Vulnerability Overview",
            heading_style,
        )
    )

    vuln_endpoints = list(vulnerabilities.get("top_endpoints", []))

    # Security prioritization:
    # 1. Critical descending
    # 2. High descending
    vuln_endpoints.sort(
        key=lambda item: (
            int(item.get("critical", 0)),
            int(item.get("high", 0)),
        ),
        reverse=True,
    )

    affected_endpoints = sum(
        1
        for item in vuln_endpoints
        if int(item.get("critical", 0)) > 0
        or int(item.get("high", 0)) > 0
    )

    vulnerability_kpis = Table(
        [[
            make_kpi_card(
                "Affected endpoints",
                affected_endpoints,
                "Critical and/or High findings",
            ),
            make_kpi_card(
                "Critical vulnerabilities",
                f'{vulnerabilities["critical"]:,}',
                "Current vulnerability state",
                kpi_critical_value_style,
            ),
            make_kpi_card(
                "High vulnerabilities",
                f'{vulnerabilities["high"]:,}',
                "Current vulnerability state",
                kpi_high_value_style,
            ),
        ]],
        colWidths=[53 * mm, 53 * mm, 53 * mm],
        hAlign="LEFT",
    )

    vulnerability_kpis.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (2, 0), (2, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    story.append(vulnerability_kpis)
    story.append(Spacer(1, 9 * mm))

    vuln_table_data = [
        [
            "Endpoint",
            "Critical",
            "High",
            "Critical + High",
        ]
    ]

    for endpoint in vuln_endpoints:
        vuln_table_data.append(
            [
                endpoint["endpoint"],
                f'{int(endpoint["critical"]):,}',
                f'{int(endpoint["high"]):,}',
                f'{int(endpoint["total"]):,}',
            ]
        )

    vuln_table = Table(
        vuln_table_data,
        colWidths=[
            70 * mm,
            30 * mm,
            30 * mm,
            35 * mm,
        ],
        repeatRows=1,
    )

    vuln_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E8E8E8"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#B0B0B0"),
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (-1, -1),
                    "RIGHT",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(vuln_table)
    story.append(Spacer(1, 10 * mm))

    story.append(
        Paragraph(
            "De tabel toont het huidige aantal kritieke en hoge kwetsbaarheden per endpoint. "
            "De endpoints zijn gerangschikt op het aantal kritieke kwetsbaarheden, "
            "gevolgd door het aantal hoge kwetsbaarheden. De classificatie van de ernst "
            "is gebaseerd op de kwetsbaarheidsgegevens die beschikbaar zijn binnen Wazuh.",
            normal_style,
        )
    )

    # ------------------------------------------------------------
    # Security Activity
    # ------------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Security Activity",
            heading_style,
        )
    )

    defender_total = int(activity.get("defender_threat_detections", 0))
    isolation_total = int(activity.get("endpoint_isolations", 0))
    active_response_total = int(activity.get("active_responses", 0))

    security_activity_kpis = Table(
        [[
            make_kpi_card(
                "Threat detections",
                defender_total,
                "Microsoft Defender",
            ),
            make_kpi_card(
                "Endpoint isolations",
                isolation_total,
                "Recorded isolation events",
            ),
            make_kpi_card(
                "Active responses",
                active_response_total,
                "Executed automated actions",
            ),
        ]],
        colWidths=[53 * mm, 53 * mm, 53 * mm],
        hAlign="LEFT",
    )

    security_activity_kpis.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (2, 0), (2, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    story.append(security_activity_kpis)
    story.append(Spacer(1, 8 * mm))

    total_security_activity = (
        defender_total
        + isolation_total
        + active_response_total
    )

    if total_security_activity == 0:
        no_activity_style = ParagraphStyle(
            "NoSecurityActivity",
            parent=normal_style,
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#444444"),
            spaceBefore=8,
            spaceAfter=8,
        )

        story.append(
            Paragraph(
                "<b>No security activity recorded</b>",
                no_activity_style,
            )
        )

        story.append(
            Paragraph(
                "No Microsoft Defender threat detections, endpoint isolation "
                "events or Active Responses were recorded for this tenant "
                "during the selected reporting period.",
                normal_style,
            )
        )

        story.append(Spacer(1, 4 * mm))

        story.append(
            Paragraph(
                "This indicates that no activity matching these monitored "
                "security categories was recorded by Wazuh during this period. "
                "It does not by itself confirm the absence of security threats.",
                normal_style,
            )
        )

    else:
        # --------------------------------------------------------
        # Threat detections
        # --------------------------------------------------------

        defender_details = activity.get("defender_threat_details", [])

        if defender_details:
            story.append(
                Paragraph(
                    "Threat Detections",
                    heading_style,
                )
            )

            threat_table_data = [
                [
                    "Threat",
                    "Severity",
                    "Endpoint",
                    "Detections",
                ]
            ]

            for threat_item in defender_details:
                threat_name = threat_item.get("threat") or "Unknown threat"

                severities = threat_item.get("severities", [])
                severity = (
                    severities[0].get("severity", "Unknown")
                    if severities
                    else "Unknown"
                )

                endpoint_rows = threat_item.get("endpoints", [])

                if endpoint_rows:
                    for endpoint_item in endpoint_rows:
                        threat_table_data.append(
                            [
                                Paragraph(str(threat_name), normal_style),
                                str(severity),
                                str(endpoint_item.get("endpoint", "Unknown")),
                                str(int(endpoint_item.get("count", 0))),
                            ]
                        )
                else:
                    threat_table_data.append(
                        [
                            Paragraph(str(threat_name), normal_style),
                            str(severity),
                            "Unknown",
                            str(int(threat_item.get("count", 0))),
                        ]
                    )

            threat_table = Table(
                threat_table_data,
                colWidths=[
                    76 * mm,
                    28 * mm,
                    38 * mm,
                    23 * mm,
                ],
                repeatRows=1,
            )

            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
                        ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(threat_table)
            story.append(Spacer(1, 7 * mm))

        # --------------------------------------------------------
        # Active Responses
        # --------------------------------------------------------

        active_response_details = activity.get(
            "active_response_details",
            [],
        )

        if active_response_details:
            story.append(
                Paragraph(
                    "Automated Security Actions",
                    heading_style,
                )
            )

            response_table_data = [
                [
                    "Response",
                    "Endpoint",
                    "Actions",
                ]
            ]

            for response_item in active_response_details:
                response_name = (
                    response_item.get("response")
                    or "Unknown active response"
                )

                endpoints_for_response = response_item.get("endpoints", [])

                if endpoints_for_response:
                    for endpoint_item in endpoints_for_response:
                        response_table_data.append(
                            [
                                Paragraph(str(response_name), normal_style),
                                str(endpoint_item.get("endpoint", "Unknown")),
                                str(int(endpoint_item.get("count", 0))),
                            ]
                        )
                else:
                    response_table_data.append(
                        [
                            Paragraph(str(response_name), normal_style),
                            "Unknown",
                            str(int(response_item.get("count", 0))),
                        ]
                    )

            response_table = Table(
                response_table_data,
                colWidths=[
                    82 * mm,
                    55 * mm,
                    28 * mm,
                ],
                repeatRows=1,
            )

            response_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
                        ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(response_table)
            story.append(Spacer(1, 7 * mm))

        # --------------------------------------------------------
        # Endpoint isolations
        # --------------------------------------------------------

        isolation_details = activity.get(
            "endpoint_isolation_details",
            [],
        )

        if isolation_details:
            story.append(
                Paragraph(
                    "Endpoint Isolations",
                    heading_style,
                )
            )

            def extract_context_value(context, key):
                if not context:
                    return None

                match = re.search(
                    rf"(?:^|[,{{]){re.escape(key)}:([^,}}]+)",
                    str(context),
                    flags=re.IGNORECASE,
                )

                if not match:
                    return None

                return match.group(1).strip().strip('"').strip("'")

            isolation_summary = {}

            for event in isolation_details:
                context = event.get("context", "")

                source = (
                    extract_context_value(context, "source")
                    or "unknown"
                )

                threat = extract_context_value(
                    context,
                    "threat_name",
                )

                reason = extract_context_value(
                    context,
                    "reason",
                )

                endpoint = event.get("endpoint") or "Unknown"

                # Prefer the actual threat if present; otherwise use reason.
                trigger = threat or reason or "Unspecified"

                key = (
                    endpoint,
                    source.lower(),
                    trigger,
                )

                if key not in isolation_summary:
                    isolation_summary[key] = {
                        "endpoint": endpoint,
                        "source": source,
                        "trigger": trigger,
                        "count": 0,
                    }

                isolation_summary[key]["count"] += 1

            isolation_rows = sorted(
                isolation_summary.values(),
                key=lambda item: (
                    -int(item["count"]),
                    str(item["endpoint"]),
                    str(item["source"]),
                    str(item["trigger"]),
                ),
            )

            isolation_table_data = [
                [
                    "Endpoint",
                    "Trigger",
                    "Threat / Reason",
                    "Count",
                ]
            ]

            for row in isolation_rows[:12]:
                source = str(row["source"]).lower()

                if source == "wazuh":
                    trigger_label = "Automatic"
                elif source == "manual":
                    trigger_label = "Manual"
                else:
                    trigger_label = str(row["source"]).title()

                isolation_table_data.append(
                    [
                        str(row["endpoint"]),
                        trigger_label,
                        Paragraph(str(row["trigger"]), normal_style),
                        str(int(row["count"])),
                    ]
                )

            isolation_table = Table(
                isolation_table_data,
                colWidths=[
                    35 * mm,
                    30 * mm,
                    77 * mm,
                    23 * mm,
                ],
                repeatRows=1,
            )

            isolation_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
                        ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(isolation_table)
            story.append(Spacer(1, 7 * mm))

        story.append(
            Paragraph(
                "De beveiligingsactiviteiten op deze pagina tonen de detecties en "
                "beveiligingsmaatregelen die tijdens de rapportageperiode door Wazuh zijn geregistreerd. "
                "Geregistreerde beveiligingsactiviteit betekent op zichzelf niet dat er sprake is "
                "van een succesvolle compromittering.",
                normal_style,
            )
        )

    # ------------------------------------------------------------
    # Configuration Compliance
    # ------------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Configuration Compliance",
            heading_style,
        )
    )

    endpoint_compliance = list(
        configuration.get("endpoint_compliance", [])
    )
    top_failed_checks = list(
        configuration.get("top_failed_checks", [])
    )

    assessed_endpoints = int(
        configuration.get("assessed_endpoints", 0)
    )
    total_endpoints = int(
        configuration.get("total_endpoints", 0)
    )

    if total_endpoints > 0:
        sca_coverage = (
            assessed_endpoints / total_endpoints
        ) * 100
    else:
        sca_coverage = 0.0

    configuration_kpis = Table(
        [[
            make_kpi_card(
                "Average compliance",
                f'{float(configuration.get("average_compliance", 0)):.1f}%',
                "Across assessed endpoints",
            ),
            make_kpi_card(
                "Assessed endpoints",
                f"{assessed_endpoints} / {total_endpoints}",
                "Endpoints with SCA results",
            ),
            make_kpi_card(
                "SCA coverage",
                f"{sca_coverage:.0f}%",
                "Share of endpoints assessed",
            ),
        ]],
        colWidths=[53 * mm, 53 * mm, 53 * mm],
        hAlign="LEFT",
    )

    configuration_kpis.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (1, 0), (1, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("BOX", (2, 0), (2, 0), 0.8, colors.HexColor("#D0D0D0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    story.append(configuration_kpis)
    story.append(Spacer(1, 8 * mm))

    if not endpoint_compliance:
        story.append(
            Paragraph(
                "<b>No configuration assessment data available</b>",
                normal_style,
            )
        )
        story.append(Spacer(1, 3 * mm))
        story.append(
            Paragraph(
                "No endpoint-level SCA results were available for this tenant "
                "when the report was generated.",
                normal_style,
            )
        )
    else:
        story.append(
            Paragraph(
                "Compliance per Endpoint",
                heading_style,
            )
        )

        compliance_table_data = [
            [
                "Endpoint",
                "Compliance",
                "Passed",
                "Failed",
                "Checks",
            ]
        ]

        # Lowest compliance first so the endpoints requiring attention
        # appear at the top of the table.
        endpoint_compliance.sort(
            key=lambda item: float(
                item.get("compliance", 0)
            )
        )

        for item in endpoint_compliance:
            compliance_table_data.append(
                [
                    str(item.get("endpoint", "Unknown")),
                    f'{float(item.get("compliance", 0)):.2f}%',
                    f'{int(item.get("passed", 0)):,}',
                    f'{int(item.get("failed", 0)):,}',
                    f'{int(item.get("total_checks", 0)):,}',
                ]
            )

        compliance_table = Table(
            compliance_table_data,
            colWidths=[
                57 * mm,
                30 * mm,
                25 * mm,
                25 * mm,
                28 * mm,
            ],
            repeatRows=1,
        )

        compliance_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
                    ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(compliance_table)
        story.append(Spacer(1, 7 * mm))

        story.append(
            Paragraph(
                "Top Failed Configuration Checks",
                heading_style,
            )
        )

        failed_check_style = ParagraphStyle(
            "FailedCheckText",
            parent=normal_style,
            fontSize=8,
            leading=10,
        )

        endpoint_list_style = ParagraphStyle(
            "FailedCheckEndpoints",
            parent=normal_style,
            fontSize=8,
            leading=10,
        )

        if top_failed_checks:
            failed_table_data = [
                [
                    "Check",
                    "Affected",
                    "Endpoints",
                ]
            ]

            for item in top_failed_checks[:10]:
                endpoint_names = ", ".join(
                    str(endpoint)
                    for endpoint in item.get("endpoints", [])
                )

                failed_table_data.append(
                    [
                        Paragraph(
                            str(
                                item.get(
                                    "title",
                                    f'SCA check {item.get("check_id", "")}',
                                )
                            ),
                            failed_check_style,
                        ),
                        str(
                            int(
                                item.get(
                                    "affected_endpoints",
                                    0,
                                )
                            )
                        ),
                        Paragraph(
                            endpoint_names or "Unknown",
                            endpoint_list_style,
                        ),
                    ]
                )

            failed_table = Table(
                failed_table_data,
                colWidths=[
                    105 * mm,
                    22 * mm,
                    38 * mm,
                ],
                repeatRows=1,
            )

            failed_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
                        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )

            story.append(failed_table)
        else:
            story.append(
                Paragraph(
                    "No failed configuration checks were recorded for the "
                    "assessed endpoints.",
                    normal_style,
                )
            )

        story.append(Spacer(1, 6 * mm))

        policy_names = sorted({
            str(item.get("policy_name"))
            for item in endpoint_compliance
            if item.get("policy_name")
        })

        if policy_names:
            story.append(
                Paragraph(
                    "<b>Assessment benchmark:</b> "
                    + ", ".join(policy_names),
                    normal_style,
                )
            )
            story.append(Spacer(1, 3 * mm))

        story.append(
            Paragraph(
                "De configuratiecompliance is gebaseerd op de meest recente SCA-resultaten "
                "die beschikbaar zijn voor de beoordeelde endpoints. De tabel met mislukte controles "
                "toont de configuratiecontroles die op het grootste aantal beoordeelde endpoints niet voldoen "
                "en biedt daarmee een praktisch uitgangspunt voor het prioriteren van verbetermaatregelen.",
                normal_style,
            )
        )

    doc.build(story)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Wazuh tenant security report."
    )
    parser.add_argument(
        "tenant",
        help="Tenant name, for example: tenant_picard",
    )
    args = parser.parse_args()

    requested_tenant = configure_paths(args.tenant)

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Collector output not found: {INPUT_FILE}"
        )

    data = load_report_data()

    # Prevent accidentally generating a report from another tenant's JSON.
    data_tenant = str(data.get("tenant", "")).strip()
    if data_tenant != requested_tenant:
        raise ValueError(
            f"Tenant mismatch: requested '{requested_tenant}', "
            f"but collector JSON contains '{data_tenant}'."
        )

    build_pdf(data)

    print(f"Tenant: {requested_tenant}")
    print(f"Collector input: {INPUT_FILE}")
    print(f"PDF generated: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
