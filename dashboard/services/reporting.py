from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from html import escape
from typing import Any, Iterable, Mapping

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _dicts(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def incident_payload(
    incident,
    evidence,
    timeline,
    notes,
    assignment,
    activities,
    intelligence,
    *,
    iocs=(),
    similar_incidents=(),
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": dict(incident),
        "assignment": dict(assignment) if assignment else None,
        "evidence": _dicts(evidence),
        "timeline": _dicts(timeline),
        "iocs": _dicts(iocs),
        "similar_incidents": [dict(row) for row in similar_incidents],
        "notes": _dicts(notes),
        "activity": _dicts(activities),
        "threat_intelligence": intelligence,
    }


def json_report(payload: dict[str, Any]) -> io.BytesIO:
    stream = io.BytesIO(json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
    stream.seek(0)
    return stream


def _write_section(writer: csv.writer, title: str, rows: list[dict[str, Any]]) -> None:
    writer.writerow([])
    writer.writerow([title])
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow(row.values())


def incident_csv_report(payload: dict[str, Any]) -> io.BytesIO:
    text = io.StringIO()
    writer = csv.writer(text)
    writer.writerow(["ShadowTrace v3 Incident Report"])
    writer.writerow(["Generated At", payload["generated_at"]])
    writer.writerow([])
    writer.writerow(["INCIDENT"])
    for key, value in payload["incident"].items():
        writer.writerow([key, value])
    _write_section(writer, "EVIDENCE", payload["evidence"])
    _write_section(writer, "TIMELINE", payload["timeline"])
    _write_section(writer, "IOCS", payload["iocs"])
    _write_section(writer, "SIMILAR INCIDENTS", payload["similar_incidents"])
    _write_section(writer, "NOTES", payload["notes"])
    _write_section(writer, "ACTIVITY", payload["activity"])
    stream = io.BytesIO(text.getvalue().encode("utf-8-sig"))
    stream.seek(0)
    return stream


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 12 * mm, "ShadowTrace v3 Security Operations Report")
    canvas.drawRightString(192 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _table_style(header_color: str = "#0f4c81") -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]
    )


def incident_pdf_report(payload: dict[str, Any]) -> io.BytesIO:
    output = io.BytesIO()
    incident = payload["incident"]
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"ShadowTrace Incident {incident.get('id')}",
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "TitleBlue",
        parent=styles["Title"],
        textColor=colors.HexColor("#0f4c81"),
        alignment=TA_CENTER,
    )
    h2 = ParagraphStyle(
        "HeadingBlue",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0f4c81"),
        spaceBefore=12,
    )
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, leading=10)
    story = [
        Paragraph("ShadowTrace v3 Incident Report", title),
        Spacer(1, 6),
        Paragraph(f"Generated: {escape(payload['generated_at'])}", styles["Normal"]),
        Spacer(1, 14),
        Paragraph(escape(f"Incident #{incident.get('id')}: {incident.get('title', '')}"), h2),
    ]
    summary_data = [
        ["Severity", incident.get("severity"), "Status", incident.get("status")],
        ["Threat score", f"{incident.get('threat_score', 0)}/100", "Confidence", f"{incident.get('confidence', 0)}%"],
        ["Source IP", incident.get("source_ip") or "—", "Destination IP", incident.get("destination_ip") or "—"],
        ["First Seen", incident.get("first_seen") or "—", "Last Seen", incident.get("last_seen") or "—"],
        ["Attack Stage", incident.get("attack_stage") or "—", "Kill Chain", incident.get("kill_chain_phase") or "—"],
    ]
    table = Table(summary_data, colWidths=[28 * mm, 52 * mm, 28 * mm, 52 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7fb")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [
        table,
        Spacer(1, 10),
        Paragraph("Summary", h2),
        Paragraph(escape(str(incident.get("summary") or "No summary.")), styles["BodyText"]),
        Paragraph("MITRE ATT&CK / Cyber Kill Chain", h2),
        Paragraph(escape(str(incident.get("mitre_techniques") or "See timeline mappings.")), styles["BodyText"]),
    ]

    story.append(Paragraph("Evidence", h2))
    evidence_rows = [["Time", "Tool", "Type", "Risk", "Description"]]
    for item in payload["evidence"]:
        evidence_rows.append(
            [
                Paragraph(escape(str(item.get("timestamp") or "—")), small),
                Paragraph(escape(str(item.get("source_tool") or "—")), small),
                Paragraph(escape(str(item.get("evidence_type") or "—")), small),
                str(item.get("risk_points") or 0),
                Paragraph(escape(str(item.get("description") or "—")), small),
            ]
        )
    if len(evidence_rows) == 1:
        evidence_rows.append(["—", "—", "—", "0", "No evidence records"])
    evidence_table = Table(
        evidence_rows,
        repeatRows=1,
        colWidths=[30 * mm, 20 * mm, 27 * mm, 12 * mm, 72 * mm],
    )
    evidence_table.setStyle(_table_style())
    story.append(evidence_table)

    story.append(Paragraph("Indicators of Compromise", h2))
    ioc_rows = [["Type", "Value", "Confidence", "Threat", "First seen"]]
    for item in payload["iocs"]:
        ioc_rows.append(
            [
                item.get("ioc_type") or "—",
                Paragraph(escape(str(item.get("normalized_value") or "—")), small),
                f"{item.get('confidence', 0)}%",
                f"{item.get('threat_score', 0)}/100",
                Paragraph(escape(str(item.get("first_seen") or "—")), small),
            ]
        )
    if len(ioc_rows) == 1:
        ioc_rows.append(["—", "No IOCs extracted", "—", "—", "—"])
    ioc_table = Table(ioc_rows, repeatRows=1, colWidths=[22 * mm, 70 * mm, 23 * mm, 20 * mm, 30 * mm])
    ioc_table.setStyle(_table_style())
    story.append(ioc_table)

    story.append(PageBreak())
    story.append(Paragraph("Attack Timeline", h2))
    timeline_rows = [["Time", "Stage", "Kill Chain", "MITRE Technique", "Description"]]
    for item in payload["timeline"]:
        timeline_rows.append(
            [
                Paragraph(escape(str(item.get("event_time") or "—")), small),
                Paragraph(escape(str(item.get("attack_stage") or "—")), small),
                Paragraph(escape(str(item.get("kill_chain_phase") or "—")), small),
                Paragraph(escape(str(item.get("mitre_technique") or "—")), small),
                Paragraph(escape(str(item.get("description") or "—")), small),
            ]
        )
    if len(timeline_rows) == 1:
        timeline_rows.append(["—", "—", "—", "—", "No timeline records"])
    timeline_table = Table(
        timeline_rows,
        repeatRows=1,
        colWidths=[27 * mm, 28 * mm, 30 * mm, 43 * mm, 38 * mm],
    )
    timeline_table.setStyle(_table_style())
    story.append(timeline_table)

    intel = payload["threat_intelligence"]
    story.append(Paragraph("Threat Intelligence", h2))
    story.append(
        Paragraph(
            f"Indicator: {escape(str(intel.get('normalized_value') or intel.get('ip') or '—'))} | "
            f"Verdict: {escape(str(intel.get('risk', {}).get('level', 'UNKNOWN')))} "
            f"({intel.get('risk', {}).get('score', 0)}/100)",
            styles["BodyText"],
        )
    )
    for reason in intel.get("risk", {}).get("reasons", []):
        story.append(Paragraph(f"• {escape(str(reason))}", styles["BodyText"]))

    story.append(Paragraph("Similar Incidents", h2))
    similar_rows = [["ID", "Title", "Similarity", "Shared indicators / reasons"]]
    for item in payload["similar_incidents"]:
        reasons = ", ".join(item.get("reasons") or item.get("shared_iocs") or [])
        similar_rows.append(
            [
                item.get("id"),
                Paragraph(escape(str(item.get("title") or "—")), small),
                f"{item.get('similarity_score', 0)}%",
                Paragraph(escape(reasons or "—"), small),
            ]
        )
    if len(similar_rows) == 1:
        similar_rows.append(["—", "No similar incidents", "—", "—"])
    similar_table = Table(similar_rows, repeatRows=1, colWidths=[14 * mm, 65 * mm, 24 * mm, 63 * mm])
    similar_table.setStyle(_table_style())
    story.append(similar_table)

    story.append(Paragraph("Investigation Notes", h2))
    if payload["notes"]:
        for note in payload["notes"]:
            story.append(
                Paragraph(
                    f"<b>{escape(str(note.get('username', 'Unknown')))}</b> — "
                    f"{escape(str(note.get('created_at', '')))}<br/>{escape(str(note.get('note', '')))}",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No investigation notes.", styles["BodyText"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    output.seek(0)
    return output


def incidents_csv_report(incidents: Iterable[Mapping[str, Any]]) -> io.BytesIO:
    rows = _dicts(incidents)
    text = io.StringIO()
    fields = [
        "id",
        "title",
        "severity",
        "threat_score",
        "confidence",
        "status",
        "source_ip",
        "destination_ip",
        "first_seen",
        "last_seen",
        "assigned_analyst",
        "evidence_count",
        "ioc_count",
    ]
    writer = csv.DictWriter(text, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    stream = io.BytesIO(text.getvalue().encode("utf-8-sig"))
    stream.seek(0)
    return stream


def incidents_pdf_report(incidents: Iterable[Mapping[str, Any]]) -> io.BytesIO:
    rows = _dicts(incidents)
    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    small = ParagraphStyle("TableSmall", parent=styles["BodyText"], fontSize=7.5, leading=9)
    data = [["ID", "Title", "Severity", "Threat", "Status", "Confidence", "Source IP", "IOCs", "Analyst"]]
    for row in rows:
        data.append(
            [
                row.get("id"),
                Paragraph(escape(str(row.get("title") or "")), small),
                row.get("severity"),
                f"{row.get('threat_score', 0)}/100",
                row.get("status"),
                f"{row.get('confidence', 0)}%",
                row.get("source_ip") or "—",
                row.get("ioc_count", 0),
                row.get("assigned_analyst") or "Unassigned",
            ]
        )
    if len(data) == 1:
        data.append(["—", "No incidents", "—", "—", "—", "—", "—", "—", "—"])
    table = Table(
        data,
        repeatRows=1,
        colWidths=[11 * mm, 68 * mm, 20 * mm, 20 * mm, 23 * mm, 22 * mm, 31 * mm, 14 * mm, 34 * mm],
    )
    table.setStyle(_table_style())
    story = [Paragraph("ShadowTrace v3 Incident Summary", styles["Title"]), Spacer(1, 8), table]
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    output.seek(0)
    return output
