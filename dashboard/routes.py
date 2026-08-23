from __future__ import annotations

import json
import math
from functools import wraps
from typing import Any

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from dashboard.db import SCHEMA_VERSION, get_db, utc_now
from dashboard.services.audit import record_audit
from dashboard.services.ioc import (
    find_similar_incidents,
    incident_iocs,
    ioc_statistics,
    local_ioc_matches,
    sync_incident_iocs,
)
from dashboard.services.reporting import (
    incident_csv_report,
    incident_payload,
    incident_pdf_report,
    incidents_csv_report,
    incidents_pdf_report,
    json_report,
)
from dashboard.services.threat_intel import country_statistics, lookup_indicator, lookup_ip

main = Blueprint("main", __name__)

ALLOWED_STATUSES = {"Open", "Investigating", "Contained", "Resolved", "Closed"}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to access ShadowTrace.", "warning")
            return redirect(url_for("main.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "Admin":
            abort(403, description="Administrator access is required.")
        return view(*args, **kwargs)

    return wrapped


@main.app_context_processor
def inject_user():
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        }
        if session.get("user_id")
        else None,
        "shadowtrace_version": SCHEMA_VERSION,
    }


@main.app_template_filter("friendly_time")
def friendly_time(value):
    if not value:
        return "—"
    return str(value).replace("T", " ").replace("+00:00", " UTC")


def _dashboard_statistics() -> dict[str, Any]:
    db = get_db()
    total_incidents = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    total_evidence = db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    active_threats = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE COALESCE(status, 'Open') NOT IN ('Resolved', 'Closed')"
    ).fetchone()[0]
    monitoring_tools = db.execute(
        "SELECT COUNT(DISTINCT source_tool) FROM evidence WHERE source_tool IS NOT NULL"
    ).fetchone()[0]
    severity = {name: 0 for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]}
    for row in db.execute(
        "SELECT UPPER(COALESCE(severity, 'UNKNOWN')) name, COUNT(*) total FROM incidents GROUP BY name"
    ):
        severity[row["name"]] = row["total"]
    status = {
        row["name"]: row["total"]
        for row in db.execute(
            "SELECT COALESCE(status, 'Open') name, COUNT(*) total FROM incidents GROUP BY name"
        )
    }
    tools = {
        row["name"]: row["total"]
        for row in db.execute(
            "SELECT source_tool name, COUNT(*) total FROM evidence GROUP BY source_tool ORDER BY total DESC"
        )
    }
    trend_rows = db.execute(
        """
        SELECT date(COALESCE(first_seen, created_at)) day, COUNT(*) total
        FROM incidents WHERE COALESCE(first_seen, created_at) IS NOT NULL
        GROUP BY day ORDER BY day DESC LIMIT 14
        """
    ).fetchall()
    trend = list(reversed([{"day": row["day"], "total": row["total"]} for row in trend_rows]))
    avg_confidence = db.execute(
        "SELECT ROUND(COALESCE(AVG(confidence), 0), 1) FROM incidents"
    ).fetchone()[0]
    avg_threat = db.execute(
        "SELECT ROUND(COALESCE(AVG(threat_score), 0), 1) FROM incidents"
    ).fetchone()[0]
    countries = country_statistics()
    return {
        "total_incidents": total_incidents,
        "total_evidence": total_evidence,
        "active_threats": active_threats,
        "monitoring_tools": monitoring_tools,
        "average_confidence": avg_confidence,
        "average_threat_score": avg_threat,
        "severity_distribution": severity,
        "status_distribution": status,
        "tool_distribution": tools,
        "incident_trend": trend,
        "country_distribution": {row["country"]: row["incidents"] for row in countries[:10]},
        "countries": countries,
        "ioc_statistics": ioc_statistics(),
    }


def _filter_spec(args) -> tuple[str, list[Any], dict[str, Any]]:
    q = (args.get("q") or "").strip()
    severity = (args.get("severity") or "").upper().strip()
    status = (args.get("status") or "").strip()
    tool = (args.get("tool") or "").strip()
    from_date = (args.get("from_date") or "").strip()
    to_date = (args.get("to_date") or "").strip()
    min_score = args.get("min_score", type=int)
    conditions = ["1=1"]
    params: list[Any] = []
    if q:
        wildcard = f"%{q}%"
        conditions.append(
            "(i.title LIKE ? OR i.summary LIKE ? OR i.source_ip LIKE ? OR i.destination_ip LIKE ? "
            "OR EXISTS (SELECT 1 FROM iocs oi WHERE oi.incident_id = i.id AND oi.normalized_value LIKE ?))"
        )
        params.extend([wildcard] * 5)
    if severity in ALLOWED_SEVERITIES:
        conditions.append("UPPER(COALESCE(i.severity, 'UNKNOWN')) = ?")
        params.append(severity)
    else:
        severity = ""
    if status in ALLOWED_STATUSES:
        conditions.append("COALESCE(i.status, 'Open') = ?")
        params.append(status)
    else:
        status = ""
    if tool:
        conditions.append(
            "EXISTS (SELECT 1 FROM evidence ef WHERE ef.incident_id = i.id AND ef.source_tool = ?)"
        )
        params.append(tool)
    if from_date:
        conditions.append("date(COALESCE(i.first_seen, i.created_at)) >= date(?)")
        params.append(from_date)
    if to_date:
        conditions.append("date(COALESCE(i.first_seen, i.created_at)) <= date(?)")
        params.append(to_date)
    if min_score is not None:
        min_score = max(0, min(min_score, 100))
        conditions.append("COALESCE(i.threat_score, 0) >= ?")
        params.append(min_score)
    return " AND ".join(conditions), params, {
        "q": q,
        "severity": severity,
        "status": status,
        "tool": tool,
        "from_date": from_date,
        "to_date": to_date,
        "min_score": "" if min_score is None else min_score,
    }


def _incident_query(where: str, order: str = "i.threat_score DESC, i.id DESC") -> str:
    return f"""
        SELECT i.*, u.username AS assigned_analyst,
               COUNT(DISTINCT e.id) AS evidence_count,
               COUNT(DISTINCT oi.id) AS ioc_count
        FROM incidents i
        LEFT JOIN incident_assignments ia ON ia.incident_id = i.id
        LEFT JOIN users u ON u.id = ia.user_id
        LEFT JOIN evidence e ON e.incident_id = i.id
        LEFT JOIN iocs oi ON oi.incident_id = i.id
        WHERE {where}
        GROUP BY i.id
        ORDER BY {order}
    """


def _all_filtered_incidents(args):
    where, params, _filters = _filter_spec(args)
    return get_db().execute(_incident_query(where), params).fetchall()


def _incident_bundle(incident_id: int):
    db = get_db()
    incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        abort(404, description="The requested incident was not found.")
    evidence = db.execute(
        "SELECT * FROM evidence WHERE incident_id = ? ORDER BY timestamp, id", (incident_id,)
    ).fetchall()
    timeline = db.execute(
        "SELECT * FROM attack_timeline WHERE incident_id = ? ORDER BY event_time, id", (incident_id,)
    ).fetchall()
    notes = db.execute(
        """SELECT n.id, n.note, n.created_at, n.user_id, u.username, u.role
           FROM incident_notes n JOIN users u ON u.id = n.user_id
           WHERE n.incident_id = ? ORDER BY n.id DESC""",
        (incident_id,),
    ).fetchall()
    assignment = db.execute(
        """SELECT ia.*, u.username, u.role FROM incident_assignments ia
           JOIN users u ON u.id = ia.user_id WHERE ia.incident_id = ?""",
        (incident_id,),
    ).fetchone()
    activities = db.execute(
        "SELECT * FROM activity_log WHERE incident_id = ? ORDER BY id DESC LIMIT 100", (incident_id,)
    ).fetchall()
    return incident, evidence, timeline, notes, assignment, activities


def _calculate_incident_score(incident, evidence, intelligence: dict[str, Any]) -> int:
    evidence_score = min(sum(int(row["risk_points"] or 0) for row in evidence), 100)
    provider_score = int((intelligence.get("risk") or {}).get("score") or 0)
    blended = round(evidence_score * 0.75 + provider_score * 0.25) if provider_score else evidence_score
    return min(100, max(int(incident["threat_score"] or 0), evidence_score, blended))


@main.route("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "service": "ShadowTrace", "version": SCHEMA_VERSION})
    except Exception:
        return jsonify({"status": "error", "service": "ShadowTrace", "version": SCHEMA_VERSION}), 503


@main.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("main.index"))
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"])
            record_audit("login_success", "user", user["id"], {"username": username})
            flash(f"Welcome back, {user['username']}.", "success")
            next_url = request.args.get("next")
            is_local = bool(next_url and next_url.startswith("/") and not next_url.startswith("//"))
            return redirect(next_url if is_local else url_for("main.index"))
        error = "Invalid username or password."
        record_audit(
            "login_failed", "user", None, {"username": username}, username=username or "anonymous"
        )
    return render_template("login.html", error=error)


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    record_audit("logout", "user", session.get("user_id"))
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.login"))


@main.route("/")
@login_required
def index():
    db = get_db()
    where, params, filters = _filter_spec(request.args)
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", current_app.config["DEFAULT_PAGE_SIZE"], type=int)
    per_page = min(max(per_page, 5), current_app.config["MAX_PAGE_SIZE"])
    total = db.execute(f"SELECT COUNT(*) FROM incidents i WHERE {where}", params).fetchone()[0]
    pages = max(math.ceil(total / per_page), 1)
    page = min(page, pages)
    incidents = db.execute(
        _incident_query(where) + " LIMIT ? OFFSET ?", [*params, per_page, (page - 1) * per_page]
    ).fetchall()
    tools = [
        row[0]
        for row in db.execute(
            "SELECT DISTINCT source_tool FROM evidence WHERE source_tool IS NOT NULL ORDER BY source_tool"
        )
    ]
    return render_template(
        "index.html",
        incidents=incidents,
        statistics=_dashboard_statistics(),
        filters=filters,
        tools=tools,
        page=page,
        pages=pages,
        per_page=per_page,
        total_filtered=total,
    )


@main.route("/api/dashboard")
@login_required
def dashboard_api():
    return jsonify(_dashboard_statistics())


@main.route("/api/incidents")
@login_required
def incidents_api():
    where, params, _filters = _filter_spec(request.args)
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 25, type=int), 1), 100)
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM incidents i WHERE {where}", params).fetchone()[0]
    rows = db.execute(
        _incident_query(where) + " LIMIT ? OFFSET ?", [*params, per_page, (page - 1) * per_page]
    ).fetchall()
    return jsonify(
        {"items": [dict(row) for row in rows], "page": page, "per_page": per_page, "total": total}
    )


@main.route("/api/map")
@login_required
def map_api():
    rows = get_db().execute(
        """SELECT i.id, i.title, i.severity, i.threat_score, i.source_ip, c.payload_json
           FROM incidents i JOIN threat_intel_cache c ON c.ip_address = i.source_ip
           ORDER BY i.threat_score DESC, i.id DESC LIMIT 250"""
    ).fetchall()
    points = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            geo = payload.get("geo", {})
            if geo.get("latitude") is not None and geo.get("longitude") is not None:
                points.append(
                    {
                        "incident_id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "threat_score": row["threat_score"],
                        "ip": row["source_ip"],
                        "latitude": geo["latitude"],
                        "longitude": geo["longitude"],
                        "country": geo.get("country"),
                        "country_code": geo.get("country_code"),
                        "city": geo.get("city"),
                        "risk": payload.get("risk", {}),
                    }
                )
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return jsonify(points)


@main.route("/api/countries")
@login_required
def countries_api():
    return jsonify(country_statistics())


@main.route("/ioc")
@login_required
def ioc_lookup():
    value = (request.args.get("value") or "").strip()
    result = None
    error = None
    if value:
        try:
            local = local_ioc_matches(value)
            intelligence = lookup_indicator(value, local["ioc_type"])
            result = {"local": local, "intelligence": intelligence}
            db = get_db()
            db.execute(
                """
                INSERT INTO ioc_lookup_history (
                    user_id, username, ioc_type, normalized_value, local_match_count,
                    provider_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.get("user_id"),
                    session.get("username") or "anonymous",
                    local["ioc_type"],
                    local["normalized_value"],
                    local["count"],
                    int(intelligence.get("risk", {}).get("score") or 0),
                    utc_now(),
                ),
            )
            db.commit()
            record_audit(
                "ioc_lookup",
                "ioc",
                local["normalized_value"],
                {
                    "ioc_type": local["ioc_type"],
                    "local_matches": local["count"],
                    "provider_score": intelligence.get("risk", {}).get("score", 0),
                },
            )
        except ValueError as exc:
            error = str(exc)
    recent = get_db().execute(
        "SELECT * FROM ioc_lookup_history ORDER BY id DESC LIMIT 12"
    ).fetchall()
    return render_template("ioc_lookup.html", value=value, result=result, error=error, recent=recent)


@main.route("/api/ioc/lookup")
@login_required
def ioc_lookup_api():
    value = (request.args.get("value") or "").strip()
    if not value:
        return jsonify({"error": "The value query parameter is required.", "error_code": "invalid_indicator"}), 400
    try:
        local = local_ioc_matches(value)
    except ValueError as exc:
        return jsonify({"error": "The supplied indicator is invalid or unsupported.", "error_code": "invalid_indicator"}), 400
    intelligence = lookup_indicator(value, local["ioc_type"])
    return jsonify(
        {
            "ioc_type": local["ioc_type"],
            "normalized_value": local["normalized_value"],
            "local_match_count": local["count"],
            "incidents": [dict(row) for row in local["incidents"]],
            "intelligence": intelligence,
        }
    )


@main.route("/api/incidents/<int:incident_id>/similar")
@login_required
def similar_incidents_api(incident_id):
    if not get_db().execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone():
        abort(404)
    sync_incident_iocs(incident_id)
    return jsonify(find_similar_incidents(incident_id, request.args.get("limit", 8, type=int)))


@main.route("/incident/<int:incident_id>")
@login_required
def incident_details(incident_id):
    sync_incident_iocs(incident_id)
    incident, evidence, timeline, notes, assignment, activities = _incident_bundle(incident_id)
    analysts = get_db().execute(
        "SELECT id, username, role FROM users WHERE is_active = 1 ORDER BY username"
    ).fetchall()
    intelligence = lookup_ip(incident["source_ip"])
    threat_score = _calculate_incident_score(incident, evidence, intelligence)
    if threat_score != int(incident["threat_score"] or 0):
        get_db().execute(
            "UPDATE incidents SET threat_score = ?, updated_at = ? WHERE id = ?",
            (threat_score, utc_now(), incident_id),
        )
        get_db().commit()
        incident = get_db().execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    recommendations = _recommendations(incident["severity"], intelligence.get("risk", {}).get("level"))
    return render_template(
        "incident.html",
        incident=incident,
        evidence=evidence,
        timeline=timeline,
        notes=notes,
        assignment=assignment,
        activities=activities,
        analysts=analysts,
        intelligence=intelligence,
        threat_score=threat_score,
        recommendations=recommendations,
        iocs=incident_iocs(incident_id),
        similar_incidents=find_similar_incidents(incident_id),
    )


def _recommendations(severity, intel_level):
    items = [
        "Preserve the related network, host, and file evidence before making changes.",
        "Validate the affected asset, user context, and the exact time window.",
        "Review correlated IOCs and similar incidents before closing the case.",
        "Document every decision and containment action in the incident activity log.",
    ]
    if str(severity).upper() in {"HIGH", "CRITICAL"}:
        items.insert(
            0,
            "Contain the affected endpoint or account using your approved incident-response procedure.",
        )
    if intel_level in {"HIGH", "CRITICAL"}:
        items.append("Review the source indicator in perimeter controls and block it only after validation.")
    return items


@main.route("/incident/<int:incident_id>/status", methods=["POST"])
@login_required
def update_status(incident_id):
    status = (request.form.get("status") or "").strip()
    if status not in ALLOWED_STATUSES:
        flash("Invalid incident status.", "warning")
        return redirect(url_for("main.incident_details", incident_id=incident_id))
    db = get_db()
    old = db.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not old:
        abort(404)
    db.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
        (status, utc_now(), incident_id),
    )
    db.commit()
    record_audit(
        "incident_status_changed",
        "incident",
        incident_id,
        {"from": old["status"], "to": status},
        incident_id=incident_id,
    )
    flash(f"Incident status updated to {status}.", "success")
    return redirect(url_for("main.incident_details", incident_id=incident_id))


@main.route("/incident/<int:incident_id>/assign", methods=["POST"])
@login_required
def assign_incident(incident_id):
    analyst_id = request.form.get("user_id", type=int)
    db = get_db()
    analyst = (
        db.execute(
            "SELECT id, username FROM users WHERE id = ? AND is_active = 1", (analyst_id,)
        ).fetchone()
        if analyst_id
        else None
    )
    if not analyst:
        flash("Please select a valid analyst.", "warning")
        return redirect(url_for("main.incident_details", incident_id=incident_id))
    if not db.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone():
        abort(404)
    db.execute(
        """INSERT INTO incident_assignments (incident_id, user_id, assigned_at) VALUES (?, ?, ?)
           ON CONFLICT(incident_id) DO UPDATE SET
               user_id = excluded.user_id, assigned_at = excluded.assigned_at""",
        (incident_id, analyst_id, utc_now()),
    )
    db.commit()
    record_audit(
        "incident_assigned",
        "incident",
        incident_id,
        {"analyst": analyst["username"], "analyst_id": analyst_id},
        incident_id=incident_id,
    )
    flash(f"Incident assigned to {analyst['username']}.", "success")
    return redirect(url_for("main.incident_details", incident_id=incident_id))


@main.route("/incident/<int:incident_id>/notes", methods=["POST"])
@login_required
def add_note(incident_id):
    note = (request.form.get("note") or "").strip()
    if not note or len(note) > 2000:
        flash("A note between 1 and 2000 characters is required.", "warning")
        return redirect(url_for("main.incident_details", incident_id=incident_id))
    db = get_db()
    if not db.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone():
        abort(404)
    cursor = db.execute(
        "INSERT INTO incident_notes (incident_id, user_id, note, created_at) VALUES (?, ?, ?, ?)",
        (incident_id, session["user_id"], note, utc_now()),
    )
    db.commit()
    record_audit(
        "note_added",
        "incident_note",
        cursor.lastrowid,
        {"length": len(note)},
        incident_id=incident_id,
    )
    flash("Investigation note added.", "success")
    return redirect(url_for("main.incident_details", incident_id=incident_id) + "#notes")


@main.route("/incident/<int:incident_id>/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(incident_id, note_id):
    db = get_db()
    note = db.execute(
        "SELECT id, user_id FROM incident_notes WHERE id = ? AND incident_id = ?",
        (note_id, incident_id),
    ).fetchone()
    if not note:
        abort(404)
    if note["user_id"] != session["user_id"] and session.get("role") != "Admin":
        abort(403)
    db.execute("DELETE FROM incident_notes WHERE id = ?", (note_id,))
    db.commit()
    record_audit("note_deleted", "incident_note", note_id, None, incident_id=incident_id)
    flash("Investigation note deleted.", "success")
    return redirect(url_for("main.incident_details", incident_id=incident_id) + "#notes")


@main.route("/incident/<int:incident_id>/intel/refresh", methods=["POST"])
@login_required
def refresh_intel(incident_id):
    db = get_db()
    incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        abort(404)
    intelligence = lookup_ip(incident["source_ip"], force=True)
    evidence = db.execute("SELECT risk_points FROM evidence WHERE incident_id = ?", (incident_id,)).fetchall()
    score = _calculate_incident_score(incident, evidence, intelligence)
    db.execute(
        "UPDATE incidents SET threat_score = ?, updated_at = ? WHERE id = ?",
        (score, utc_now(), incident_id),
    )
    db.commit()
    record_audit(
        "threat_intel_refreshed",
        "incident",
        incident_id,
        {"ip": incident["source_ip"], "risk": intelligence.get("risk"), "incident_score": score},
        incident_id=incident_id,
    )
    flash("Threat intelligence and incident score refreshed.", "success")
    return redirect(url_for("main.incident_details", incident_id=incident_id) + "#intelligence")


def _report_payload(incident_id):
    sync_incident_iocs(incident_id)
    incident, evidence, timeline, notes, assignment, activities = _incident_bundle(incident_id)
    intelligence = lookup_ip(incident["source_ip"])
    return incident_payload(
        incident,
        evidence,
        timeline,
        notes,
        assignment,
        activities,
        intelligence,
        iocs=incident_iocs(incident_id),
        similar_incidents=find_similar_incidents(incident_id),
    )


@main.route("/incident/<int:incident_id>/report.<fmt>")
@login_required
def incident_report(incident_id, fmt):
    payload = _report_payload(incident_id)
    fmt = fmt.lower()
    if fmt == "pdf":
        stream, mime = incident_pdf_report(payload), "application/pdf"
    elif fmt == "csv":
        stream, mime = incident_csv_report(payload), "text/csv"
    elif fmt == "json":
        stream, mime = json_report(payload), "application/json"
    else:
        abort(404)
    record_audit(
        "incident_report_exported",
        "incident",
        incident_id,
        {"format": fmt},
        incident_id=incident_id,
    )
    return send_file(
        stream,
        mimetype=mime,
        as_attachment=True,
        download_name=f"shadowtrace-v3-incident-{incident_id}.{fmt}",
    )


@main.route("/reports/incidents.<fmt>")
@login_required
def incidents_report(fmt):
    incidents = _all_filtered_incidents(request.args)
    fmt = fmt.lower()
    if fmt == "csv":
        stream, mime = incidents_csv_report(incidents), "text/csv"
    elif fmt == "json":
        stream, mime = (
            json_report({"generated_at": utc_now(), "incidents": [dict(row) for row in incidents]}),
            "application/json",
        )
    elif fmt == "pdf":
        stream, mime = incidents_pdf_report(incidents), "application/pdf"
    else:
        abort(404)
    record_audit(
        "incident_list_exported", "report", fmt, {"count": len(incidents), "format": fmt}
    )
    return send_file(
        stream,
        mimetype=mime,
        as_attachment=True,
        download_name=f"shadowtrace-v3-incidents.{fmt}",
    )


@main.route("/audit")
@login_required
def audit_log():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = 25
    q = (request.args.get("q") or "").strip()
    action = (request.args.get("action") or "").strip()
    conditions = ["1=1"]
    params: list[Any] = []
    if q:
        wildcard = f"%{q}%"
        conditions.append("(username LIKE ? OR entity_type LIKE ? OR entity_id LIKE ? OR details LIKE ?)")
        params.extend([wildcard] * 4)
    if action:
        conditions.append("action = ?")
        params.append(action)
    where = " AND ".join(conditions)
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_log WHERE {where}", params).fetchone()[0]
    pages = max(math.ceil(total / per_page), 1)
    page = min(page, pages)
    rows = db.execute(
        f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page],
    ).fetchall()
    actions = [row[0] for row in db.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    return render_template(
        "audit.html",
        entries=rows,
        page=page,
        pages=pages,
        total=total,
        filters={"q": q, "action": action},
        actions=actions,
    )
