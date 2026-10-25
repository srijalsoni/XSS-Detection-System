import json
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from database.connection import get_db


def parse_time_filter(time_range: Optional[str]) -> Optional[str]:
    """
    Parses a time filter string ('24h', '7d', '30d', 'all') and returns
    an ISO-8601 UTC cutoff timestamp, or None if 'all' or empty.
    """
    if not time_range or time_range.lower() == "all":
        return None

    now = datetime.now(timezone.utc)
    tr = time_range.lower().strip()
    if tr == "24h":
        cutoff = now - timedelta(hours=24)
    elif tr == "7d":
        cutoff = now - timedelta(days=7)
    elif tr == "30d":
        cutoff = now - timedelta(days=30)
    else:
        # Safe fallback: if unrecognized filter provided, do not crash; treat as 'all'
        return None

    return cutoff.isoformat()


class DashboardRepository:
    """
    Efficient, parameterized aggregation repository for the Security Monitoring Dashboard.
    Performs server-side SQL grouping and counting to deliver high-performance telemetry.
    """

    @staticmethod
    def get_summary(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """Returns high-level event metrics: total, high-risk, critical, blocked."""
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk_events,
                SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_events,
                SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END) as blocked_events,
                SUM(CASE WHEN action = 'REJECTED' THEN 1 ELSE 0 END) as rejected_events,
                SUM(CASE WHEN action = 'SAFE_RENDERED' THEN 1 ELSE 0 END) as safe_rendered_events,
                SUM(CASE WHEN action = 'LOGGED' THEN 1 ELSE 0 END) as logged_events
            FROM security_events
            {where_clause}
        """
        cursor.execute(sql, params)
        row = cursor.fetchone()

        total = row["total_events"] if row and row["total_events"] else 0
        high = row["high_risk_events"] if row and row["high_risk_events"] else 0
        critical = row["critical_events"] if row and row["critical_events"] else 0
        blocked = row["blocked_events"] if row and row["blocked_events"] else 0
        rejected = row["rejected_events"] if row and row["rejected_events"] else 0
        safe_rendered = row["safe_rendered_events"] if row and row["safe_rendered_events"] else 0
        logged = row["logged_events"] if row and row["logged_events"] else 0

        return {
            "total_events": total,
            "high_risk_events": high,
            "critical_events": critical,
            "blocked_events": blocked,
            "rejected_events": rejected,
            "safe_rendered_events": safe_rendered,
            "logged_events": logged,
            "time_filter": time_range or "all",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    def get_risk_distribution(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """Returns frequency of security events grouped by risk level."""
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT risk_level, COUNT(*) as cnt
            FROM security_events
            {where_clause}
            GROUP BY risk_level
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # Deterministic ordering of standard risk levels
        standard_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        counts_dict = {lvl: 0 for lvl in standard_levels}
        for r in rows:
            lvl = r["risk_level"].upper()
            counts_dict[lvl] = r["cnt"]

        return {
            "labels": list(counts_dict.keys()),
            "counts": list(counts_dict.values())
        }

    @staticmethod
    def get_action_distribution(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """Returns frequency of security events grouped by response action."""
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT action, COUNT(*) as cnt
            FROM security_events
            {where_clause}
            GROUP BY action
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        standard_actions = ["LOGGED", "SAFE_RENDERED", "REJECTED", "BLOCKED"]
        counts_dict = {act: 0 for act in standard_actions}
        for r in rows:
            act = r["action"].upper()
            counts_dict[act] = r["cnt"]

        return {
            "labels": list(counts_dict.keys()),
            "counts": list(counts_dict.values())
        }

    @staticmethod
    def get_rule_frequency(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """
        Calculates frequency of each triggered rule.
        Since rule_id may contain comma-separated rules (e.g. 'XSS-001,XSS-006'),
        this aggregation handles split counting cleanly.
        """
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        where_clause = "WHERE created_at >= ? AND rule_id IS NOT NULL" if cutoff else "WHERE rule_id IS NOT NULL"
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT rule_id
            FROM security_events
            {where_clause}
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        rule_names = {
            "XSS-001": "Script Tag",
            "XSS-002": "Event Handler",
            "XSS-003": "Executable Scheme",
            "XSS-004": "Dangerous Elements",
            "XSS-005": "Attribute Breakout",
            "XSS-006": "JavaScript Sink"
        }
        counts = {r_id: 0 for r_id in rule_names}

        for r in rows:
            r_str = r["rule_id"] or ""
            parts = [p.strip() for p in r_str.split(",") if p.strip()]
            for p in parts:
                counts[p] = counts.get(p, 0) + 1

        sorted_rules = sorted(counts.keys())
        labels = [f"{r_id} ({rule_names.get(r_id, 'Other')})" for r_id in sorted_rules]
        values = [counts[r_id] for r_id in sorted_rules]

        return {
            "rule_ids": sorted_rules,
            "labels": labels,
            "counts": values
        }

    @staticmethod
    def get_endpoint_distribution(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """Returns security events count grouped by target endpoint."""
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT endpoint, COUNT(*) as cnt
            FROM security_events
            {where_clause}
            GROUP BY endpoint
            ORDER BY cnt DESC
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        labels = [r["endpoint"] for r in rows]
        counts = [r["cnt"] for r in rows]

        return {
            "labels": labels,
            "counts": counts
        }

    @staticmethod
    def get_timeline(time_range: Optional[str] = None, conn=None) -> Dict[str, Any]:
        """
        Returns security event counts over time grouped by hour (for 24h) or date.
        """
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        # If 24h, group by substring YYYY-MM-DDTHH:00; otherwise YYYY-MM-DD
        is_24h = (time_range and time_range.lower() == "24h")
        date_substr_len = 13 if is_24h else 10  # 2026-09-29T11 vs 2026-09-29

        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff,) if cutoff else ()

        sql = f"""
            SELECT SUBSTR(created_at, 1, {date_substr_len}) as time_bucket, COUNT(*) as cnt
            FROM security_events
            {where_clause}
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        labels = [r["time_bucket"] for r in rows]
        counts = [r["cnt"] for r in rows]

        return {
            "labels": labels,
            "counts": counts
        }

    @staticmethod
    def get_recent_events(limit: int = 15, time_range: Optional[str] = None, conn=None) -> List[Dict[str, Any]]:
        """
        Retrieves recent security telemetry events.
        CRITICAL PRIVACY GUARANTEE: Never exposes raw attack payloads or internal secrets.
        """
        db = conn or get_db()
        cutoff = parse_time_filter(time_range)
        cursor = db.cursor()

        safe_limit = max(1, min(limit, 100))
        where_clause = "WHERE created_at >= ?" if cutoff else ""
        params = (cutoff, safe_limit) if cutoff else (safe_limit,)

        sql = f"""
            SELECT id, created_at, event_type, endpoint, method, risk_level, action,
                   rule_id, request_id, details_json
            FROM security_events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
        """
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        events = []
        for r in rows:
            reason = ""
            confidence = 0.0
            field_name = ""
            if r["details_json"]:
                try:
                    d = json.loads(r["details_json"])
                    reason = d.get("reasoning", "")
                    confidence = d.get("confidence", 0.0)
                    field_name = d.get("field", "")
                except Exception:
                    pass

            events.append({
                "id": r["id"],
                "created_at": r["created_at"],
                "event_type": r["event_type"],
                "endpoint": r["endpoint"],
                "method": r["method"],
                "risk_level": r["risk_level"],
                "action": r["action"],
                "rule_id": r["rule_id"] or "N/A",
                "field": field_name or "N/A",
                "request_id": r["request_id"] or "N/A",
                "confidence": confidence,
                "reason": reason
            })
        return events
