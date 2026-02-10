"""
SQLite Database Module for Project Atlas

Handles persistent storage of scan results, statistics, and history.
"""

import os
import sqlite3
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

from extension_shield.core.config import get_settings


class Database:
    """SQLite database manager for Project Atlas."""

    def __init__(self, db_path: str = None):
        """Initialize database connection.

        Args:
            db_path: Path to SQLite database file. If None, uses DATABASE_PATH
                     environment variable or defaults to 'project-atlas.db'.
        """
        if db_path is None:
            db_path = get_settings().database_path
        self.db_path = Path(db_path)
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_database(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Privacy-first telemetry (no PII)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS page_views_daily (
                    day TEXT NOT NULL,
                    path TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, path)
                )
            """
            )

            # User-scoped scan history (references global scan_results by extension_id)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS user_scan_history (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    extension_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """
            )

            # Scan results table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    extension_id TEXT UNIQUE NOT NULL,
                    extension_name TEXT,
                    url TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    security_score INTEGER,
                    risk_level TEXT,
                    total_findings INTEGER DEFAULT 0,
                    total_files INTEGER DEFAULT 0,
                    high_risk_count INTEGER DEFAULT 0,
                    medium_risk_count INTEGER DEFAULT 0,
                    low_risk_count INTEGER DEFAULT 0,
                    metadata TEXT,
                    manifest TEXT,
                    permissions_analysis TEXT,
                    sast_results TEXT,
                    webstore_analysis TEXT,
                    summary TEXT,
                    extracted_path TEXT,
                    extracted_files TEXT,
                    icon_path TEXT,
                    error TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            
            # Add icon_path column if it doesn't exist (for existing databases)
            try:
                cursor.execute("ALTER TABLE scan_results ADD COLUMN icon_path TEXT")
            except Exception:
                # Column already exists, ignore
                pass

            # Statistics table for aggregated metrics
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT UNIQUE NOT NULL,
                    metric_value INTEGER DEFAULT 0,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Initialize default statistics
            cursor.execute(
                """
                INSERT OR IGNORE INTO statistics (metric_name, metric_value)
                VALUES 
                    ('total_scans', 0),
                    ('high_risk_extensions', 0),
                    ('total_files_analyzed', 0),
                    ('total_vulnerabilities', 0)
            """
            )

            # Create indexes for better query performance
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_extension_id 
                ON scan_results(extension_id)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON scan_results(timestamp DESC)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_risk_level 
                ON scan_results(risk_level)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_page_views_day
                ON page_views_daily(day)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_scan_history_user_created
                ON user_scan_history(user_id, created_at DESC)
            """
            )

    def save_scan_result(self, result: Dict[str, Any]) -> bool:
        """Save or update scan result."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Extract metadata
                extension_id = result.get("extension_id")
                metadata = result.get("metadata", {}) or {}
                # Get extension_name from top-level first, then try metadata fields
                extension_name = (
                    result.get("extension_name")
                    or metadata.get("title")
                    or metadata.get("name")
                    or extension_id
                )

                # Calculate risk distribution
                risk_dist = result.get("risk_distribution", {})

                # Enhance summary with modern fields for signals and risk calculation
                summary_data = result.get("summary", {}) or {}
                if not isinstance(summary_data, dict):
                    summary_data = {}
                
                # Store modern fields in summary JSON for backward compatibility
                # These fields are needed for frontend signal calculation
                if result.get("scoring_v2"):
                    summary_data["scoring_v2"] = result.get("scoring_v2")
                if result.get("report_view_model"):
                    summary_data["report_view_model"] = result.get("report_view_model")
                if result.get("governance_bundle"):
                    summary_data["governance_bundle"] = result.get("governance_bundle")
                if result.get("virustotal_analysis"):
                    summary_data["virustotal_analysis"] = result.get("virustotal_analysis")

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO scan_results (
                        extension_id, extension_name, url, timestamp, status,
                        security_score, risk_level, total_findings, total_files,
                        high_risk_count, medium_risk_count, low_risk_count,
                        metadata, manifest, permissions_analysis, sast_results,
                        webstore_analysis, summary, extracted_path, extracted_files,
                        icon_path, error, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        extension_id,
                        extension_name,
                        result.get("url"),
                        result.get("timestamp"),
                        result.get("status"),
                        result.get("overall_security_score"),
                        result.get("overall_risk"),
                        result.get("total_findings", 0),
                        len(result.get("extracted_files") or []),
                        risk_dist.get("high", 0),
                        risk_dist.get("medium", 0),
                        risk_dist.get("low", 0),
                        json.dumps(result.get("metadata", {})),
                        json.dumps(result.get("manifest", {})),
                        json.dumps(result.get("permissions_analysis", {})),
                        json.dumps(result.get("sast_results", {})),
                        json.dumps(result.get("webstore_analysis", {})),
                        json.dumps(summary_data),
                        result.get("extracted_path"),
                        json.dumps(result.get("extracted_files", [])),
                        result.get("icon_path"),  # Relative path to icon (e.g., "icons/128.png")
                        result.get("error"),
                        datetime.now().isoformat(),
                    ),
                )

                # Update statistics
                self._update_statistics()

                return True
        except Exception as e:
            print(f"Error saving scan result: {e}")
            return False

    def increment_page_view(self, day: str, path: str) -> int:
        """
        Increment a page view count for a given UTC day + path.

        Args:
            day: YYYY-MM-DD (UTC)
            path: Route path (e.g., /research)

        Returns:
            Updated count
        """
        path = (path or "/").strip()
        if not path.startswith("/"):
            path = "/" + path

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO page_views_daily (day, path, count)
                VALUES (?, ?, 1)
                ON CONFLICT(day, path) DO UPDATE SET count = count + 1
            """,
                (day, path),
            )
            cursor.execute(
                "SELECT count FROM page_views_daily WHERE day = ? AND path = ?",
                (day, path),
            )
            row = cursor.fetchone()
            return int(row["count"]) if row else 0

    def get_page_view_summary(self, days: int = 14) -> Dict[str, Any]:
        """
        Return aggregate telemetry counts for the last N UTC days.

        Returns:
            {
              "days": int,
              "start_day": "YYYY-MM-DD",
              "end_day": "YYYY-MM-DD",
              "by_day": { "YYYY-MM-DD": int },
              "by_path": { "/research": int },
              "rows": [{ "day": "...", "path": "...", "count": 123 }]
            }
        """
        days = int(days or 14)
        days = max(1, min(days, 365))

        now_utc = datetime.now(timezone.utc).date()
        start_date = now_utc - timedelta(days=days - 1)
        start_day = start_date.strftime("%Y-%m-%d")
        end_day = now_utc.strftime("%Y-%m-%d")

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT day, path, count
                FROM page_views_daily
                WHERE day >= ?
                ORDER BY day ASC, path ASC
            """,
                (start_day,),
            )
            rows = [dict(r) for r in cursor.fetchall()]

        by_day: Dict[str, int] = {}
        by_path: Dict[str, int] = {}
        for r in rows:
            d = r.get("day")
            p = r.get("path")
            c = int(r.get("count") or 0)
            if d:
                by_day[d] = by_day.get(d, 0) + c
            if p:
                by_path[p] = by_path.get(p, 0) + c

        return {
            "days": days,
            "start_day": start_day,
            "end_day": end_day,
            "by_day": by_day,
            "by_path": by_path,
            "rows": rows,
        }

    def add_user_scan_history(self, user_id: str, extension_id: str) -> bool:
        """
        Insert a user-scoped scan history entry.
        """
        try:
            now = datetime.now(timezone.utc).isoformat()
            row_id = str(uuid.uuid4())
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO user_scan_history (id, user_id, extension_id, created_at)
                    VALUES (?, ?, ?, ?)
                """,
                    (row_id, user_id, extension_id, now),
                )
            return True
        except Exception as e:
            print(f"Error adding user scan history: {e}")
            return False

    def get_user_scan_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get scan history for a single user, joined with global scan_results by extension_id.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT
                        h.extension_id,
                        r.extension_name,
                        r.url,
                        r.timestamp,
                        r.status,
                        r.security_score,
                        r.risk_level,
                        r.total_findings,
                        r.total_files,
                        r.high_risk_count,
                        r.medium_risk_count,
                        r.low_risk_count
                    FROM user_scan_history h
                    LEFT JOIN scan_results r
                        ON r.extension_id = h.extension_id
                    WHERE h.user_id = ?
                    ORDER BY h.created_at DESC
                    LIMIT ?
                """,
                    (user_id, limit),
                )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting user scan history: {e}")
            return []

    def get_scan_result(self, extension_id: str) -> Optional[Dict[str, Any]]:
        """Get scan result by extension ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM scan_results WHERE extension_id = ?
                """,
                    (extension_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                return self._row_to_dict(row)
        except Exception as e:
            print(f"Error getting scan result: {e}")
            return None

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan history ordered by most recent."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        extension_id, extension_name, url, timestamp, status,
                        security_score, risk_level, total_findings, total_files,
                        high_risk_count, medium_risk_count, low_risk_count
                    FROM scan_results
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting scan history: {e}")
            return []

    def get_statistics(self) -> Dict[str, int]:
        """Get aggregated statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get basic stats from statistics table
                cursor.execute("SELECT metric_name, metric_value FROM statistics")
                stats = {row["metric_name"]: row["metric_value"] for row in cursor.fetchall()}

                # Get additional computed stats
                cursor.execute(
                    """
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk,
                        SUM(total_files) as total_files,
                        SUM(total_findings) as total_findings,
                        AVG(security_score) as avg_security_score
                    FROM scan_results
                    WHERE status = 'completed'
                """
                )

                row = cursor.fetchone()
                if row:
                    stats.update(
                        {
                            "total_scans": row["total_scans"] or 0,
                            "high_risk_extensions": row["high_risk"] or 0,
                            "total_files_analyzed": row["total_files"] or 0,
                            "total_vulnerabilities": row["total_findings"] or 0,
                            "avg_security_score": int(row["avg_security_score"] or 0),
                        }
                    )

                return stats
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                "total_scans": 0,
                "high_risk_extensions": 0,
                "total_files_analyzed": 0,
                "total_vulnerabilities": 0,
                "avg_security_score": 0,
            }

    def get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of risk levels."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        risk_level,
                        COUNT(*) as count
                    FROM scan_results
                    WHERE status = 'completed'
                    GROUP BY risk_level
                """
                )

                distribution = {"high": 0, "medium": 0, "low": 0}
                for row in cursor.fetchall():
                    risk_level = row["risk_level"]
                    if risk_level in distribution:
                        distribution[risk_level] = row["count"]

                return distribution
        except Exception as e:
            print(f"Error getting risk distribution: {e}")
            return {"high": 0, "medium": 0, "low": 0}

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans with summary info including metadata and signal data to avoid N+1 queries."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        extension_id, extension_name, timestamp,
                        security_score, risk_level, total_findings,
                        total_files, metadata, 
                        sast_results, permissions_analysis, manifest, 
                        webstore_analysis, summary
                    FROM scan_results
                    WHERE status = 'completed'
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

                # Use _row_to_dict to parse JSON fields like metadata, sast_results, etc.
                rows = cursor.fetchall()
                result_rows = []
                for row in rows:
                    row_dict = self._row_to_dict(row)
                    
                    # Extract modern fields from summary JSON if present (for signal calculation)
                    summary = row_dict.get("summary", {})
                    if isinstance(summary, dict):
                        if "scoring_v2" in summary:
                            row_dict["scoring_v2"] = summary.get("scoring_v2")
                        if "report_view_model" in summary:
                            row_dict["report_view_model"] = summary.get("report_view_model")
                        if "governance_bundle" in summary:
                            row_dict["governance_bundle"] = summary.get("governance_bundle")
                        if "virustotal_analysis" in summary:
                            row_dict["virustotal_analysis"] = summary.get("virustotal_analysis")
                    
                    result_rows.append(row_dict)
                
                return result_rows
        except Exception as e:
            print(f"Error getting recent scans: {e}")
            return []

    def delete_scan_result(self, extension_id: str) -> bool:
        """Delete a scan result."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM scan_results WHERE extension_id = ?
                """,
                    (extension_id,),
                )

                self._update_statistics()
                return True
        except Exception as e:
            print(f"Error deleting scan result: {e}")
            return False

    def clear_all_results(self) -> bool:
        """Clear all scan results."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_results")
                self._update_statistics()
                return True
        except Exception as e:
            print(f"Error clearing results: {e}")
            return False

    def _update_statistics(self):
        """Update aggregated statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Update total scans
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COUNT(*) FROM scan_results WHERE status = 'completed'
                    ),
                        updated_at = ?
                    WHERE metric_name = 'total_scans'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update high risk count
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COUNT(*) FROM scan_results 
                        WHERE status = 'completed' AND risk_level = 'high'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'high_risk_extensions'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update total files
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COALESCE(SUM(total_files), 0) FROM scan_results 
                        WHERE status = 'completed'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'total_files_analyzed'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update total vulnerabilities
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COALESCE(SUM(total_findings), 0) FROM scan_results 
                        WHERE status = 'completed'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'total_vulnerabilities'
                """,
                    (datetime.now().isoformat(),),
                )

        except Exception as e:
            print(f"Error updating statistics: {e}")

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert database row to dictionary with JSON parsing."""
        result = dict(row)

        # Parse JSON fields
        json_fields = [
            "metadata",
            "manifest",
            "permissions_analysis",
            "sast_results",
            "webstore_analysis",
            "summary",
            "extracted_files",
        ]

        for field in json_fields:
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except json.JSONDecodeError:
                    result[field] = {}

        return result


class SupabaseDatabase:
    """
    Supabase-backed storage adapter.

    Uses a single `scan_results` table (JSON-friendly) and computes statistics on-the-fly.
    This is intended for production deployments where the filesystem/SQLite may be ephemeral.
    """

    def __init__(self):
        settings = get_settings()
        supabase_url = settings.supabase_url
        supabase_key = settings.supabase_key
        if not supabase_url or not supabase_key:
            raise ValueError("Missing SUPABASE_URL or SUPABASE_*_KEY")

        self.table_scan_results = settings.supabase_scan_results_table

        # Lazy import so local dev doesn't require Supabase deps unless enabled.
        from supabase import create_client  # type: ignore

        self.client = create_client(supabase_url, supabase_key)

    def save_scan_result(self, result: Dict[str, Any]) -> bool:
        try:
            extension_id = result.get("extension_id")
            if not extension_id:
                return False

            metadata = result.get("metadata", {}) or {}
            extension_name = (
                result.get("extension_name")
                or metadata.get("title")
                or metadata.get("name")
                or extension_id
            )

            risk_dist = result.get("risk_distribution", {}) or {}
            extracted_files = result.get("extracted_files") or []

            # Map timestamp to scanned_at (Supabase column name)
            timestamp_value = result.get("timestamp")
            # Convert ISO string to timestamptz if needed, or use current time
            if timestamp_value:
                scanned_at = timestamp_value
            else:
                scanned_at = datetime.now(timezone.utc).isoformat()
            
            # Enhance summary with modern fields for signals and risk calculation
            summary_data = result.get("summary", {}) or {}
            if not isinstance(summary_data, dict):
                summary_data = {}
            
            # Store modern fields in summary JSONB for backward compatibility
            # These fields are needed for frontend signal calculation
            if result.get("scoring_v2"):
                summary_data["scoring_v2"] = result.get("scoring_v2")
            if result.get("report_view_model"):
                summary_data["report_view_model"] = result.get("report_view_model")
            if result.get("governance_bundle"):
                summary_data["governance_bundle"] = result.get("governance_bundle")
            if result.get("virustotal_analysis"):
                summary_data["virustotal_analysis"] = result.get("virustotal_analysis")
            
            row = {
                "extension_id": extension_id,
                "extension_name": extension_name,
                "url": result.get("url"),
                "scanned_at": scanned_at,  # Renamed from timestamp → scanned_at
                "status": result.get("status"),
                "security_score": result.get("overall_security_score"),
                "risk_level": result.get("overall_risk"),
                "total_findings": result.get("total_findings", 0),
                "total_files": len(extracted_files),
                "high_risk_count": risk_dist.get("high", 0),
                "medium_risk_count": risk_dist.get("medium", 0),
                "low_risk_count": risk_dist.get("low", 0),
                "metadata": result.get("metadata", {}) or {},
                "manifest": result.get("manifest", {}) or {},
                "permissions_analysis": result.get("permissions_analysis", {}) or {},
                "sast_results": result.get("sast_results", {}) or {},
                "webstore_analysis": result.get("webstore_analysis", {}) or {},
                "summary": summary_data,  # Enhanced with modern fields
                "extracted_path": result.get("extracted_path"),
                "extracted_files": extracted_files,
                "icon_path": result.get("icon_path"),  # Relative path to icon (e.g., "icons/128.png")
                "error": result.get("error"),
                # updated_at is auto-updated by trigger, but set it anyway for initial insert
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            # Upsert on extension_id
            self.client.table(self.table_scan_results).upsert(row).execute()
            return True
        except Exception as e:
            print(f"Error saving scan result (Supabase): {e}")
            return False

    def add_user_scan_history(self, user_id: str, extension_id: str) -> bool:
        """
        Insert into Supabase `user_scan_history`.
        The trigger `user_scan_history_increment_karma` will automatically:
        - Create/update user_profiles record
        - Increment karma_points by 1
        - Increment total_scans by 1
        Relies on RLS policies in production.
        """
        try:
            # Check if this extension was already scanned by this user (avoid duplicate karma)
            existing = (
                self.client.table("user_scan_history")
                .select("id")
                .eq("user_id", user_id)
                .eq("extension_id", extension_id)
                .limit(1)
                .execute()
            )
            
            existing_data = getattr(existing, "data", None) or []
            if existing_data:
                # User already scanned this extension, don't add duplicate or increment karma
                return True
            
            # Insert new scan history (trigger will handle karma increment)
            self.client.table("user_scan_history").insert(
                {"user_id": user_id, "extension_id": extension_id}
            ).execute()
            return True
        except Exception as e:
            print(f"Error adding user scan history (Supabase): {e}")
            return False
    
    def get_user_karma(self, user_id: str) -> Dict[str, Any]:
        """
        Get user's karma points and scan statistics.
        """
        try:
            resp = (
                self.client.table("user_profiles")
                .select("karma_points, total_scans, created_at, updated_at")
                .eq("user_id", user_id)
                .limit(1)
                .execute()
            )
            data = getattr(resp, "data", None) or []
            if data:
                return data[0]
            # Return defaults if profile doesn't exist yet
            return {"karma_points": 0, "total_scans": 0, "created_at": None, "updated_at": None}
        except Exception as e:
            print(f"Error getting user karma (Supabase): {e}")
            return {"karma_points": 0, "total_scans": 0, "created_at": None, "updated_at": None}

    def get_user_scan_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch user history rows, then look up global scan_results by extension_id.
        """
        try:
            hist_resp = (
                self.client.table("user_scan_history")
                .select("extension_id, created_at")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            hist_rows = getattr(hist_resp, "data", None) or []
            ext_ids = [r.get("extension_id") for r in hist_rows if r.get("extension_id")]
            if not ext_ids:
                return []

            scans_resp = (
                self.client.table(self.table_scan_results)
                .select(
                    "extension_id, extension_name, url, scanned_at, status, security_score, risk_level, total_findings, total_files, high_risk_count, medium_risk_count, low_risk_count, metadata, sast_results, permissions_analysis, manifest, summary"
                )
                .in_("extension_id", ext_ids)
                .execute()
            )
            scans = getattr(scans_resp, "data", None) or []
            by_id = {}
            for r in scans:
                # Map scanned_at → timestamp for API compatibility
                if "scanned_at" in r:
                    r["timestamp"] = r.pop("scanned_at")
                
                # Extract modern fields from summary JSONB if present
                summary = r.get("summary", {})
                if isinstance(summary, dict):
                    if "scoring_v2" in summary:
                        r["scoring_v2"] = summary.get("scoring_v2")
                    if "report_view_model" in summary:
                        r["report_view_model"] = summary.get("report_view_model")
                    if "governance_bundle" in summary:
                        r["governance_bundle"] = summary.get("governance_bundle")
                    if "virustotal_analysis" in summary:
                        r["virustotal_analysis"] = summary.get("virustotal_analysis")
                
                by_id[r.get("extension_id")] = r

            # Preserve user history ordering; attach scan summary where available.
            out: List[Dict[str, Any]] = []
            for h in hist_rows:
                ext = h.get("extension_id")
                row = by_id.get(ext, {"extension_id": ext})
                out.append(row)
            return out
        except Exception as e:
            print(f"Error getting user scan history (Supabase): {e}")
            return []

    def get_scan_result(self, extension_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = (
                self.client.table(self.table_scan_results)
                .select("*")
                .eq("extension_id", extension_id)
                .limit(1)
                .execute()
            )
            data = getattr(resp, "data", None) or []
            if not data:
                return None
            
            # Map scanned_at → timestamp for API compatibility
            result = data[0]
            if "scanned_at" in result:
                result["timestamp"] = result.pop("scanned_at")
            
            # Extract modern fields from summary JSONB if present
            # Also check top-level in case they were stored there (backward compatibility)
            summary = result.get("summary", {})
            if isinstance(summary, dict):
                if "scoring_v2" in summary:
                    result["scoring_v2"] = summary.get("scoring_v2")
                if "report_view_model" in summary:
                    result["report_view_model"] = summary.get("report_view_model")
                if "governance_bundle" in summary:
                    result["governance_bundle"] = summary.get("governance_bundle")
                if "virustotal_analysis" in summary:
                    result["virustotal_analysis"] = summary.get("virustotal_analysis")
            
            # If not found in summary, check top-level (for backward compatibility with old scans)
            # Note: Supabase might return these as top-level fields if they were stored that way
            if "scoring_v2" not in result and result.get("scoring_v2"):
                pass  # Already at top level
            if "virustotal_analysis" not in result and result.get("virustotal_analysis"):
                pass  # Already at top level
            
            return result
        except Exception as e:
            print(f"Error getting scan result (Supabase): {e}")
            return None

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            resp = (
                self.client.table(self.table_scan_results)
                .select(
                    "extension_id, extension_name, url, scanned_at, status, security_score, risk_level, total_findings, total_files, high_risk_count, medium_risk_count, low_risk_count, metadata, sast_results, permissions_analysis, manifest, summary"
                )
                .order("scanned_at", desc=True)
                .limit(limit)
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            # Map scanned_at → timestamp for API compatibility
            # Extract modern fields from summary for frontend compatibility
            for row in rows:
                if "scanned_at" in row:
                    row["timestamp"] = row.pop("scanned_at")
                
                # Extract modern fields from summary JSONB if present
                summary = row.get("summary", {})
                if isinstance(summary, dict):
                    if "scoring_v2" in summary:
                        row["scoring_v2"] = summary.get("scoring_v2")
                    if "report_view_model" in summary:
                        row["report_view_model"] = summary.get("report_view_model")
                    if "governance_bundle" in summary:
                        row["governance_bundle"] = summary.get("governance_bundle")
                    if "virustotal_analysis" in summary:
                        row["virustotal_analysis"] = summary.get("virustotal_analysis")
            return rows
        except Exception as e:
            print(f"Error getting scan history (Supabase): {e}")
            return []

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        try:
            resp = (
                self.client.table(self.table_scan_results)
                .select("extension_id, extension_name, scanned_at, security_score, risk_level, total_findings, total_files, metadata, sast_results, permissions_analysis, manifest, summary")
                .eq("status", "completed")
                .order("scanned_at", desc=True)
                .limit(limit)
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            # Map scanned_at → timestamp for API compatibility
            # Extract modern fields from summary for frontend compatibility
            for row in rows:
                if "scanned_at" in row:
                    row["timestamp"] = row.pop("scanned_at")
                
                # Extract modern fields from summary JSONB if present
                summary = row.get("summary", {})
                if isinstance(summary, dict):
                    if "scoring_v2" in summary:
                        row["scoring_v2"] = summary.get("scoring_v2")
                    if "report_view_model" in summary:
                        row["report_view_model"] = summary.get("report_view_model")
                    if "governance_bundle" in summary:
                        row["governance_bundle"] = summary.get("governance_bundle")
                    if "virustotal_analysis" in summary:
                        row["virustotal_analysis"] = summary.get("virustotal_analysis")
            return rows
        except Exception as e:
            print(f"Error getting recent scans (Supabase): {e}")
            return []

    def delete_scan_result(self, extension_id: str) -> bool:
        try:
            self.client.table(self.table_scan_results).delete().eq("extension_id", extension_id).execute()
            return True
        except Exception as e:
            print(f"Error deleting scan result (Supabase): {e}")
            return False

    def clear_all_results(self) -> bool:
        try:
            # PostgREST requires a filter for deletes; this matches all rows.
            self.client.table(self.table_scan_results).delete().neq("extension_id", "").execute()
            return True
        except Exception as e:
            print(f"Error clearing results (Supabase): {e}")
            return False

    def get_risk_distribution(self) -> Dict[str, int]:
        dist = {"high": 0, "medium": 0, "low": 0}
        try:
            resp = (
                self.client.table(self.table_scan_results)
                .select("risk_level")
                .eq("status", "completed")
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            for r in rows:
                level = (r.get("risk_level") or "").lower()
                if level in dist:
                    dist[level] += 1
            return dist
        except Exception as e:
            print(f"Error getting risk distribution (Supabase): {e}")
            return dist

    def get_statistics(self) -> Dict[str, int]:
        """
        Compute stats on-the-fly from scan_results.
        (For large datasets you can replace with a materialized stats table or RPC.)
        """
        try:
            resp = (
                self.client.table(self.table_scan_results)
                .select("security_score, risk_level, total_files, total_findings")
                .eq("status", "completed")
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            total_scans = len(rows)
            high_risk = sum(1 for r in rows if (r.get("risk_level") or "").lower() == "high")
            total_files = sum(int(r.get("total_files") or 0) for r in rows)
            total_findings = sum(int(r.get("total_findings") or 0) for r in rows)
            security_scores = [int(r["security_score"]) for r in rows if r.get("security_score") is not None]
            avg_security_score = int(sum(security_scores) / len(security_scores)) if security_scores else 0

            return {
                "total_scans": total_scans,
                "high_risk_extensions": high_risk,
                "total_files_analyzed": total_files,
                "total_vulnerabilities": total_findings,
                "avg_security_score": avg_security_score,
            }
        except Exception as e:
            print(f"Error getting statistics (Supabase): {e}")
            return {
                "total_scans": 0,
                "high_risk_extensions": 0,
                "total_files_analyzed": 0,
                "total_vulnerabilities": 0,
                "avg_security_score": 0,
            }

    def increment_page_view(self, day: str, path: str) -> int:
        """
        Increment a page view count for a given UTC day + path (Supabase backend).
        
        Uses atomic RPC function to prevent race conditions and lost updates.

        Args:
            day: YYYY-MM-DD (UTC)
            path: Route path (e.g., /research)

        Returns:
            Updated count
        """
        path = (path or "/").strip()
        if not path.startswith("/"):
            path = "/" + path

        try:
            # Use atomic RPC function for safe concurrent increments
            resp = self.client.rpc(
                "increment_page_view",
                {"p_day": day, "p_path": path}
            ).execute()
            
            # Parse RPC return value - handle multiple response formats
            result = getattr(resp, "data", None)
            if result is None:
                return 0
            
            # Case 1: Direct integer
            if isinstance(result, int):
                return result
            
            # Case 2: String representation of integer
            if isinstance(result, str):
                try:
                    return int(result)
                except (ValueError, TypeError):
                    return 0
            
            # Case 3: Dictionary with count or function name as key
            if isinstance(result, dict):
                # Try common keys
                count = result.get("count") or result.get("increment_page_view") or result.get("value")
                if count is not None:
                    try:
                        return int(count)
                    except (ValueError, TypeError):
                        pass
                return 0
            
            # Case 4: List of values
            if isinstance(result, list) and len(result) > 0:
                first_item = result[0]
                # If list contains integers
                if isinstance(first_item, int):
                    return first_item
                # If list contains dicts
                if isinstance(first_item, dict):
                    count = first_item.get("count") or first_item.get("increment_page_view") or first_item.get("value")
                    if count is not None:
                        try:
                            return int(count)
                        except (ValueError, TypeError):
                            pass
                # If list contains strings
                if isinstance(first_item, str):
                    try:
                        return int(first_item)
                    except (ValueError, TypeError):
                        pass
            
            return 0
                
        except Exception as e:
            print(f"Error incrementing page view (Supabase): {e}")
            # Fallback to non-atomic method if RPC doesn't exist (backward compatibility)
            try:
                resp = (
                    self.client.table("page_views_daily")
                    .select("count")
                    .eq("day", day)
                    .eq("path", path)
                    .limit(1)
                    .execute()
                )
                data = getattr(resp, "data", None) or []
                
                if data:
                    current_count = int(data[0].get("count", 0))
                    new_count = current_count + 1
                    self.client.table("page_views_daily").update(
                        {"count": new_count}
                    ).eq("day", day).eq("path", path).execute()
                    return new_count
                else:
                    self.client.table("page_views_daily").insert(
                        {"day": day, "path": path, "count": 1}
                    ).execute()
                    return 1
            except Exception:
                return 0

    def get_page_view_summary(self, days: int = 14) -> Dict[str, Any]:
        """
        Return aggregate telemetry counts for the last N UTC days (Supabase backend).

        Returns:
            {
              "days": int,
              "start_day": "YYYY-MM-DD",
              "end_day": "YYYY-MM-DD",
              "by_day": { "YYYY-MM-DD": int },
              "by_path": { "/research": int },
              "rows": [{ "day": "...", "path": "...", "count": 123 }]
            }
        """
        days = int(days or 14)
        days = max(1, min(days, 365))

        now_utc = datetime.now(timezone.utc).date()
        start_date = now_utc - timedelta(days=days - 1)
        start_day = start_date.strftime("%Y-%m-%d")
        end_day = now_utc.strftime("%Y-%m-%d")

        try:
            resp = (
                self.client.table("page_views_daily")
                .select("day, path, count")
                .gte("day", start_day)
                .order("day", desc=False)
                .execute()
            )
            rows = getattr(resp, "data", None) or []

            by_day: Dict[str, int] = {}
            by_path: Dict[str, int] = {}
            for r in rows:
                d = r.get("day")
                p = r.get("path")
                c = int(r.get("count") or 0)
                if d:
                    by_day[d] = by_day.get(d, 0) + c
                if p:
                    by_path[p] = by_path.get(p, 0) + c

            return {
                "days": days,
                "start_day": start_day,
                "end_day": end_day,
                "by_day": by_day,
                "by_path": by_path,
                "rows": rows,
            }
        except Exception as e:
            print(f"Error getting page view summary (Supabase): {e}")
            return {
                "days": days,
                "start_day": start_day,
                "end_day": end_day,
                "by_day": {},
                "by_path": {},
                "rows": [],
            }


def _create_db():
    """
    Choose storage backend:
    - Supabase if SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are set
    - SQLite otherwise (dev fallback)
    """
    import logging
    logger = logging.getLogger(__name__)
    
    settings = get_settings()

    if settings.db_backend == "supabase":
        try:
            db = SupabaseDatabase()
            logger.info("✓ DB backend selected: supabase")
            print("✓ DB backend selected: supabase")
            return db
        except Exception as e:
            logger.warning(
                f"Supabase enabled but failed to initialize. Falling back to SQLite. Error: {e}"
            )
            print(
                f"⚠️  Supabase enabled but failed to initialize. Falling back to SQLite. Error: {e}"
            )
            db = Database()
            logger.info("✓ DB backend selected: sqlite (fallback)")
            print("✓ DB backend selected: sqlite (fallback)")
            return db

    if settings.db_backend == "sqlite":
        db = Database()
        logger.info("✓ DB backend selected: sqlite")
        print("✓ DB backend selected: sqlite")
        return db

    # Postgres not supported by current implementation (see core.config validation).
    raise ValueError(f"Unsupported DB backend: {settings.db_backend}")


# Global database instance
db = _create_db()

