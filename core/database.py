"""
SQLite Database Handler
Author: ARIF
"""

import sqlite3
import json
import os
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime


class Database:
    def __init__(self, db_path: str = "scanner_results.db"):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.conn = None
        self._initialize()

    def _initialize(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")

    def _create_tables(self) -> None:
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                duration REAL,
                total_requests INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                modules TEXT,
                errors TEXT,
                status TEXT DEFAULT 'running',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                severity_score REAL,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                remediation TEXT,
                cvss_score REAL,
                confidence REAL,
                module TEXT,
                timestamp REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS crawl_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                response_time REAL,
                forms TEXT,
                links TEXT,
                timestamp REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS config_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                config_json TEXT,
                timestamp REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_crawl_scan_id ON crawl_results(scan_id);
        """)
        self.conn.commit()

    def save_scan(self, result) -> None:
        if not self.conn:
            return
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scans
                (id, target, start_time, end_time, duration, total_requests,
                 total_vulnerabilities, modules, errors, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                result.target,
                result.start_time,
                result.end_time,
                result.duration,
                result.total_requests,
                len(result.vulnerabilities),
                json.dumps(result.modules_ran),
                json.dumps(result.errors),
                'completed'
            ))
            for vuln in result.vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities
                    (scan_id, name, description, severity, severity_score,
                     url, parameter, payload, evidence, remediation,
                     cvss_score, confidence, module, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    vuln.name,
                    vuln.description,
                    vuln.severity.value,
                    vuln.severity.score,
                    vuln.url,
                    vuln.parameter,
                    vuln.payload,
                    vuln.evidence,
                    vuln.remediation,
                    vuln.cvss_score,
                    vuln.confidence,
                    vuln.module,
                    vuln.timestamp
                ))
            self.conn.commit()
            self.logger.info(f"Scan {result.scan_id} saved to database")
        except Exception as e:
            self.logger.error(f"Failed to save scan: {e}")

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        if not self.conn:
            return None
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            scan = cursor.fetchone()
            if not scan:
                return None
            scan_dict = dict(scan)
            cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            scan_dict['vulnerabilities'] = [dict(v) for v in cursor.fetchall()]
            return scan_dict
        except Exception as e:
            self.logger.error(f"Failed to get scan: {e}")
            return None

    def get_all_scans(self, limit: int = 50) -> List[Dict]:
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get all scans: {e}")
            return []

    def get_vulnerabilities(self, scan_id: Optional[str] = None,
                            severity: Optional[str] = None,
                            limit: int = 100) -> List[Dict]:
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM vulnerabilities WHERE 1=1"
            params = []
            if scan_id:
                query += " AND scan_id = ?"
                params.append(scan_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())
            query += " ORDER BY severity_score DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def delete_scan(self, scan_id: str) -> bool:
        if not self.conn:
            return False
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM crawl_results WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self.conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete scan: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        if not self.conn:
            return {}
        try:
            cursor = self.conn.cursor()
            stats = {}
            cursor.execute("SELECT COUNT(*) FROM scans")
            stats['total_scans'] = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = cursor.fetchone()[0]
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities GROUP BY severity
            """)
            stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
            cursor.execute("""
                SELECT target, COUNT(*) as count
                FROM vulnerabilities GROUP BY target
                ORDER BY count DESC LIMIT 5
            """)
            stats['top_targets'] = [dict(row) for row in cursor.fetchall()]
            cursor.execute("SELECT COUNT(DISTINCT target) FROM scans")
            stats['unique_targets'] = cursor.fetchone()[0]
            return stats
        except Exception as e:
            self.logger.error(f"Failed to get stats: {e}")
            return {}

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
