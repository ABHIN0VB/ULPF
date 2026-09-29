import sqlite3
import json
import threading
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

class SQLiteEventStore:
    def __init__(self, db_path='ulpf_events.db'):
        self.db_path = db_path
        self.local = threading.local()
        self._init_db()

    def get_conn(self) -> sqlite3.Connection:
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.local.conn.row_factory = sqlite3.Row
            self.local.conn.execute('PRAGMA journal_mode=WAL')
            self.local.conn.execute('PRAGMA busy_timeout=5000')
        return self.local.conn

    def _init_db(self):
        conn = self.get_conn()
        c = conn.cursor()
        
        # 1. Raw Events Store (First class citizen, immutable forensic audit trail)
        c.execute('''CREATE TABLE IF NOT EXISTS raw_events (
            id TEXT PRIMARY KEY,
            received_at DATETIME,
            source_id TEXT,
            source_ip TEXT,
            raw_log TEXT,
            raw_hash TEXT,
            size_bytes INTEGER
        )''')

        # 2. Normalized Events Store (Universal Event Schema)
        c.execute('''CREATE TABLE IF NOT EXISTS normalized_events (
            id TEXT PRIMARY KEY,
            raw_event_id TEXT,
            processed_at DATETIME,
            source_id TEXT,
            parser_plugin TEXT,
            parser_version TEXT,
            mapping_version TEXT,
            schema_version TEXT,
            confidence REAL,
            event_action TEXT,
            event_outcome TEXT,
            event_severity INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            host_name TEXT,
            user_name TEXT,
            is_duplicate INTEGER DEFAULT 0,
            dedup_key TEXT,
            field_completeness REAL,
            schema_valid INTEGER DEFAULT 1,
            tags TEXT,
            full_event TEXT,
            FOREIGN KEY (raw_event_id) REFERENCES raw_events(id)
        )''')

        # 3. Dead Letter Queue (DLQ / Quarantine for malformed/unsupported events)
        c.execute('''CREATE TABLE IF NOT EXISTS failed_events (
            id TEXT PRIMARY KEY,
            raw_event_id TEXT,
            timestamp DATETIME,
            source_id TEXT,
            raw_log TEXT,
            raw_hash TEXT,
            failure_reason TEXT,
            parser_attempted TEXT,
            processing_stage TEXT,
            error_details TEXT,
            retry_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'quarantined',
            FOREIGN KEY (raw_event_id) REFERENCES raw_events(id)
        )''')

        # 4. Deduplication & Idempotency Cache
        c.execute('''CREATE TABLE IF NOT EXISTS deduplication_cache (
            dedup_key TEXT PRIMARY KEY,
            event_id TEXT,
            source_id TEXT,
            first_seen DATETIME,
            expires_at DATETIME
        )''')

        # 5. Security & Administrative Audit Logs
        c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp DATETIME,
            user TEXT,
            role TEXT,
            action TEXT,
            resource TEXT,
            result TEXT,
            source_ip TEXT,
            details TEXT
        )''')

        # Create indexes for high-speed SIEM querying and deduplication
        c.execute('CREATE INDEX IF NOT EXISTS idx_norm_source ON normalized_events(source_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_norm_outcome ON normalized_events(event_outcome)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_norm_processed ON normalized_events(processed_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_raw_hash ON raw_events(raw_hash)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_dedup_expires ON deduplication_cache(expires_at)')
        # Migrations for existing DB instances
        for table, col in [
            ("raw_events", "size_bytes INTEGER"),
            ("normalized_events", "raw_event_id TEXT"),
            ("normalized_events", "parser_version TEXT"),
            ("normalized_events", "mapping_version TEXT"),
            ("normalized_events", "schema_version TEXT"),
            ("normalized_events", "is_duplicate INTEGER DEFAULT 0"),
            ("normalized_events", "dedup_key TEXT"),
            ("normalized_events", "field_completeness REAL"),
            ("normalized_events", "schema_valid INTEGER DEFAULT 1")
        ]:
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass

        conn.commit()

    # ==========================================
    # RAW EVENT PRESERVATION (FIRST-CLASS PIPELINE STEP)
    # ==========================================
    def save_raw_event(self, event_id: str, raw_log: str, raw_hash: str, source_id: str, source_ip: str, received_at: Optional[str] = None) -> str:
        """Persist raw event immediately before parsing begins."""
        if not received_at:
            received_at = datetime.now(timezone.utc).isoformat()
        size_bytes = len(raw_log.encode('utf-8'))
        
        conn = self.get_conn()
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO raw_events 
                     (id, received_at, source_id, source_ip, raw_log, raw_hash, size_bytes)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (event_id, received_at, source_id, source_ip, raw_log, raw_hash, size_bytes))
        conn.commit()
        return event_id

    def get_raw_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM raw_events WHERE id = ?", (event_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def verify_event_integrity(self, event_id: str) -> Dict[str, Any]:
        """Cryptographically verify that stored raw event exactly matches recorded SHA-256 hash."""
        raw_row = self.get_raw_event(event_id)
        if not raw_row:
            conn = self.get_conn()
            c = conn.cursor()
            c.execute("SELECT raw_event_id FROM normalized_events WHERE id = ?", (event_id,))
            n_row = c.fetchone()
            if n_row and n_row['raw_event_id']:
                raw_row = self.get_raw_event(n_row['raw_event_id'])

        if not raw_row:
            return {"verified": False, "error": "Event not found in raw event store"}
        
        raw_text = raw_row.get('raw_log', '')
        stored_hash = raw_row.get('raw_hash', '')
        computed_hash = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()
        
        is_valid = (stored_hash == computed_hash)
        return {
            "event_id": event_id,
            "verified": is_valid,
            "status": "VERIFIED" if is_valid else "TAMPERED",
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "algorithm": "SHA-256",
            "byte_size": len(raw_text.encode('utf-8')),
            "verification_timestamp": datetime.now(timezone.utc).isoformat()
        }

    # ==========================================
    # DEDUPLICATION & IDEMPOTENCY
    # ==========================================
    def check_and_record_dedup(self, source_id: str, raw_hash: str, window_seconds: int = 30) -> Tuple[bool, str]:
        """
        Check if an identical event from the same source was received within window_seconds.
        Returns: (is_duplicate: bool, dedup_key: str)
        """
        dedup_key = hashlib.sha256(f"{source_id}:{raw_hash}".encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=window_seconds)

        conn = self.get_conn()
        c = conn.cursor()
        
        # Check active entry
        c.execute("SELECT first_seen, expires_at FROM deduplication_cache WHERE dedup_key = ?", (dedup_key,))
        row = c.fetchone()
        
        if row:
            exp = datetime.fromisoformat(row['expires_at'])
            if exp > now:
                return True, dedup_key
        
        # Insert or refresh window
        c.execute('''INSERT OR REPLACE INTO deduplication_cache 
                     (dedup_key, event_id, source_id, first_seen, expires_at)
                     VALUES (?, ?, ?, ?, ?)''',
                  (dedup_key, "", source_id, now.isoformat(), expires_at.isoformat()))
        conn.commit()
        return False, dedup_key

    # ==========================================
    # NORMALIZED EVENTS PERSISTENCE
    # ==========================================
    def store_event(self, ues_dict: dict, is_duplicate: bool = False, dedup_key: str = ""):
        ulpf = ues_dict.get('ulpf', {})
        evt = ues_dict.get('event', {})
        src = ues_dict.get('source', {})
        dst = ues_dict.get('destination', {})
        net = ues_dict.get('network', {})
        host = ues_dict.get('host', {})
        user = ues_dict.get('user', {})
        parser_meta = ues_dict.get('parser', {})
        lineage = ues_dict.get('lineage', {})
        quality = ues_dict.get('quality', {})
        
        event_id = ulpf.get('id')
        raw_event_id = lineage.get('raw_event_id', event_id)
        
        conn = self.get_conn()
        c = conn.cursor()

        c.execute('''INSERT OR REPLACE INTO normalized_events (
            id, raw_event_id, processed_at, source_id, parser_plugin, parser_version,
            mapping_version, schema_version, confidence, event_action, event_outcome,
            event_severity, src_ip, dst_ip, src_port, dst_port, protocol, host_name,
            user_name, is_duplicate, dedup_key, field_completeness, schema_valid,
            tags, full_event
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            event_id,
            raw_event_id,
            ulpf.get('ingest_timestamp', datetime.now(timezone.utc).isoformat()),
            ulpf.get('source_id', 'unknown'),
            parser_meta.get('name', ulpf.get('parser_plugin', 'unknown')),
            parser_meta.get('version', '1.0.0'),
            lineage.get('mapping_version', '1.0'),
            ulpf.get('schema_version', '1.0'),
            ulpf.get('confidence', 0.0),
            evt.get('action'),
            evt.get('outcome', 'unknown'),
            evt.get('severity', 0),
            src.get('ip'),
            dst.get('ip'),
            src.get('port'),
            dst.get('port'),
            net.get('protocol'),
            host.get('name'),
            user.get('name'),
            1 if is_duplicate else 0,
            dedup_key,
            quality.get('field_completeness', 0.0),
            1 if quality.get('schema_valid', True) else 0,
            json.dumps(ues_dict.get('tags', [])),
            json.dumps(ues_dict)
        ))
        conn.commit()

    def query_events(self, filters: dict, limit: int = 50, offset: int = 0) -> List[Dict]:
        conn = self.get_conn()
        c = conn.cursor()
        
        query = "SELECT * FROM normalized_events WHERE 1=1"
        params = []
        
        for k, v in filters.items():
            if v is not None and v != "":
                if k == 'severity_min':
                    query += " AND event_severity >= ?"
                    params.append(v)
                elif k == 'severity_max':
                    query += " AND event_severity <= ?"
                    params.append(v)
                elif k == 'search':
                    query += " AND (full_event LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)"
                    params.extend([f"%{v}%", f"%{v}%", f"%{v}%"])
                elif k in ['source_id', 'src_ip', 'dst_ip', 'event_outcome', 'event_action', 'parser_plugin']:
                    query += f" AND {k} = ?"
                    params.append(v)
                elif k == 'is_duplicate':
                    query += " AND is_duplicate = ?"
                    params.append(1 if v else 0)
                    
        query += " ORDER BY processed_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, params)
        return [dict(row) for row in c.fetchall()]

    def get_event_by_id(self, event_id: str) -> Dict[str, Any]:
        conn = self.get_conn()
        c = conn.cursor()
        c.execute("SELECT full_event FROM normalized_events WHERE id = ?", (event_id,))
        row = c.fetchone()
        if row:
            return json.loads(row['full_event'])
        return {}

    # ==========================================
    # DEAD LETTER QUEUE (DLQ / QUARANTINE)
    # ==========================================
    def store_failed_event(
        self,
        event_id: str,
        raw_event_id: str,
        source_id: str,
        raw_log: str,
        raw_hash: str,
        failure_reason: str,
        parser_attempted: str = "generic_parser",
        processing_stage: str = "parsing",
        error_details: str = "",
        retry_count: int = 0
    ) -> str:
        conn = self.get_conn()
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        c.execute('''INSERT OR REPLACE INTO failed_events (
            id, raw_event_id, timestamp, source_id, raw_log, raw_hash,
            failure_reason, parser_attempted, processing_stage, error_details,
            retry_count, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            event_id, raw_event_id, now, source_id, raw_log, raw_hash,
            failure_reason, parser_attempted, processing_stage, error_details,
            retry_count, 'quarantined'
        ))
        conn.commit()
        return event_id

    def query_dlq(self, limit: int = 50, offset: int = 0, status: str = 'quarantined') -> List[Dict]:
        conn = self.get_conn()
        c = conn.cursor()
        query = "SELECT * FROM failed_events WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        c.execute(query, params)
        return [dict(row) for row in c.fetchall()]

    def get_failed_event(self, dlq_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM failed_events WHERE id = ?", (dlq_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def update_failed_event_status(self, dlq_id: str, status: str, retry_count: Optional[int] = None):
        conn = self.get_conn()
        c = conn.cursor()
        if retry_count is not None:
            c.execute("UPDATE failed_events SET status = ?, retry_count = ? WHERE id = ?", (status, retry_count, dlq_id))
        else:
            c.execute("UPDATE failed_events SET status = ? WHERE id = ?", (status, dlq_id))
        conn.commit()

    # ==========================================
    # AUDIT LOGGING
    # ==========================================
    def log_audit(self, user: str, role: str, action: str, resource: str, result: str, source_ip: str = "127.0.0.1", details: str = ""):
        conn = self.get_conn()
        c = conn.cursor()
        import uuid
        audit_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        c.execute('''INSERT INTO audit_logs (id, timestamp, user, role, action, resource, result, source_ip, details)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (audit_id, now, user, role, action, resource, result, source_ip, details))
        conn.commit()

    def query_audit_logs(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        conn = self.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(row) for row in c.fetchall()]

    # ==========================================
    # METRICS & STATS FOR SYSTEM DASHBOARD
    # ==========================================
    def get_stats(self) -> Dict[str, Any]:
        conn = self.get_conn()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) as total FROM normalized_events")
        total_normalized = c.fetchone()['total']

        c.execute("SELECT COUNT(*) as total_raw FROM raw_events")
        total_raw = c.fetchone()['total_raw']

        c.execute("SELECT COUNT(*) as dlq_count FROM failed_events WHERE status = 'quarantined'")
        dlq_count = c.fetchone()['dlq_count']

        c.execute("SELECT COUNT(*) as dup_count FROM normalized_events WHERE is_duplicate = 1")
        dup_count = c.fetchone()['dup_count']

        c.execute("SELECT event_outcome, COUNT(*) as count FROM normalized_events GROUP BY event_outcome")
        outcomes = {row['event_outcome']: row['count'] for row in c.fetchall()}

        c.execute("SELECT parser_plugin, COUNT(*) as count FROM normalized_events GROUP BY parser_plugin")
        parsers = {row['parser_plugin']: row['count'] for row in c.fetchall()}

        c.execute("SELECT AVG(field_completeness) as avg_comp FROM normalized_events")
        avg_completeness = c.fetchone()['avg_comp'] or 0.0

        c.execute("SELECT SUM(schema_valid) as valid_count, COUNT(*) as total FROM normalized_events")
        schema_row = c.fetchone()
        schema_valid_rate = (schema_row['valid_count'] / schema_row['total']) if schema_row and schema_row['total'] > 0 else 1.0

        parse_success_rate = ((total_normalized - dlq_count) / max(total_raw, 1)) if total_raw > 0 else 1.0

        return {
            'total_events': total_normalized,
            'total_raw_events': total_raw,
            'dlq_quarantine_count': dlq_count,
            'duplicate_count': dup_count,
            'events_by_outcome': outcomes,
            'events_by_parser': parsers,
            'data_quality': {
                'parse_success_rate': round(max(0.0, min(1.0, parse_success_rate)), 4),
                'schema_validation_rate': round(schema_valid_rate, 4),
                'avg_field_completeness': round(avg_completeness, 4),
                'duplicate_rate': round((dup_count / max(total_normalized, 1)), 4),
                'failure_rate': round((dlq_count / max(total_raw, 1)), 4)
            }
        }

    def get_sources(self) -> List[Dict]:
        conn = self.get_conn()
        c = conn.cursor()
        c.execute('''SELECT source_id, COUNT(*) as count, MAX(processed_at) as last_seen,
                            SUM(CASE WHEN event_outcome = 'success' THEN 1 ELSE 0 END) as success_count,
                            SUM(CASE WHEN is_duplicate = 1 THEN 1 ELSE 0 END) as duplicate_count
                     FROM normalized_events GROUP BY source_id''')
        rows = c.fetchall()
        result = []
        for r in rows:
            cnt = r['count']
            suc = r['success_count']
            rate = round((suc / cnt), 2) if cnt > 0 else 1.0
            result.append({
                "source_id": r['source_id'],
                "count": cnt,
                "last_seen": r['last_seen'],
                "success_rate": rate,
                "duplicates": r['duplicate_count']
            })
        return result
