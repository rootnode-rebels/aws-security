"""
Database Manager for Account Hijacking Detection System.
Supports MongoDB (via PyMongo) with transparent local document-store fallback for zero-dependency local execution.
"""
import os
import time
import json
import threading
from datetime import datetime, date, timezone, timedelta
from typing import Dict, Any, List, Optional

def _load_env():
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

_load_env()

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "db.json")
MONGODB_URI = os.getenv("MONGODB_URI", "")

class LocalCollection:
    """Thread-safe document collection with MongoDB-compatible query and mutation interface."""
    def __init__(self, name: str, parent_db: 'LocalDatabase'):
        self.name = name
        self.parent = parent_db

    def find_one(self, query: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        with self.parent.lock:
            docs = list(self.parent.get_collection_data(self.name))
        filter_query = query if query is not None else {}
        for doc in docs:
            if self._matches(doc, filter_query):
                return json.loads(json.dumps(doc))
        return None

    def find(self, query: Optional[Dict[str, Any]] = None, sort_key: Optional[str] = None, reverse: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        with self.parent.lock:
            docs = list(self.parent.get_collection_data(self.name))
        results = []
        for doc in docs:
            if query is None or self._matches(doc, query):
                results.append(json.loads(json.dumps(doc)))
        if sort_key:
            def _safe_sort(x):
                val = x.get(sort_key)
                if val is None:
                    return ""
                if isinstance(val, (int, float)):
                    return f"{val:020.6f}"
                return str(val)
            results.sort(key=_safe_sort, reverse=reverse)
        return results[:limit]

    def insert_one(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        with self.parent.lock:
            # DB-001: App-level duplicate prevention for users table in local fallback
            if self.name == "users" and "email" in doc:
                if self.find_one({"email": doc["email"]}):
                    raise Exception(f"E11000 duplicate key error collection: users index: email_1 dup key: {{ email: '{doc['email']}' }}")

            docs = self.parent.get_collection_data(self.name)
            doc_copy = json.loads(json.dumps(doc))
            if "_id" not in doc_copy:
                doc_copy["_id"] = f"{self.name}_{int(datetime.now(timezone.utc).timestamp() * 1000)}_{len(docs) + 1}"
            docs.append(doc_copy)
            self.parent.save()
            return {"inserted_id": doc_copy["_id"]}

    def _get_nested(self, doc: Dict[str, Any], key_path: str) -> Any:
        if "." not in key_path:
            return doc.get(key_path)
        parts = key_path.split(".")
        curr = doc
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return None
        return curr

    def _set_nested(self, doc: Dict[str, Any], key_path: str, value: Any):
        parts = key_path.split(".")
        curr = doc
        for p in parts[:-1]:
            if p not in curr or not isinstance(curr[p], dict):
                curr[p] = {}
            curr = curr[p]
        curr[parts[-1]] = value

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any]) -> bool:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            for i, doc in enumerate(docs):
                if self._matches(doc, query):
                    if "$set" in update:
                        for k, v in update["$set"].items():
                            if "." in k:
                                self._set_nested(doc, k, v)
                            else:
                                doc[k] = v
                    if "$push" in update:
                        for k, v in update["$push"].items():
                            if k not in doc or not isinstance(doc[k], list):
                                doc[k] = []
                            doc[k].append(v)
                    docs[i] = doc
                    self.parent.save()
                    return True
            return False

    def update_many(self, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            updated_count = 0
            for i, doc in enumerate(docs):
                if self._matches(doc, query):
                    if "$set" in update:
                        for k, v in update["$set"].items():
                            if "." in k:
                                self._set_nested(doc, k, v)
                            else:
                                doc[k] = v
                    if "$push" in update:
                        for k, v in update["$push"].items():
                            if k not in doc or not isinstance(doc[k], list):
                                doc[k] = []
                            doc[k].append(v)
                    docs[i] = doc
                    updated_count += 1
            if updated_count > 0:
                self.parent.save()
            return updated_count

    def delete_one(self, query: Dict[str, Any]) -> bool:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            for i, doc in enumerate(docs):
                if self._matches(doc, query):
                    docs.pop(i)
                    self.parent.save()
                    return True
            return False

    def delete_many(self, query: Dict[str, Any]) -> int:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            initial_count = len(docs)
            remaining = [doc for doc in docs if not self._matches(doc, query)]
            self.parent.set_collection_data(self.name, remaining)
            deleted_count = initial_count - len(remaining)
            if deleted_count > 0:
                self.parent.save()
            return deleted_count

    def count_documents(self, query: Optional[Dict[str, Any]] = None) -> int:
        with self.parent.lock:
            docs = list(self.parent.get_collection_data(self.name))
        if not query:
            return len(docs)
        return sum(1 for doc in docs if self._matches(doc, query))

    def _matches(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for key, val in query.items():
            if key == "$or":
                if not any(self._matches(doc, subq) for subq in val):
                    return False
                continue
            if key == "$and":
                if not all(self._matches(doc, subq) for subq in val):
                    return False
                continue
            doc_val = self._get_nested(doc, key)
            if isinstance(val, dict):
                for op, op_val in val.items():
                    if op == "$ne" and doc_val == op_val:
                        return False
                    elif op == "$in" and doc_val not in op_val:
                        return False
                    elif op == "$nin" and doc_val in op_val:
                        return False
                    elif op == "$gt" and not (doc_val is not None and doc_val > op_val):
                        return False
                    elif op == "$gte" and not (doc_val is not None and doc_val >= op_val):
                        return False
                    elif op == "$lt" and not (doc_val is not None and doc_val < op_val):
                        return False
                    elif op == "$lte" and not (doc_val is not None and doc_val <= op_val):
                        return False
                    elif op == "$exists":
                        if (key in doc) != bool(op_val):
                            return False
            elif doc_val != val:
                return False
        return True


class LocalDatabase:
    """Thread-safe persistent JSON document store mirroring MongoDB with atomic crash-safe writes."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.lock = threading.RLock()
        self.data: Dict[str, List[Dict[str, Any]]] = {
            "users": [],
            "active_sessions": [],
            "security_events": [],
            "password_resets": [],
            "cloudwatch_logs": [],
            "admin_requests": []
        }
        self._load()

    def _prune_ttl_records(self):
        """Prunes stale telemetry and expired sessions to prevent unbounded growth in db.json (ISSUE-14)."""
        now = datetime.now(timezone.utc)
        cutoff_7d = (now - timedelta(days=7)).isoformat()
        cutoff_30d = (now - timedelta(days=30)).isoformat()
        now_iso = now.isoformat()

        def _safe_ts(rec):
            if not isinstance(rec, dict):
                return ""
            ts = rec.get("timestamp") or rec.get("created_at") or ""
            if isinstance(ts, (int, float)):
                try:
                    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                except Exception:
                    return ""
            return str(ts)

        cw_logs = self.data.get("cloudwatch_logs", [])
        if cw_logs:
            self.data["cloudwatch_logs"] = [
                log for log in cw_logs
                if _safe_ts(log) >= cutoff_7d
            ]
        sec_events = self.data.get("security_events", [])
        if sec_events:
            self.data["security_events"] = [
                ev for ev in sec_events
                if _safe_ts(ev) >= cutoff_30d
            ]
        # Prune expired sessions so inactive clients don't accumulate indefinitely
        sessions = self.data.get("active_sessions", [])
        if sessions:
            self.data["active_sessions"] = [
                s for s in sessions
                if not (isinstance(s, dict) and s.get("expires_at") and str(s.get("expires_at")) < now_iso)
            ]

    def _check_external_reload(self):
        """Detects if db.json was modified externally (e.g. via reset_db.py) and reloads dynamically."""
        try:
            if os.path.exists(self.filepath):
                mtime = os.path.getmtime(self.filepath)
                if getattr(self, "_last_mtime", 0) != mtime:
                    self._load()
        except Exception:
            pass

    def reset(self, clear_sessions: bool = True) -> Dict[str, Any]:
        """Atomically resets local session and event caches, clears all lockouts, and syncs state."""
        with self.lock:
            self._load()
            initial_sessions = len(self.data.get("active_sessions", []))
            if clear_sessions:
                self.data["active_sessions"] = []
            else:
                self._prune_ttl_records()

            # Restore any locked/frozen accounts to ACTIVE and clear orphaned MFA challenges
            for u in self.data.get("users", []):
                if isinstance(u, dict):
                    if u.get("status") == "LOCKED":
                        u["status"] = "ACTIVE"
                    u["mfa_pending"] = None
                    if "account_is_frozen" in u:
                        u["account_is_frozen"] = False

            self.data["security_alerts"] = []
            self.data["password_resets"] = []
            pruned_sessions = initial_sessions - len(self.data.get("active_sessions", []))
            self.save()
            return {
                "initial_sessions": initial_sessions,
                "pruned_sessions": pruned_sessions,
                "remaining_sessions": len(self.data.get("active_sessions", [])),
                "total_users": len(self.data.get("users", [])),
                "total_events": len(self.data.get("security_events", []))
            }

    def _load(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                self._last_mtime = os.path.getmtime(self.filepath)
                self._prune_ttl_records()
            except Exception:
                self.save()
        else:
            self.save()

    def save(self):
        """Atomic crash-safe persistence: writes to temp file then atomic rename/replace."""
        self._prune_ttl_records()
        tmp_file = f"{self.filepath}.tmp_{threading.get_ident()}"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp_file, self.filepath)
            self._last_mtime = os.path.getmtime(self.filepath)
        except Exception as e:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except Exception:
                    pass
            raise e

    def get_collection_data(self, name: str) -> List[Dict[str, Any]]:
        self._check_external_reload()
        if name not in self.data:
            self.data[name] = []
        return self.data[name]

    def set_collection_data(self, name: str, items: List[Dict[str, Any]]):
        self.data[name] = items

    def get_collection(self, name: str) -> LocalCollection:
        return LocalCollection(name, self)


def _sanitize_mongo_value(val: Any) -> Any:
    """Recursively converts BSON ObjectId, datetime, and nested structures to JSON-serializable types."""
    if val is None:
        return None
    type_name = type(val).__name__
    if "ObjectId" in type_name or type_name in ("Decimal128", "Binary", "DBRef"):
        return str(val)
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    if isinstance(val, dict):
        return {str(k): _sanitize_mongo_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [_sanitize_mongo_value(v) for v in val]
    return val


def _normalize_filter(filter_query):
    if not isinstance(filter_query, dict):
        return filter_query if filter_query is not None else {}
    query_copy = dict(filter_query)
    if "_id" in query_copy:
        val = query_copy["_id"]
        if isinstance(val, str) and len(val) == 24:
            try:
                from bson import ObjectId
                if ObjectId.is_valid(val):
                    query_copy["_id"] = {"$in": [val, ObjectId(val)]}
            except Exception:
                pass
    return query_copy


class MongoCollectionWrapper:
    """Wrapper around raw PyMongo collection to support sort_key, reverse, limit, and auto-retry on reconnect."""
    def __init__(self, raw_collection, name: str = "", manager: Optional['DatabaseManager'] = None):
        self._col = raw_collection
        self._name = name
        self._mgr = manager

    def _execute_with_retry(self, fn, *args, **kwargs):
        try:
            return fn(self._col, *args, **kwargs)
        except Exception as e:
            # Check if socket dropped or network timeout occurred
            err_str = str(e).lower()
            if any(k in err_str for k in ("connection", "socket", "timeout", "autoreconnect", "network")):
                if self._mgr and self._mgr.reconnect() and self._mgr.db is not None and self._name:
                    try:
                        self._col = self._mgr.db[self._name]
                        return fn(self._col, *args, **kwargs)
                    except Exception as retry_err:
                        print(f"[DB] Mongo retry failed for {self._name}: {retry_err}")
            print(f"[DB] Mongo error in {self._name}: {e}")
            raise e

    def find_one(self, query=None, *args, **kwargs):
        filter_query = _normalize_filter(query)
        def _op(col):
            doc = col.find_one(filter_query, *args, **kwargs)
            return _sanitize_mongo_value(dict(doc)) if doc is not None else None
        try:
            return self._execute_with_retry(_op)
        except Exception as e:
            print(f"[DB] Mongo find_one error: {e}")
            return None

    def find(self, query=None, *args, **kwargs):
        sort_key = kwargs.pop("sort_key", None)
        reverse = kwargs.pop("reverse", False)
        limit = kwargs.pop("limit", None)
        filter_query = _normalize_filter(query)

        def _op(col):
            cursor = col.find(filter_query, *args, **kwargs)
            if sort_key:
                direction = -1 if reverse else 1
                cursor = cursor.sort([(sort_key, direction)])
            if limit:
                cursor = cursor.limit(limit)
            return [_sanitize_mongo_value(dict(doc)) for doc in cursor if isinstance(doc, dict)]

        try:
            return self._execute_with_retry(_op)
        except Exception as e:
            print(f"[DB] Mongo find error: {e}")
            return []

    def count_documents(self, query=None, *args, **kwargs) -> int:
        filter_query = _normalize_filter(query)
        try:
            return int(self._execute_with_retry(lambda col: col.count_documents(filter_query, *args, **kwargs)))
        except Exception as e:
            print(f"[DB] Mongo count_documents error: {e}")
            return 0

    def delete_many(self, query=None, *args, **kwargs) -> int:
        filter_query = _normalize_filter(query)
        try:
            res = self._execute_with_retry(lambda col: col.delete_many(filter_query, *args, **kwargs))
            return int(getattr(res, "deleted_count", 0))
        except Exception as e:
            print(f"[DB] Mongo delete_many error: {e}")
            return 0

    def delete_one(self, query=None, *args, **kwargs) -> bool:
        filter_query = _normalize_filter(query)
        try:
            res = self._execute_with_retry(lambda col: col.delete_one(filter_query, *args, **kwargs))
            return bool(getattr(res, "deleted_count", 0) > 0)
        except Exception as e:
            print(f"[DB] Mongo delete_one error: {e}")
            return False

    def update_many(self, query=None, update=None, *args, **kwargs) -> int:
        filter_query = _normalize_filter(query)
        update_spec = update if update is not None else {}
        try:
            res = self._execute_with_retry(lambda col: col.update_many(filter_query, update_spec, *args, **kwargs))
            return int(getattr(res, "modified_count", 0))
        except Exception as e:
            print(f"[DB] Mongo update_many error: {e}")
            return 0

    def update_one(self, query=None, update=None, *args, **kwargs) -> bool:
        filter_query = _normalize_filter(query)
        update_spec = update if update is not None else {}
        try:
            res = self._execute_with_retry(lambda col: col.update_one(filter_query, update_spec, *args, **kwargs))
            return bool(getattr(res, "modified_count", 0) > 0 or getattr(res, "matched_count", 0) > 0)
        except Exception as e:
            print(f"[DB] Mongo update_one error: {e}")
            return False

    def insert_one(self, doc, *args, **kwargs):
        try:
            return self._execute_with_retry(lambda col: col.insert_one(doc, *args, **kwargs))
        except Exception:
            return None

    def insert_many(self, docs, *args, **kwargs):
        try:
            return self._execute_with_retry(lambda col: col.insert_many(docs, *args, **kwargs))
        except Exception:
            return None

    def __getattr__(self, name):
        return getattr(self._col, name)


# Singleton local database instance
_local_db = LocalDatabase(DB_FILE)

class DatabaseManager:
    """Provides access to MongoDB collections with transparent fallback, auto-reconnect, and health monitoring."""
    def __init__(self):
        self.client = None
        self.db = None
        self.use_mongo = False
        self._connect_mongo()

    def _connect_mongo(self) -> bool:
        """Connects to live MongoDB with connection pooling to prevent idle socket timeouts."""
        if not MONGODB_URI:
            self.use_mongo = False
            return False

        try:
            from pymongo import MongoClient
            # Recycles connections every 45s to avoid NAT/firewall idle socket drops
            self.client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=3000,
                connectTimeoutMS=5000,
                socketTimeoutMS=10000,
                maxIdleTimeMS=45000,
                retryWrites=True,
                retryReads=True
            )
            # Verify connection with ping
            self.client.admin.command('ping')
            try:
                self.db = self.client.get_default_database()
            except Exception:
                self.db = self.client.get_database("account_security_db")
            self.use_mongo = True
            print(f"[DB] Connected successfully to live MongoDB instance (DB: {self.db.name}).")
            self._init_mongo_indexes()
            return True
        except Exception as e:
            is_prod = os.getenv("DEPLOYMENT_MODE", "").upper() == "AWS_ECS_PROD"
            if is_prod:
                print(f"[CRITICAL DB ERROR] Could not connect to MongoDB in PRODUCTION: {e}")
                raise RuntimeError("FATAL: MongoDB connection failed in Production. Refusing to fall back to local db.json.")
            else:
                print(f"[DB] Could not connect to MongoDB ({e}). Falling back to local document store.")
                self.use_mongo = False
                return False

    def reconnect(self) -> bool:
        """Pings connection; if unresponsive, recycles MongoClient and restores connection."""
        if not MONGODB_URI:
            return False
        try:
            if self.client:
                self.client.admin.command('ping')
                return True
        except Exception:
            pass
        print("[DB] Reconnecting to MongoDB after idle disconnect...")
        return self._connect_mongo()

    def _init_mongo_indexes(self):
        """Creates required MongoDB indexes (Unique and TTL) safely."""
        try:
            import pymongo
            self.db.users.create_index("email", unique=True)
            self.db.cloudwatch_logs.create_index("created_at", expireAfterSeconds=7*24*3600)
            self.db.security_events.create_index("created_at", expireAfterSeconds=30*24*3600)
            self.db.password_resets.create_index("created_at", expireAfterSeconds=3600)
            print("[DB] MongoDB indexes (Unique & TTL) initialized.")
        except Exception as e:
            print(f"[DB] Warning: Could not initialize MongoDB indexes: {e}")

    def health_check(self) -> Dict[str, Any]:
        """Validates live database connection, measures ping latency, and returns summary stats."""
        start = time.time()
        is_healthy = False
        backend = "Embedded Local Document Store"

        if self.use_mongo and self.client:
            try:
                self.client.admin.command('ping')
                is_healthy = True
                backend = f"MongoDB Live Cluster ({self.db.name if self.db else 'Connected'})"
            except Exception:
                reconnected = self.reconnect()
                is_healthy = reconnected
                backend = f"MongoDB Live Cluster (Reconnected: {reconnected})"
        else:
            try:
                with _local_db.lock:
                    _local_db._prune_ttl_records()
                is_healthy = True
                backend = "Embedded Local Document Store (db.json)"
            except Exception as e:
                is_healthy = False
                backend = f"Embedded Local Document Store (Error: {e})"

        latency_ms = round((time.time() - start) * 1000.0, 2)
        users_count = self.users.count_documents({})
        sessions_count = self.active_sessions.count_documents({})

        return {
            "status": "HEALTHY" if is_healthy else "UNHEALTHY",
            "is_connected": is_healthy,
            "database_backend": backend,
            "latency_ms": latency_ms,
            "total_users": users_count,
            "active_sessions": sessions_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def reset_database(self, clear_sessions: bool = True, preserve_email: Optional[str] = None) -> Dict[str, Any]:
        """
        Refreshes DB connection link, prunes expired sessions, resets orphaned device lockouts,
        and returns updated connection diagnostics.
        """
        # 1. Reconnect & verify connection
        if self.use_mongo:
            self.reconnect()

        # 2. Prune or reset sessions
        pruned_count = 0
        if clear_sessions:
            query = {}
            if preserve_email:
                query["user_email"] = {"$ne": preserve_email}
            pruned_count = self.active_sessions.delete_many(query)
        else:
            now_iso = datetime.now(timezone.utc).isoformat()
            pruned_count = self.active_sessions.delete_many({"expires_at": {"$lt": now_iso}})

        # 3. If local DB, trigger deep prune & save
        if not self.use_mongo:
            _local_db.reset(clear_sessions=clear_sessions)

        # 4. Clean up orphaned MFA pending states and restore locked accounts to ACTIVE
        self.users.update_many(
            {},
            {"$set": {"mfa_pending": None, "status": "ACTIVE", "account_is_frozen": False}}
        )

        # 5. Clear transient lockout security alerts
        try:
            self.security_alerts.delete_many({"type": {"$in": ["BRUTE_FORCE_LOCKOUT", "EMERGENCY_LOCKOUT", "ACCOUNT_LOCKED"]}})
        except Exception:
            pass

        # 6. Return health check
        health = self.health_check()
        health["pruned_sessions"] = pruned_count
        return health

    def get_collection(self, collection_name: str):
        if self.use_mongo and self.db is not None:
            return MongoCollectionWrapper(self.db[collection_name], name=collection_name, manager=self)
        return _local_db.get_collection(collection_name)

    @property
    def users(self):
        return self.get_collection("users")

    @property
    def active_sessions(self):
        return self.get_collection("active_sessions")

    @property
    def security_events(self):
        return self.get_collection("security_events")

    @property
    def password_resets(self):
        return self.get_collection("password_resets")

    @property
    def cloudwatch_logs(self):
        return self.get_collection("cloudwatch_logs")

    @property
    def security_alerts(self):
        return self.get_collection("security_alerts")

    @property
    def admin_requests(self):
        return self.get_collection("admin_requests")

db = DatabaseManager()
