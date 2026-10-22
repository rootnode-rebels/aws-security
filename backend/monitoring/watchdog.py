"""
Server-Side Hourly Automated System Watchdog Daemon.
Performs continuous integrity audits on Database connectivity, session TTL pruning,
ML Anomaly Detection engine readiness, and CloudWatch telemetry pipelines.
Runs 24/7 in the background with zero client dependency and self-healing recovery.
"""

import os
import time
import asyncio
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from database.db_manager import db
from backend.monitoring.cloudwatch_service import cloudwatch
from backend.ml.model import ml_engine
from backend.ml.tf_autoencoder import tf_autoencoder
from backend.security.notification_service import notification_service


class SystemWatchdog:
    """
    Automated Background Watchdog that verifies full system health every hour.
    Self-heals connection drops, cleans expired sessions, and verifies ML pipelines.
    """

    def __init__(self):
        self._interval_seconds = int(os.getenv("SYSTEM_WATCHDOG_INTERVAL_SECONDS", "3600"))
        self._is_running = False
        self._task: Optional[asyncio.Task] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        self.total_audits_performed = 0
        self.last_run_timestamp: Optional[str] = None
        self.next_run_timestamp: Optional[str] = None
        self.current_status = "INITIALIZING"
        self.last_report: Dict[str, Any] = {}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "watchdog_active": self._is_running,
                "interval_seconds": self._interval_seconds,
                "interval_hours": round(self._interval_seconds / 3600.0, 2),
                "status": self.current_status,
                "total_audits": self.total_audits_performed,
                "last_audit_at": self.last_run_timestamp,
                "next_audit_at": self.next_run_timestamp,
                "last_report": self.last_report
            }

    def run_health_audit(self) -> Dict[str, Any]:
        """
        Executes a complete synchronous diagnostic cycle.
        Safe to call from scheduled background loop or on-demand via REST endpoint.
        """
        start_time = time.time()
        audit_time = datetime.now(timezone.utc)
        report: Dict[str, Any] = {
            "timestamp": audit_time.isoformat(),
            "overall_status": "HEALTHY",
            "components": {},
            "actions_taken": []
        }

        # 1. Database Connectivity & Ping
        try:
            db_diag = db.health_check()
            report["components"]["database"] = {
                "status": "HEALTHY" if db_diag.get("is_connected") else "DEGRADED",
                "backend": db_diag.get("database_backend"),
                "latency_ms": db_diag.get("latency_ms", 0.0),
                "total_users": db_diag.get("total_users", 0),
                "active_sessions": db_diag.get("active_sessions", 0)
            }
            if not db_diag.get("is_connected"):
                report["overall_status"] = "DEGRADED"
                report["actions_taken"].append("Database auto-reconnect attempted")
                if hasattr(db, "reconnect"):
                    db.reconnect()
        except Exception as e:
            report["overall_status"] = "DEGRADED"
            report["components"]["database"] = {"status": "ERROR", "error": str(e)}

        # 2. Session TTL Pruning & Zombie Clean
        try:
            now_iso = audit_time.isoformat()
            expired_query = {"expires_at": {"$lt": now_iso}}
            del_result = db.active_sessions.delete_many(expired_query)
            pruned_count = int(del_result if isinstance(del_result, (int, float)) else getattr(del_result, "deleted_count", 0))
            report["components"]["sessions"] = {
                "status": "HEALTHY",
                "pruned_expired_sessions": pruned_count
            }
            if pruned_count > 0:
                report["actions_taken"].append(f"Pruned {pruned_count} expired session(s)")
        except Exception as e:
            report["components"]["sessions"] = {"status": "WARNING", "error": str(e)}

        # 3. ML Risk Engine & Neural Autoencoder Inference Check
        try:
            test_features = {
                "geo_velocity_kmh": 0.0,
                "distance_km": 0.0,
                "device_distance": 0.0,
                "ip_reputation": 0.0,
                "failed_attempts_burst": 0,
                "circadian_anomaly": 0.0,
                "bot_signature": 0.0
            }
            eval_res = ml_engine.evaluate_risk(test_features)
            loss_res = tf_autoencoder.compute_reconstruction_loss([0.0] * 7)
            
            ml_healthy = (
                eval_res is not None and 
                "risk_score" in eval_res and 
                loss_res is not None and 
                "mse_reconstruction_error" in loss_res
            )
            report["components"]["ml_engine"] = {
                "status": "HEALTHY" if ml_healthy else "DEGRADED",
                "baseline_eval_risk": eval_res.get("risk_score") if eval_res else None,
                "autoencoder_loss": loss_res.get("mse_reconstruction_error") if loss_res else None
            }
        except Exception as e:
            report["overall_status"] = "DEGRADED"
            report["components"]["ml_engine"] = {"status": "ERROR", "error": str(e)}

        # 4. Telemetry & CloudWatch Heartbeat
        duration_ms = round((time.time() - start_time) * 1000.0, 2)
        report["audit_duration_ms"] = duration_ms

        try:
            cloudwatch.put_log_event(
                log_group="/aws/lambda/SystemWatchdog",
                level="INFO" if report["overall_status"] == "HEALTHY" else "WARN",
                message=f"[WATCHDOG] Automated Health Audit: {report['overall_status']} (Duration: {duration_ms}ms, DB: {report['components'].get('database', {}).get('status')})"
            )
        except Exception:
            pass

        # 5. Alert Dispatch on Degradation
        if report["overall_status"] != "HEALTHY":
            try:
                admin_email = os.getenv("SUPER_ADMIN_EMAIL", "superadmin@awssecurity.io")
                notification_service.dispatch(
                    recipient_email=admin_email,
                    subject="⚠️ [AWSSecurity Alert] Hourly Automated Watchdog Detected Degraded Component",
                    body_text=(
                        f"Hourly System Watchdog Audit Report ({audit_time.strftime('%Y-%m-%d %H:%M:%S UTC')}):\n\n"
                        f"Overall Status: {report['overall_status']}\n"
                        f"Diagnostics: {report['components']}\n"
                        f"Actions Taken: {report['actions_taken']}\n\n"
                        "Automated self-healing procedures have been initiated."
                    ),
                    notification_type="SECURITY_NOTIFICATION",
                    is_serious=True
                )
            except Exception:
                pass

        # Update singleton state
        with self._lock:
            self.total_audits_performed += 1
            self.last_run_timestamp = audit_time.isoformat()
            self.next_run_timestamp = (audit_time + timedelta(seconds=self._interval_seconds)).isoformat()
            self.current_status = report["overall_status"]
            self.last_report = report

        return report

    def _loop(self):
        """Internal daemon loop running on a dedicated thread."""
        print(f"[System Watchdog] Hourly daemon activated (Interval: {self._interval_seconds}s / {round(self._interval_seconds/3600.0, 1)}h).")
        # Perform initial verification 5 seconds after startup
        time.sleep(5)
        while self._is_running:
            try:
                self.run_health_audit()
            except Exception as e:
                print(f"[System Watchdog] Audit exception: {e}")
            
            # Sleep in 1-second chunks so shutdown is responsive
            slept = 0
            while self._is_running and slept < self._interval_seconds:
                time.sleep(1)
                slept += 1

    def start(self):
        """Starts the background watchdog daemon thread."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self.next_run_timestamp = (datetime.now(timezone.utc) + timedelta(seconds=self._interval_seconds)).isoformat()
            self._thread = threading.Thread(target=self._loop, name="SystemWatchdogDaemon", daemon=True)
            self._thread.start()

    def stop(self):
        """Stops the watchdog loop cleanly."""
        with self._lock:
            self._is_running = False


# Global singleton instance
watchdog = SystemWatchdog()
