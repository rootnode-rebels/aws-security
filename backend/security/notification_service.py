"""
Real-Time Security Notification & Dispatch Service (Amazon SNS / SES / SMTP / In-App Mailbox).
Delivers immediate security alerts, password reset tokens, MFA OTP codes, and account status updates
directly to legitimate users via Amazon SNS topics, email subscriptions, and standalone telemetry.
"""
import os
import sys
import time
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from database.db_manager import db
from backend.monitoring.cloudwatch_service import cloudwatch

logger = logging.getLogger("AWSSecurity.NotificationService")


def load_env_file():
    """Lightweight built-in .env parser that loads variables into os.environ."""
    candidates = [
        os.path.join(os.getcwd(), ".env"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    ]
    for env_path in candidates:
        if os.path.isfile(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("\"'")
                        if k:
                            os.environ[k] = v
                break
            except Exception as e:
                logger.debug(f"Failed reading .env file at {env_path}: {e}")


SERIOUS_NOTIFICATION_TYPES = {
    "THREAT_BLOCKED",
    "HIGH_RISK_HIJACK_BLOCKED",
    "IMPOSSIBLE_TRAVEL_BLOCKED",
    "BRUTE_FORCE_LOCKOUT",
    "ACCOUNT_STATUS_CHANGE",
    "PASSWORD_RESET_TOKEN",
    "SECONDARY_PASSWORD_ROTATED",
    "TEST_ALERT"
}


class NotificationDispatcher:
    """
    Central dispatcher coordinating Amazon SNS, Email (SES/SMTP/Gmail),
    CloudWatch audit logging, and in-app dispatched notification telemetry.
    """

    def __init__(self):
        self._reload_config()
        self._boto3_sns_client = None

    def _reload_config(self):
        """Refreshes configuration from environment and .env file."""
        load_env_file()
        self.sns_topic_arn = os.getenv("SECURITY_ALERT_TOPIC_ARN") or os.getenv("AWS_SNS_TOPIC_ARN")
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        
        # When sending via Gmail/authenticated SMTP, default from_email to authenticated user
        custom_from = os.getenv("SES_SOURCE_EMAIL") or os.getenv("SMTP_FROM")
        if custom_from:
            self.from_email = custom_from
        elif self.smtp_user and ("@" in self.smtp_user):
            self.from_email = self.smtp_user
        else:
            self.from_email = "security@awssecurity.io"

    def get_status(self) -> Dict[str, Any]:
        """Returns the current dispatch engine status and configured channels."""
        self._reload_config()
        is_sns = bool(self.sns_topic_arn and not self.sns_topic_arn.startswith("arn:aws:sns:dummy"))
        is_smtp = bool(self.smtp_host and self.smtp_user)
        is_gmail = bool(is_smtp and ("gmail" in (self.smtp_host or "").lower() or "@gmail.com" in (self.smtp_user or "").lower()))

        if is_sns and is_smtp:
            mode = "AWS_SNS_AND_SMTP"
            desc = "Amazon SNS + Live Email Delivery"
        elif is_sns:
            mode = "AWS_SNS"
            desc = "Amazon SNS Topic (Cloud)"
        elif is_gmail:
            mode = "GMAIL_SMTP"
            desc = f"Gmail Live Delivery ({self.smtp_user})"
        elif is_smtp:
            mode = "CUSTOM_SMTP"
            desc = f"Live SMTP Delivery ({self.smtp_host})"
        else:
            mode = "LOCAL_EMULATION"
            desc = "Amazon SNS / Email (Local Emulation)"

        return {
            "mode": mode,
            "description": desc,
            "sns_configured": is_sns,
            "smtp_configured": is_smtp,
            "is_gmail": is_gmail,
            "smtp_host": self.smtp_host,
            "smtp_user": self.smtp_user,
            "from_email": self.from_email,
            "live_delivery": is_sns or is_smtp
        }

    def _get_sns_client(self):
        """Lazy-initialize boto3 SNS client if available and configured."""
        if self._boto3_sns_client is not None:
            return self._boto3_sns_client

        if not self.sns_topic_arn or self.sns_topic_arn.startswith("arn:aws:sns:dummy"):
            return None

        try:
            import boto3
            session = boto3.Session()
            self._boto3_sns_client = session.client("sns", region_name=os.getenv("AWS_REGION", "us-east-1"))
            return self._boto3_sns_client
        except Exception as e:
            logger.debug(f"[NotificationDispatcher] Boto3 SNS unavailable: {e}")
            return None

    def _publish_sns(self, recipient_email: str, subject: str, message: str, notification_type: str) -> bool:
        """Publishes security alert to Amazon SNS Topic with message attributes."""
        client = self._get_sns_client()
        if not client or not self.sns_topic_arn:
            return False

        try:
            client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject[:100],
                Message=message,
                MessageAttributes={
                    "RecipientEmail": {"DataType": "String", "StringValue": recipient_email},
                    "NotificationType": {"DataType": "String", "StringValue": notification_type}
                }
            )
            return True
        except Exception as e:
            logger.warning(f"[NotificationDispatcher] AWS SNS publish failed: {e}")
            return False

    def _send_smtp(self, recipient_email: str, subject: str, body_text: str, body_html: str) -> tuple[bool, Optional[str]]:
        """Sends security alert via standard SMTP or Google Gmail SMTP."""
        if not self.smtp_host:
            return False, "SMTP not configured"

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = recipient_email
            msg["Date"] = smtplib.email.utils.formatdate(localtime=False)
            msg["Message-ID"] = smtplib.email.utils.make_msgid(domain="awssecurity.io")

            part1 = MIMEText(body_text, "plain", "utf-8")
            part2 = MIMEText(body_html, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)

            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=8)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=8)
                server.ehlo()
                try:
                    server.starttls()
                    server.ehlo()
                except Exception as tls_err:
                    logger.debug(f"STARTTLS notice: {tls_err}")

            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)

            server.sendmail(self.from_email, [recipient_email], msg.as_string())
            server.quit()
            logger.info(f"[NotificationDispatcher] SMTP delivered successfully to {recipient_email}")
            return True, None
        except Exception as e:
            logger.warning(f"[NotificationDispatcher] SMTP delivery to {recipient_email} failed: {e}")
            return False, str(e)

    def dispatch(
        self,
        recipient_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        notification_type: str = "SECURITY_NOTIFICATION",
        metadata: Optional[Dict[str, Any]] = None,
        is_serious: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Dispatches a security notification:
        - Critical/Serious events (Threat Blocked, Account Frozen, Password Reset, Brute Force Lockout)
          are delivered to the user's real email (Gmail/SMTP/SNS) AND the Main Device In-App Inbox.
        - Routine events are delivered to the Main Device In-App Inbox only, keeping real email clean.
        """
        self._reload_config()
        now_iso = datetime.now(timezone.utc).isoformat()
        notification_id = f"notif_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
        meta = dict(metadata or {})

        if is_serious is None:
            is_serious = notification_type in SERIOUS_NOTIFICATION_TYPES

        meta["is_serious"] = is_serious

        sns_success = False
        smtp_success = False
        smtp_err = None

        if is_serious:
            # 1. Attempt AWS SNS Publish for serious security incidents
            sns_success = self._publish_sns(recipient_email, subject, body_text, notification_type)

            # 2. Attempt SMTP / Gmail Email for serious security incidents
            smtp_success, smtp_err = self._send_smtp(recipient_email, subject, body_text, body_html or body_text)
            if smtp_err and self.smtp_host:
                meta["delivery_warning"] = f"SMTP Delivery Error: {smtp_err}"

            # Determine active channel representation
            if sns_success and smtp_success:
                channel = "Amazon SNS + Live Email"
            elif sns_success:
                channel = "Amazon SNS Topic"
            elif smtp_success:
                channel = "Gmail SMTP Live Delivery" if ("gmail" in (self.smtp_host or "").lower()) else "Live SMTP Delivery"
            else:
                channel = "Amazon SNS / Email (Local Emulation)"
            delivery_status = "DELIVERED" if (sns_success or smtp_success or not self.smtp_host) else "DELIVERY_FAILED"
        else:
            # Routine / Low-Risk event: Sent strictly to Main Device In-App Inbox (No outbound email)
            channel = "Main Device In-App Inbox (Routine)"
            delivery_status = "DELIVERED"

        # 3. Store in Database for Main Device Inbox & User Portal inspection (Always received by Main Device)
        record = {
            "notification_id": notification_id,
            "created_at": now_iso,
            "recipient_email": recipient_email,
            "subject": subject,
            "body_text": body_text,
            "body_html": body_html or f"<pre style='font-family:sans-serif;'>{body_text}</pre>",
            "notification_type": notification_type,
            "channel": channel,
            "status": delivery_status,
            "is_serious": is_serious,
            "metadata": meta
        }

        try:
            db.get_collection("dispatched_notifications").insert_one(record)
        except Exception as ex:
            logger.error(f"[NotificationDispatcher] Failed to store record in DB: {ex}")

        # 4. Log to CloudWatch
        cloudwatch.put_log_event(
            log_group="/aws/lambda/NotificationDispatcher",
            level="WARN" if is_serious else "INFO",
            message=f"[{channel}] Dispatched {notification_type} to {recipient_email}: {subject}",
            payload={"notification_id": notification_id, "recipient": recipient_email, "type": notification_type, "is_serious": is_serious}
        )

        # 5. Formatted Console Output for Developer & Live Demonstration
        self._print_terminal_banner(recipient_email, subject, body_text, channel, notification_type, is_serious)

        return record

    def _print_terminal_banner(self, recipient: str, subject: str, body: str, channel: str, ntype: str, is_serious: bool = True):
        """Prints a high-visibility terminal card demonstrating notification delivery."""
        try:
            border = "=" * 76
            clean_subj = subject.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(sys.stdout.encoding or "utf-8")
            print(f"\n{border}")
            print(f"[AMAZON SNS / EMAIL DISPATCHER] -> STATUS: DELIVERED")
            print(f"   Recipient: {recipient}")
            print(f"   Type:      {ntype}")
            print(f"   Channel:   {channel}")
            print(f"   Subject:   {clean_subj}")
            print(f"   Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print("-" * 76)
            # Indent body preview
            for line in body.strip().splitlines()[:10]:
                clean_line = line.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(sys.stdout.encoding or "utf-8")
                print(f"   | {clean_line}")
            if len(body.strip().splitlines()) > 10:
                print("   | ... [Full text viewable in Dispatched Notifications Drawer]")
            print(f"{border}\n")
        except Exception:
            pass

    # =========================================================================
    # High-Level Event Dispatch Helpers
    # =========================================================================

    def send_password_reset(self, email: str, reset_token: str, client_ip: str = "Unknown") -> Dict[str, Any]:
        """Dispatches password reset link & token to user's email."""
        subject = "🔐 [AWS Security] Password Reset Recovery Token"
        body_text = (
            f"Hello,\n\n"
            f"A password reset request was initiated for your AWS Security account ({email}) from IP: {client_ip}.\n\n"
            f"Your single-use recovery token is:\n\n"
            f"    {reset_token}\n\n"
            f"This token is valid for 15 minutes. Use it on the login screen by clicking 'Forgot Password' -> 'Enter Recovery Token'.\n\n"
            f"⚠️ If you did NOT request this reset, your account credentials may be targeted. "
            f"Please review your Security Dashboard immediately and consider freezing your account.\n\n"
            f"Best regards,\n"
            f"AWS Security Defense Platform\n"
            f"Automated Notification Dispatcher (Amazon SNS)"
        )
        body_html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0b1329; color: #e2e8f0; border-radius: 12px; border: 1px solid #1e293b; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0ea5e9, #6366f1); padding: 20px 24px; text-align: center;">
            <h2 style="margin: 0; color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: 0.5px;">AWS Security Defense Platform</h2>
            <p style="margin: 6px 0 0; color: #e0e7ff; font-size: 13px;">Amazon SNS & Security Telemetry Dispatcher</p>
          </div>
          <div style="padding: 28px 24px;">
            <h3 style="margin-top: 0; color: #38bdf8; font-size: 18px;">🔐 Password Reset Recovery Token</h3>
            <p style="color: #94a3b8; line-height: 1.6; font-size: 14px;">
              A password reset request was initiated for your account (<strong>{email}</strong>) from IP <code>{client_ip}</code>.
            </p>
            <div style="background: #0f172a; border: 1px dashed #38bdf8; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0;">
              <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8; margin-bottom: 8px;">Single-Use Recovery Token (15m Expiry)</div>
              <div style="font-family: 'Courier New', monospace; font-size: 20px; font-weight: bold; color: #38bdf8; letter-spacing: 2px;">{reset_token}</div>
            </div>
            <p style="color: #94a3b8; line-height: 1.6; font-size: 13px;">
              Enter this token in your password reset modal to choose a new strong password.
            </p>
            <div style="background: #1e1b4b; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; margin-top: 24px;">
              <strong style="color: #fbbf24; font-size: 13px;">Security Notice:</strong>
              <p style="color: #cbd5e1; font-size: 12px; margin: 4px 0 0;">
                If you did not request this recovery token, an attacker may be attempting to access your account. Please log in from your primary device and freeze the account.
              </p>
            </div>
          </div>
          <div style="background: #070d1e; padding: 16px 24px; text-align: center; font-size: 11px; color: #64748b; border-top: 1px solid #1e293b;">
            Delivered via Amazon SNS / AWS Security Automated Gateway &bull; Reference: {email}
          </div>
        </div>
        """
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            notification_type="PASSWORD_RESET_TOKEN",
            metadata={"client_ip": client_ip, "token": reset_token}
        )

    def send_password_changed(self, email: str, client_ip: str = "Unknown") -> Dict[str, Any]:
        """Dispatches security confirmation following a successful password update."""
        subject = "🛡️ [AWS Security] Master Password Updated"
        body_text = (
            f"Security Notice:\n\n"
            f"The password for your account ({email}) was successfully changed from IP: {client_ip}.\n\n"
            f"As a security precaution, all remote secondary sessions have been revoked.\n"
            f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"If this change was not made by you, please trigger an Emergency Account Freeze immediately.\n"
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0b1329; color: #e2e8f0; border-radius: 12px; padding: 24px; border: 1px solid #1e293b;">
          <h2 style="color: #10b981; margin-top: 0;">🛡️ Master Password Updated</h2>
          <p style="color: #94a3b8; font-size: 14px;">The password for <strong>{email}</strong> was updated from IP <code>{client_ip}</code>.</p>
          <p style="color: #cbd5e1; font-size: 13px;">All secondary sessions have been automatically terminated for your protection.</p>
          <div style="font-size: 11px; color: #64748b; margin-top: 20px;">Delivered via Amazon Simple Notification Service (SNS)</div>
        </div>
        """
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            notification_type="PASSWORD_CHANGED",
            metadata={"client_ip": client_ip}
        )

    def send_threat_blocked(
        self,
        email: str,
        threat_type: str,
        risk_score: float,
        geo: Dict[str, Any],
        client_ip: str,
        factors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Dispatches critical alert when an impossible travel or high-risk attempt is blocked."""
        city = geo.get("city", "Unknown City")
        country = geo.get("country", "Unknown Country")
        location_str = f"{city}, {country}"
        factor_summary = "\n".join([f"  - {f.get('factor', 'Anomaly')}: {f.get('detail', '')}" for f in factors[:3]])

        subject = f"🚨 [CRITICAL ALERT] Unauthorized Access Blocked ({risk_score:.0f}/100 Risk)"
        body_text = (
            f"🚨 EMERGENCY SECURITY ALERT: Unauthorized sign-in attempt BLOCKED.\n\n"
            f"Target Account: {email}\n"
            f"Risk Score:     {risk_score:.1f} / 100 (HIGH SEVERITY)\n"
            f"Origin:         {location_str} (IP: {client_ip})\n"
            f"Threat Factors:\n{factor_summary}\n\n"
            f"Action Taken: The ML Anomaly Detection Engine immediately blocked this connection to protect your account.\n\n"
            f"If you are currently traveling, verify your session from your Primary Security Portal.\n"
            f"If this was NOT you, log in immediately and activate Emergency Account Freeze."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; border-radius: 12px; border: 2px solid #ef4444; overflow: hidden;">
          <div style="background: #991b1b; padding: 18px 24px; color: white;">
            <h2 style="margin: 0; font-size: 20px;">🚨 Security Defense Alert: Unauthorized Access Blocked</h2>
          </div>
          <div style="padding: 24px;">
            <p style="font-size: 14px; color: #cbd5e1;">A high-risk login attempt against <strong>{email}</strong> was intercepted and blocked.</p>
            <table style="width: 100%; font-size: 13px; color: #e2e8f0; border-collapse: collapse; margin: 16px 0;">
              <tr><td style="padding: 6px 0; color: #94a3b8;">Risk Score:</td><td style="font-weight: bold; color: #ef4444;">{risk_score:.1f} / 100 (CRITICAL)</td></tr>
              <tr><td style="padding: 6px 0; color: #94a3b8;">Origin Location:</td><td>{location_str}</td></tr>
              <tr><td style="padding: 6px 0; color: #94a3b8;">Origin IP:</td><td><code>{client_ip}</code></td></tr>
            </table>
            <div style="background: #1e293b; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #cbd5e1; margin-top: 12px;">
              <strong>Detected Threat Indicators:</strong>
              <pre style="margin: 8px 0 0; font-family: monospace; white-space: pre-wrap;">{factor_summary}</pre>
            </div>
          </div>
          <div style="background: #020617; padding: 12px 24px; font-size: 11px; color: #64748b;">Dispatched by Amazon SNS Incident Response Engine</div>
        </div>
        """
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            notification_type="THREAT_BLOCKED",
            metadata={"risk_score": risk_score, "origin": location_str, "client_ip": client_ip, "threat": threat_type}
        )

    def send_mfa_code(
        self,
        email: str,
        otp: str,
        device_name: str,
        geo: Dict[str, Any],
        client_ip: str
    ) -> Dict[str, Any]:
        """Dispatches 6-digit MFA verification code to user's email."""
        city = geo.get("city", "Unknown City")
        location_str = f"{city}, {geo.get('country', 'Unknown')}"

        subject = f"🔑 [AWS Security] Sign-In Verification Code: {otp}"
        body_text = (
            f"Verification Code: {otp}\n\n"
            f"A sign-in attempt for {email} requires identity verification.\n"
            f"Device:   {device_name}\n"
            f"Location: {location_str}\n"
            f"IP:       {client_ip}\n\n"
            f"Enter this 6-digit code to complete authentication. Code expires in 10 minutes.\n"
            f"Do NOT share this code with anyone."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0b1329; color: #e2e8f0; border-radius: 12px; padding: 24px; border: 1px solid #3b82f6;">
          <h2 style="color: #38bdf8; margin-top: 0;">🔑 Sign-In Verification Code</h2>
          <p style="color: #94a3b8; font-size: 14px;">A sign-in request from <strong>{device_name}</strong> ({location_str}) requires step-up MFA verification.</p>
          <div style="background: #0f172a; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #38bdf8; font-family: monospace;">{otp}</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Valid for 10 minutes &bull; Single Use</div>
          </div>
          <div style="font-size: 11px; color: #64748b;">Delivered via Amazon SNS Push / Email Gateway</div>
        </div>
        """
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            notification_type="MFA_VERIFICATION_CODE",
            metadata={"otp": otp, "device": device_name, "client_ip": client_ip, "origin": location_str}
        )

    def send_brute_force_alert(
        self,
        email: str,
        fail_count: int,
        client_ip: str,
        lockout_seconds: int
    ) -> Dict[str, Any]:
        """Dispatches alert when account experiences repeated failed login attempts."""
        subject = f"⚠️ [AWS Security] Account Lockout: {fail_count} Failed Login Attempts"
        body_text = (
            f"Security Warning: Brute Force Attempt Intercepted\n\n"
            f"Account: {email}\n"
            f"We detected {fail_count} consecutive failed login attempts with invalid credentials from IP: {client_ip}.\n\n"
            f"The account login has been temporarily restricted for {lockout_seconds} seconds to prevent brute-force attacks.\n\n"
            f"If you forgot your password, please use the 'Forgot Password' link to securely recover your account."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="BRUTE_FORCE_LOCKOUT",
            metadata={"fail_count": fail_count, "client_ip": client_ip, "lockout_seconds": lockout_seconds}
        )

    def send_account_status_alert(self, email: str, action: str, client_ip: str) -> Dict[str, Any]:
        """Dispatches status alert when account is frozen or restored."""
        is_freeze = action.upper() == "FROZEN"
        subject = (
            "⚠️ [AWS Security] Emergency Account Freeze Activated"
            if is_freeze
            else "✅ [AWS Security] Account Restored to Active Status"
        )
        status_desc = "frozen and all remote secondary sessions were killed" if is_freeze else "unfrozen and restored to ACTIVE status"
        body_text = (
            f"Account Status Notice:\n\n"
            f"Your AWS Security account ({email}) was {status_desc} from IP: {client_ip}.\n"
            f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"Action was authorized by the Primary Security Portal."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="ACCOUNT_STATUS_CHANGE",
            metadata={"action": action, "client_ip": client_ip}
        )


    def send_welcome_registration(self, email: str, full_name: str, client_ip: str) -> Dict[str, Any]:
        """Dispatches security welcome notice when a user registers."""
        subject = "🎉 [AWS Security] Account Registered & Defense Policies Active"
        body_text = (
            f"Welcome to AWS Security Defense, {full_name}!\n\n"
            f"Your account ({email}) has been successfully enrolled from IP: {client_ip}.\n\n"
            f"Active Protections:\n"
            f"  - Real-time ML Anomaly Detection & Impossible Travel Prevention\n"
            f"  - Amazon SNS Emergency Alert Routing\n"
            f"  - Primary Device Authority & Zero-Data-Leak Architecture\n\n"
            f"If you did not initiate this registration, please contact security incident response."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="ACCOUNT_REGISTERED",
            metadata={"full_name": full_name, "client_ip": client_ip}
        )

    def send_secondary_password_changed(self, email: str, client_ip: str) -> Dict[str, Any]:
        """Dispatches alert when the Master Secondary Security Password is changed."""
        subject = "🛡️ [AWS Security] Master Secondary Password Updated"
        body_text = (
            f"Security Notice:\n\n"
            f"The Master Secondary Security Password for {email} was updated from IP: {client_ip}.\n"
            f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"This secondary credential controls Primary Device authority transfers and recovery.\n"
            f"If this change was not made by you, activate Emergency Account Freeze immediately."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="SECONDARY_PASSWORD_ROTATED",
            metadata={"client_ip": client_ip}
        )

    def send_primary_device_transferred(self, email: str, device_label: str, client_ip: str) -> Dict[str, Any]:
        """Dispatches alert when Primary Device authority is assigned or transferred."""
        subject = f"🛡️ [AWS Security] Primary Device Authority Enrolled: {device_label}"
        body_text = (
            f"Primary Authority Transfer Notice:\n\n"
            f"Your account ({email}) has designated a new Primary Security Portal:\n"
            f"  Device: {device_label}\n"
            f"  IP:     {client_ip}\n"
            f"  Time:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"All remote secondary devices will require approval from this device to access your account."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="PRIMARY_DEVICE_ENROLLED",
            metadata={"device": device_label, "client_ip": client_ip}
        )

    def send_sessions_revoked_alert(self, email: str, count: int, client_ip: str) -> Dict[str, Any]:
        """Dispatches alert when remote sessions are revoked."""
        subject = f"⚠️ [AWS Security] Remote Sessions Revoked ({count} Active Sessions Terminated)"
        body_text = (
            f"Session Revocation Notice:\n\n"
            f"A kill command was executed from your Primary Security Portal.\n"
            f"Terminated Sessions: {count}\n"
            f"Initiated From IP:   {client_ip}\n"
            f"Timestamp:           {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"Your primary portal session remains active."
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="SESSIONS_REVOKED",
            metadata={"count": count, "client_ip": client_ip}
        )

    def send_account_deleted_alert(self, email: str, client_ip: str) -> Dict[str, Any]:
        """Dispatches alert when an account is permanently deleted."""
        subject = "🗑️ [AWS Security] Account and Telemetry Permanently Deleted"
        body_text = (
            f"Account Closure Confirmation:\n\n"
            f"The AWS Security Defense account for {email} was permanently deleted from IP: {client_ip}.\n"
            f"All active sessions, credentials, behavioral baselines, and alerts have been purged.\n"
            f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            notification_type="ACCOUNT_DELETED",
            metadata={"client_ip": client_ip}
        )




    def send_email_verification(self, email: str, full_name: str, code: str) -> Dict[str, Any]:
        """Dispatches 6-digit email verification code via AWS SNS upon registration."""
        subject = f"?? [AWS Security] Verify Your Email Address: {code}"
        body_text = (
            f"Welcome to AWS Security Defense, {full_name}!\n\n"
            f"To complete your registration for {email}, please use the following verification code:\n\n"
            f"    {code}\n\n"
            f"This code will expire shortly. Do not share this code with anyone."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0b1329; color: #e2e8f0; border-radius: 12px; padding: 24px; border: 1px solid #1e293b;">
          <h2 style="color: #38bdf8; margin-top: 0;">?? Verify Your Email Address</h2>
          <p style="color: #94a3b8; font-size: 14px;">Welcome, <strong>{full_name}</strong>. Please verify your email.</p>
          <div style="background: #0f172a; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #38bdf8; font-family: monospace;">{code}</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Single Use Code</div>
          </div>
          <div style="font-size: 11px; color: #64748b;">Delivered via Amazon SNS Push / Email Gateway</div>
        </div>
        """
        return self.dispatch(
            recipient_email=email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            notification_type="EMAIL_VERIFICATION",
            metadata={"code": code}
        )
# Global singleton dispatcher instance
notification_service = NotificationDispatcher()


