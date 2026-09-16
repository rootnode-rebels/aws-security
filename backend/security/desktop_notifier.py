"""
Desktop Notification Dispatcher for AWSSecurity.
Sends native OS Desktop notifications (Windows Action Center / Toast)
in a non-blocking background thread when a secondary device attempts sign-in.
"""
import os
import sys
import threading
import subprocess
import logging

logger = logging.getLogger("AWSSecurity.Notifier")

PS_SCRIPT = """
param(
    [string]$Title = "AWSSecurity Alert",
    [string]$Message = "Secondary device requesting access"
)
try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $xml = [xml]$template.GetXml()
    $texts = $xml.GetElementsByTagName('text')
    $texts[0].AppendChild($xml.CreateTextNode($Title)) | Out-Null
    $texts[1].AppendChild($xml.CreateTextNode($Message)) | Out-Null
    $toastXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $toastXml.LoadXml($xml.OuterXml)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($toastXml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AWSSecurity").Show($toast)
} catch {
    # Fail silently if notifications are disabled in Windows settings
}
"""

_script_path = os.path.join(os.path.dirname(__file__), "toast_notifier.ps1")
try:
    with open(_script_path, "w", encoding="utf-8") as f:
        f.write(PS_SCRIPT)
except Exception as e:
    logger.warning(f"Could not write toast_notifier.ps1: {e}")

def _dispatch_worker(title: str, message: str):
    if sys.platform != "win32":
        return

    try:
        # Use python-subprocess to trigger PowerShell toast in background
        if os.path.exists(_script_path):
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", _script_path, "-Title", title, "-Message", message],
                capture_output=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
    except Exception as ex:
        logger.debug(f"Failed to dispatch Windows toast: {ex}")

def send_desktop_notification(title: str, message: str):
    """
    Asynchronously fires a real native Windows Desktop Toast notification.
    Safe and non-blocking.
    """
    t = threading.Thread(target=_dispatch_worker, args=(title, message), daemon=True)
    t.start()
