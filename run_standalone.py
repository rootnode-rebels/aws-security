"""
One-Click Standalone Runner for AWSSecurity AI.
Runs the complete cyber defense platform locally with ZERO AWS dependencies.
"""
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

import uvicorn

if __name__ == "__main__":
    dep_mode = os.getenv("DEPLOYMENT_MODE", "STANDALONE_LOCAL")
    os.environ["DEPLOYMENT_MODE"] = dep_mode
    
    host = os.getenv("HOST", "0.0.0.0" if dep_mode != "LOCAL_STRICT" else "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    default_reload = "false" if dep_mode in ("CONTAINER", "CLOUD", "PRODUCTION", "DOCKER") else "true"
    reload_opt = os.getenv("RELOAD", default_reload).lower() in ("true", "1", "yes")
    
    print("=" * 68)
    print("  [AWSSECURITY AI] STANDALONE CYBER DEFENSE PLATFORM")
    print("=" * 68)
    print(f"  [+] Mode:             {dep_mode}")
    print("  [+] Database:         Local Document Store / Standalone MongoDB")
    print("  [+] SIEM & Monitor:   Built-in Local Telemetry (Zero CloudWatch required)")
    print("  [+] ML Risk Engine:   Local Scikit-Learn & TensorFlow Neural Autoencoder")
    print("  [+] Alert Dispatch:   In-App Security Alert Inbox (Zero SNS required)")
    print(f"  [+] Access Portal:    http://{host}:{port} (Local: http://127.0.0.1:{port})")
    print("=" * 68)
    print("Starting server... Press Ctrl+C to stop.\n")

    uvicorn.run("backend.app:app", host=host, port=port, reload=reload_opt)
