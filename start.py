import os
import subprocess
import sys

port = os.environ.get("PORT", "5000")
print(f"Starting InvoiceSnap on port {port}")
subprocess.run([
    sys.executable, "-m", "gunicorn", "app:app",
    "--bind", f"0.0.0.0:{port}",
    "--timeout", "120"
])
