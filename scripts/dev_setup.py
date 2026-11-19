"""Create local test credentials and a localhost TLS certificate (never commit them)."""
import json
import os
from pathlib import Path
import secrets
import subprocess

p = Path('.local')
p.mkdir(mode=0o700, exist_ok=True)
(p / 'data').mkdir(mode=0o700, exist_ok=True)
if not (p / 'keys.json').exists():
    (p / 'keys.json').write_text(json.dumps({'demo-key': {'tenant': 'demo', 'secret': secrets.token_hex(32)}}))
    os.chmod(p / 'keys.json', 0o600)
if not (p / 'server.crt').exists():
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                    '-keyout', str(p / 'server.key'), '-out', str(p / 'server.crt'),
                    '-days', '7', '-subj', '/CN=localhost', '-addext',
                    'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
    os.chmod(p / 'server.key', 0o600)
print('Local configuration is ready. The client trusts only .local/server.crt.')
