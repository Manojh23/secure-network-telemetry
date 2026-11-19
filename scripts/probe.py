"""Probe an explicitly configured endpoint and send authenticated telemetry.

No shell execution, scanning, dynamic URLs from the API, or disabled TLS validation.
Uses the Python standard library only.
"""
import argparse
import hashlib
import hmac
import json
import socket
import ssl
import time
import urllib.request
import uuid
from pathlib import Path

def request(base, path, method, payload, key_id, credential, ca):
    body = b'' if payload is None else json.dumps(payload, separators=(',', ':')).encode()
    stamp, nonce = str(int(time.time())), uuid.uuid4().hex
    message = '\n'.join([key_id, method, path, stamp, nonce, hashlib.sha256(body).hexdigest()])
    signature = hmac.new(credential['secret'].encode(), message.encode(), hashlib.sha256).hexdigest()
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    req = urllib.request.Request(base + path, data=body if method == 'POST' else None, method=method,
          headers={'X-Key-ID': key_id, 'X-Timestamp': stamp, 'X-Nonce': nonce,
                   'X-Signature': signature, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, context=context, timeout=10) as response:
        return json.load(response)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', default='https://localhost:9443')
    p.add_argument('--ca', default='.local/server.crt')
    p.add_argument('--keys', default='.local/keys.json')
    p.add_argument('--key-id', default='demo-key')
    p.add_argument('--target', default='localhost')
    p.add_argument('--port', type=int, default=9443)
    p.add_argument('--protocol', choices=['tcp', 'tls'], default='tls')
    p.add_argument('--site', default='boston-demo')
    p.add_argument('--report-id', help='Reuse this ID to demonstrate a conflicting payload')
    args = p.parse_args()
    if not args.base.startswith('https://'):
        p.error('Gateway must use HTTPS')
    credential = json.loads(Path(args.keys).read_text())[args.key_id]
    start = time.monotonic()
    success, error = True, ''
    try:
        with socket.create_connection((args.target, args.port), timeout=3) as connection:
            if args.protocol == 'tls':
                ctx = ssl.create_default_context(cafile=args.ca)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                with ctx.wrap_socket(connection, server_hostname=args.target):
                    pass
    except (OSError, ssl.SSLError):
        success, error = False, 'connect_or_certificate_validation_failed'
    payload = {'id': args.report_id or uuid.uuid4().hex, 'site': args.site,
               'target': f'{args.target}:{args.port}', 'protocol': args.protocol,
               'observed_at': int(time.time()), 'success': success,
               'latency_ms': round((time.monotonic()-start)*1000, 3), 'error': error}
    print(json.dumps({'submitted': request(args.base, '/v1/reports', 'POST', payload,
                                         args.key_id, credential, args.ca),
                      'summary': request(args.base, '/v1/summary', 'GET', None,
                                         args.key_id, credential, args.ca)}, indent=2))

if __name__ == '__main__':
    main()
