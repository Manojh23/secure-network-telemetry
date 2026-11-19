"""Exercise the compiled process over verified TLS, including a real restart."""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error

from probe import request

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', default='dist/gateway')
    args = p.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        cert, key = root/'server.crt', root/'server.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        credentials = {'alpha-key': {'tenant': 'alpha', 'secret': secrets.token_hex(32)},
                       'beta-key': {'tenant': 'beta', 'secret': secrets.token_hex(32)}}
        (root/'keys.json').write_text(json.dumps(credentials))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, LISTEN_ADDR=f'127.0.0.1:{port}', KEY_FILE=str(root/'keys.json'),
                   TLS_CERT=str(cert), TLS_KEY=str(key), DATA_FILE=str(root/'reports.jsonl'))
        base = f'https://localhost:{port}'
        def start(log):
            process = subprocess.Popen([binary], env=env, stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('gateway exited before startup')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        return process
                except OSError:
                    time.sleep(.05)
            process.terminate()
            raise TimeoutError('gateway startup timed out')
        def send(path, method='GET', payload=None, identity='alpha-key'):
            return request(base, path, method, payload, identity, credentials[identity], str(cert))
        report = {'id': 'restart-proof', 'site': 'boston', 'target': 'example.test:443',
                  'protocol': 'tls', 'observed_at': int(time.time()), 'success': True, 'latency_ms': 8}
        with (root/'server.log').open('w') as log:
            process = start(log)
            try:
                assert send('/v1/reports', 'POST', report)['created']
                assert not send('/v1/reports', 'POST', report)['created']
                assert send('/v1/summary', identity='beta-key') == []
                assert send('/v1/summary')[0]['samples'] == 1
                changed = dict(report, latency_ms=10)
                try:
                    send('/v1/reports', 'POST', changed)
                    raise AssertionError('conflicting write accepted')
                except urllib.error.HTTPError as error:
                    assert error.code == 409
            finally:
                process.terminate()
                assert process.wait(timeout=15) == 0
            process = start(log)
            try:
                assert send('/v1/summary')[0]['samples'] == 1
                assert not send('/v1/reports', 'POST', report)['created']
            finally:
                process.terminate()
                assert process.wait(timeout=15) == 0
        print('PASS: verified HTTPS, signed intake, duplicate/conflict checks, tenant isolation, graceful shutdown and durable restart')

if __name__ == '__main__':
    main()
