import ipaddress
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import paramiko
from namessh import core


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ('test', 'secret') else paramiko.AUTH_FAILED
    def get_allowed_auths(self, username): return 'password'
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_pty_request(self, *args): return True
    def check_channel_shell_request(self, channel):
        channel.send(b'hello from ssh\r\n')
        return True


class SSHServer:
    def __init__(self, key):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0)); self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.key = key
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
    def run(self):
        transport = None
        try:
            self.sock.settimeout(5)
            conn, _ = self.sock.accept()
            transport = paramiko.Transport(conn); transport.add_server_key(self.key)
            transport.start_server(server=Server())
            self.stop.wait(5)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            if transport: transport.close()
            self.sock.close()
    def close(self):
        self.stop.set(); self.thread.join(6)


class CoreTests(unittest.TestCase):
    def test_fingerprint(self):
        key = paramiko.RSAKey.generate(1024)
        self.assertTrue(core.fingerprint(key).startswith('SHA256:'))
        self.assertNotIn('=', core.fingerprint(key))

    def test_scan_rejects_oversized_and_ipv6(self):
        for subnet in ('192.168.0.0/16', '::1/128'):
            with self.assertRaises(ValueError): core.scan_network(subnet)

    def test_scan_reports_only_ssh(self):
        found, progress = [], []
        with patch.object(core, 'probe_ssh', side_effect=lambda ip, port: 'SSH-2.0-test' if ip.endswith('.1') else None):
            core.scan_network('192.0.2.0/30', found=lambda *x: found.append(x), progress=lambda *x: progress.append(x))
        self.assertEqual(found, [('192.0.2.1', 'SSH-2.0-test')])
        self.assertEqual(progress[-1], (2, 2))

    def test_probe_banner_and_non_ssh(self):
        for banner, expected in ((b'SSH-2.0-test\r\n', 'SSH-2.0-test'), (b'HTTP/1.0 200 OK\r\n', None)):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); listener.listen(1)
                def serve():
                    conn, _ = listener.accept()
                    with conn: conn.sendall(banner)
                thread = threading.Thread(target=serve); thread.start()
                self.assertEqual(core.probe_ssh('127.0.0.1', listener.getsockname()[1]), expected)
                thread.join()

    def test_real_ssh_auth_shell_and_key_verification(self):
        key = paramiko.RSAKey.generate(2048)
        with tempfile.TemporaryDirectory() as tmp, patch.object(core, 'APP_DIR', Path(tmp)), patch.object(core, 'KNOWN_HOSTS', Path(tmp) / 'known_hosts'):
            server = SSHServer(key)
            confirmations = []
            try:
                client = core.connect_ssh('127.0.0.1', server.port, 'test', 'secret', '', lambda *a: confirmations.append(a) or True)
                channel = client.invoke_shell()
                self.assertIn(b'hello from ssh', channel.recv(1024))
                channel.close(); client.close()
                self.assertEqual(len(confirmations), 1)
                self.assertTrue(core.KNOWN_HOSTS.exists())
            finally: server.close()
            # Check the matching known-hosts entry explicitly; changed keys must not prompt.
            hostkey_name = f'[127.0.0.1]:{server.port}'
            client = paramiko.SSHClient(); client.load_host_keys(str(core.KNOWN_HOSTS))
            self.assertEqual(client.get_host_keys()[hostkey_name][key.get_name()], key)

    def test_rejected_key_is_not_saved(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(core, 'APP_DIR', Path(tmp)), patch.object(core, 'KNOWN_HOSTS', Path(tmp) / 'known_hosts'):
            server = SSHServer(paramiko.RSAKey.generate(2048))
            try:
                with self.assertRaises(paramiko.SSHException):
                    core.connect_ssh('127.0.0.1', server.port, 'test', 'secret', '', lambda *a: False)
                self.assertFalse(core.KNOWN_HOSTS.exists())
            finally: server.close()


if __name__ == '__main__': unittest.main()
