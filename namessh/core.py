"""Network discovery and SSH connection helpers, independent of the GUI."""
import base64
import concurrent.futures
import hashlib
import ipaddress
import os
import socket
import threading
from pathlib import Path

import paramiko
import psutil

APP_DIR = Path(os.environ.get('APPDATA') or Path.home() / '.config') / 'NameSSH'
KNOWN_HOSTS = APP_DIR / 'known_hosts'
MAX_HOSTS = 1024


def local_networks():
    """Return local IPv4 networks; limit very large networks to the local /24."""
    results = []
    for name, addresses in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if stats and not stats.isup:
            continue
        for addr in addresses:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            try:
                iface = ipaddress.ip_interface(f'{addr.address}/{addr.netmask}')
                if iface.ip.is_loopback or iface.ip.is_link_local or iface.ip.is_unspecified:
                    continue
                network = iface.network
                limited = network.num_addresses > MAX_HOSTS
                if limited:
                    network = ipaddress.ip_network(f'{iface.ip}/24', strict=False)
                results.append((name, str(iface.ip), str(network), limited))
            except ValueError:
                continue
    return results


def probe_ssh(host, port=22, timeout=0.65):
    """Only report a host when it actually sends an SSH identification banner."""
    try:
        with socket.create_connection((str(host), port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            data = b''
            # RFC 4253 permits informational lines before the SSH banner.
            while len(data) < 2048:
                chunk = conn.recv(256)
                if not chunk:
                    break
                data += chunk
                for line in data.splitlines():
                    if line.startswith(b'SSH-'):
                        return line.decode('utf-8', errors='replace').strip()[:255]
    except (OSError, TimeoutError):
        pass
    return None


def scan_network(network, port=22, cancel=None, progress=None, found=None, workers=64):
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4 or net.num_addresses > MAX_HOSTS:
        raise ValueError(f'Допустима сеть IPv4 не более {MAX_HOSTS} адресов')
    hosts = list(net.hosts())
    cancel = cancel or threading.Event()
    done = 0
    # A bounded subnet and timeouts keep shutdown predictable.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_ssh, str(ip), port): str(ip) for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if cancel.is_set():
                for pending in futures:
                    pending.cancel()
                break
            banner = future.result()
            done += 1
            if banner and found:
                found(futures[future], banner)
            if progress:
                progress(done, len(hosts))


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class ConfirmHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, confirm):
        self.confirm = confirm

    def missing_host_key(self, client, hostname, key):
        if not self.confirm(hostname, key.get_name(), fingerprint(key)):
            raise paramiko.SSHException('Ключ сервера не подтверждён')
        # Save before connecting: a later changed key must be rejected by Paramiko.
        APP_DIR.mkdir(parents=True, exist_ok=True)
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(KNOWN_HOSTS))


def connect_ssh(host, port, username, password, key_file, confirm):
    client = paramiko.SSHClient()
    if KNOWN_HOSTS.exists():
        client.load_host_keys(str(KNOWN_HOSTS))
    client.set_missing_host_key_policy(ConfirmHostKey(confirm))
    try:
        client.connect(hostname=host, port=port, username=username,
                       password=password or None, key_filename=key_file or None,
                       passphrase=password or None, timeout=10, banner_timeout=10,
                       auth_timeout=15, allow_agent=not bool(key_file),
                       look_for_keys=not bool(key_file))
        return client
    except Exception:
        client.close()
        raise
