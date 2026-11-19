import base64
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import time
import urllib.error
import urllib.request

import paramiko

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / '.runtime' / 'vm-test'
HOSTS = ('192.168.245.11', '192.168.245.12')


def connect(host, password):
    RUNTIME.mkdir(parents=True, exist_ok=True)
    known = RUNTIME / 'known_hosts'
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if known.exists():
        client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username='root', password=password, timeout=8,
                   auth_timeout=8, banner_timeout=8, look_for_keys=False, allow_agent=False)
    client.save_host_keys(str(known))
    return client


def run(client, command, timeout=25):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return {'exitCode': stdout.channel.recv_exit_status(), 'stdout': out, 'stderr': err}


def inspect(password):
    report = {}
    commands = {
        'os': 'uname -m; cat /etc/os-release; systemctl --version; getenforce',
        'resources': 'hostname; uptime; free -b; df -B1 /',
        'network': 'ip -4 addr; ip -4 route; ss -lntp',
        'firewall': 'firewall-cmd --state; firewall-cmd --get-active-zones; firewall-cmd --list-all',
        'services': 'systemctl list-units --type=service --state=running --no-pager --no-legend',
        'existingFleetOps': 'for p in /opt/fleetops /etc/fleetops /var/lib/fleetops-a /var/lib/fleetops-b /etc/systemd/system/fleetops-a.service /etc/systemd/system/fleetops-b.service; do if test -e "$p"; then ls -ld "$p"; fi; done; getent passwd fleetops-a; getent passwd fleetops-b; true',
    }
    for host in HOSTS:
        client = connect(host, password)
        try:
            key = client.get_transport().get_remote_server_key()
            fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            report[host] = {'sshHostKey': f'SHA256:{fingerprint}', **{name: run(client, cmd) for name, cmd in commands.items()}}
        finally:
            client.close()
    return report


def checked(client, command, timeout=30):
    result = run(client, command, timeout)
    if result['exitCode']:
        raise RuntimeError(f"Remote operation failed ({result['exitCode']}): {result['stderr'][:1000]}")
    return result['stdout']


def put(client, path, content, mode=0o600):
    with client.open_sftp() as sftp:
        with sftp.open(path, 'w') as stream:
            stream.write(content)
        sftp.chmod(path, mode)


def deploy(password):
    report = {}
    for host in HOSTS:
        client = connect(host, password)
        try:
            roles = ('a', 'b') if host == HOSTS[0] else ('a',)
            checked(client, 'set -eu; test ! -e /root/.fleetops-vm-test; test ! -e /opt/fleetops; test ! -e /etc/fleetops; test ! -e /var/lib/fleetops-a; test ! -e /var/lib/fleetops-b; test ! -e /etc/systemd/system/fleetops-a.service; test ! -e /etc/systemd/system/fleetops-b.service; ! getent passwd fleetops-a; ! getent passwd fleetops-b')
            checked(client, 'install -d -m 0700 /root/.fleetops-vm-test')
            for role in roles:
                name = f'fleetops-{role}'
                checked(client, f'set -eu; useradd --system --user-group --home-dir /var/lib/{name} --shell /sbin/nologin {name}; install -d -m 0755 /opt/fleetops/{role}; install -d -o {name} -g {name} -m 0700 /etc/fleetops/{role} /var/lib/{name}')
                binary = ROOT / ('a-agent' if role == 'a' else 'b-monitor') / 'build' / name
                with client.open_sftp() as sftp:
                    sftp.put(str(binary), f'/opt/fleetops/{role}/{name}')
                    sftp.chmod(f'/opt/fleetops/{role}/{name}', 0o755)
                template = (ROOT / 'deploy' / 'linux' / f'{role}.example.yaml').read_text()
                template = template.replace('127.0.0.1:', f'{host}:')
                put(client, f'/etc/fleetops/{role}/config.yaml', template)
                checked(client, f'chown {name}:{name} /etc/fleetops/{role}/config.yaml')
                checked(client, f'umask 077; runuser -u {name} -- /opt/fleetops/{role}/{name} init --config /etc/fleetops/{role}/config.yaml > /root/.fleetops-vm-test/bootstrap-{role}.json')
                unit = (ROOT / 'deploy' / 'linux' / f'{name}.centos7.service').read_text()
                put(client, f'/etc/systemd/system/{name}.service', unit, 0o644)
                result = run(client, f'systemd-analyze verify /etc/systemd/system/{name}.service')
                if result['exitCode'] or result['stderr'].strip():
                    raise RuntimeError(f'Systemd unit validation: {result}')
                checked(client, f'systemctl daemon-reload && systemctl enable {name} && systemctl start {name}')
                report[f'{host}/{role}'] = checked(client, f'systemctl is-active {name}; systemctl is-enabled {name}; uname -r').strip()
        finally:
            client.close()
    return report


def read_remote(client, path):
    with client.open_sftp() as sftp:
        with sftp.open(path) as stream:
            return stream.read().decode('utf-8')


def until(description, check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    raise RuntimeError(f'Timed out: {description}')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify(password):
    clients = {}
    secrets = [password]
    checks = []
    report = {'passed': False, 'backend': 'CentOS 7 VMs, native systemd 219', 'metricsScope': 'host', 'checks': checks}
    addresses = {'a1': f'http://{HOSTS[0]}:18080', 'a2': f'http://{HOSTS[1]}:18080', 'b': f'http://{HOSTS[0]}:18081'}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(service, path, token=None, method='GET', body=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(addresses[service] + path, data=data, headers=headers, method=method)
        try:
            response = opener.open(req, timeout=6)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(1048577)
            assert len(data) <= 1048576, 'response limit exceeded'
            return response.status, json.loads(data) if data else None

    def login(service):
        code, session = request(service, '/api/v1/session', method='POST', body={'credential': access[service]['credential']})
        assert code == 200, f'{service} login failed'
        secrets.append(session['token'])
        return session

    def cli(service, args):
        client = clients[HOSTS[1] if service == 'a2' else HOSTS[0]]
        role = 'b' if service == 'b' else 'a'
        raw = checked(client, f'runuser -u fleetops-{role} -- /opt/fleetops/{role}/fleetops-{role} {args} --config /etc/fleetops/{role}/config.yaml')
        return json.loads(raw) if raw.strip() else None

    def desktop(with_monitor):
        payload = {'targets': [{'name': f'虚拟机 A{i}', 'origin': addresses[f'a{i}'], **access[f'a{i}']} for i in (1, 2)]}
        if with_monitor:
            payload['monitor'] = {'name': '虚拟机持续监控 B', 'origin': addresses['b'], **access['b']}
        child = subprocess.Popen(['node', str(ROOT / 'c-desktop/scripts/smoke.mjs'), '--vm'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', cwd=ROOT)
        try:
            stdout, stderr = child.communicate(json.dumps(payload), timeout=120)
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill.exe', '/PID', str(child.pid), '/T', '/F'], capture_output=True, check=False)
            child.communicate()
            raise RuntimeError('Windows EXE verification timed out; test process tree terminated') from None
        assert child.returncode == 0, 'Windows EXE verification failed; diagnostic output withheld to protect secrets'
        result = json.loads(stdout)
        assert result['passed'] and result['embeddedFrontend']
        return result

    try:
        for host in HOSTS:
            clients[host] = connect(host, password)
        access = {
            'a1': json.loads(read_remote(clients[HOSTS[0]], '/root/.fleetops-vm-test/bootstrap-a.json')),
            'a2': json.loads(read_remote(clients[HOSTS[1]], '/root/.fleetops-vm-test/bootstrap-a.json')),
            'b': json.loads(read_remote(clients[HOSTS[0]], '/root/.fleetops-vm-test/bootstrap-b.json')),
        }
        secrets.extend(value['credential'] for value in access.values())
        assert len({value['nodeId'] for value in access.values()}) == 3, 'identities must be independent'
        sessions = {service: login(service) for service in addresses}
        metrics = {}
        for service, host in zip(('a1', 'a2'), HOSTS):
            code, status = request(service, '/api/v1/status', sessions[service]['token'])
            assert code == 200 and status['metricsScope'] == 'host'
            assert status['nodeId'] == access[service]['nodeId']
            client = clients[host]
            hostname = checked(client, 'hostname').strip()
            kernel = checked(client, 'uname -r').strip()
            meminfo = read_remote(client, '/proc/meminfo')
            memtotal = int(next(line.split()[1] for line in meminfo.splitlines() if line.startswith('MemTotal:'))) * 1024
            uptime = float(read_remote(client, '/proc/uptime').split()[0])
            disk = checked(client, 'LC_ALL=C df -B1 -P /').splitlines()[-1].split()
            assert status['hostname'] == hostname and status['system']['kernel'] == kernel
            assert status['memory']['totalBytes'] == memtotal
            assert abs(status['uptimeSeconds'] - uptime) < 20
            assert abs(status['disk']['totalBytes'] - int(disk[1])) < int(disk[1]) * 0.01
            assert abs(status['disk']['usedBytes'] - int(disk[2])) < int(disk[1]) * 0.01
            assert status['cpu']['logicalCount'] == int(checked(client, 'getconf _NPROCESSORS_ONLN'))
            assert status['cpu']['usagePercent'] is not None and 0 <= status['cpu']['usagePercent'] <= 100
            metrics[service] = {'hostname': hostname, 'kernel': kernel, 'nodeId': status['nodeId'], 'memoryTotalBytes': memtotal, 'rootTotalBytes': status['disk']['totalBytes'], 'uptimeSeconds': status['uptimeSeconds']}
            assert request(service, '/api/v1/status')[0] == 401
        assert request('a2', '/api/v1/status', sessions['a1']['token'])[0] == 401
        checks.extend(['distinct A1/A2/B identities', 'authenticated host metrics match hostname, kernel, CPU count, /proc/meminfo, uptime and df', 'unauthenticated and cross-node requests rejected'])
        report['hosts'] = metrics
        report['endpoints'] = addresses
        machine = {}
        old_tokens = {}
        for service in ('a1', 'a2'):
            old_tokens[service] = cli(service, 'list-tokens')
            machine[service] = cli(service, 'issue-token --name vm-monitor')
            secrets.append(machine[service]['token'])
            assert request(service, '/api/v1/status', machine[service]['token'])[0] == 200
            assert request(service, '/api/v1/session', machine[service]['token'])[0] == 403
        targets = {'targets': [{'id': service, 'name': f'虚拟机 A{i}', 'url': addresses[service], 'expected_node_id': access[service]['nodeId'], 'token': machine[service]['token']} for i, service in enumerate(('a1', 'a2'), 1)]}
        bclient = clients[HOSTS[0]]
        put(bclient, '/etc/fleetops/b/targets.yaml.new', json.dumps(targets))
        checked(bclient, 'chown fleetops-b:fleetops-b /etc/fleetops/b/targets.yaml.new && mv /etc/fleetops/b/targets.yaml.new /etc/fleetops/b/targets.yaml && systemctl restart fleetops-b')
        until('B ready', lambda: request('b', '/api/v1/session')[0] == 401)
        btoken = login('b')['token']

        def observation():
            code, data = request('b', '/api/v1/monitor', btoken)
            assert code == 200
            return data

        def events():
            code, data = request('b', '/api/v1/events?limit=100', btoken)
            assert code == 200
            return data['events']

        def all_online():
            data = observation()
            return data if len(data['targets']) == 2 and all(t['state'] == 'online' for t in data['targets']) and data['storageHealthy'] else None

        until('B monitors both hosts', all_online)
        for service in ('a1', 'a2'):
            for old in old_tokens[service]:
                if old['name'] == 'vm-monitor':
                    cli(service, 'revoke-token --id ' + old['id'])
        checks.extend(['machine tokens restricted to status', 'B polls both VMs using separate machine tokens', 'new tokens verified before old vm-monitor tokens are revoked'])
        checked(bclient, 'systemctl stop fleetops-b')
        assert run(bclient, 'systemctl is-active fleetops-b')['stdout'].strip() == 'inactive'
        report['desktopWithoutB'] = desktop(False)
        checks.append('real production Windows EXE connects both VMs while B is stopped')
        checked(bclient, 'systemctl start fleetops-b')
        until('B ready again', lambda: request('b', '/api/v1/session')[0] == 401)
        assert request('b', '/api/v1/monitor', btoken)[0] == 401
        btoken = login('b')['token']
        until('B reobserves both VMs', all_online)
        report['desktopWithB'] = desktop(True)
        checks.append('real production Windows EXE reads B monitor targets')
        previous = events()
        last_id = previous[0]['id'] if previous else 0
        checked(bclient, 'systemctl stop fleetops-a')

        def failed_five():
            data = observation()
            a1 = next(t for t in data['targets'] if t['id'] == 'a1')
            a2 = next(t for t in data['targets'] if t['id'] == 'a2')
            assert a2['state'] == 'online', 'A2 affected by A1 stop'
            return data if a1['state'] == 'unreachable' and a1['failures'] >= 5 and a1['stale'] else None

        offline = until('A1 failure threshold, stale and repeated failure', failed_five, 190)
        recent = [e for e in events() if e['id'] > last_id]
        assert len([e for e in recent if e['targetId'] == 'a1' and e['kind'] == 'unreachable']) == 1
        checked(bclient, 'systemctl start fleetops-a')
        until('A1 recovers', all_online, 50)
        recent = [e for e in events() if e['id'] > last_id]
        assert len([e for e in recent if e['targetId'] == 'a1' and e['kind'] == 'recovered']) == 1
        assert not [e for e in recent if e['targetId'] == 'a2']
        assert request('a1', '/api/v1/status', sessions['a1']['token'])[0] == 401
        assert login('a1')['nodeId'] == access['a1']['nodeId']
        assert request('a1', '/api/v1/status', machine['a1']['token'])[0] == 200
        checks.extend(['B continues with both C windows closed', 'A1 threshold/stale/deduplicated outage and recovery; A2 unaffected', 'A restart preserves identity and machine token, invalidates session'])
        retained = {e['id'] for e in recent}
        last_id = max(retained)
        before_instance = observation()['instanceId']
        for role in ('a', 'b'):
            name = f'fleetops-{role}'
            old_pid = checked(bclient, f'systemctl show {name} -p MainPID').strip()
            checked(bclient, f'systemctl kill --kill-who=main --signal=SIGKILL {name}')

            def restarted():
                state = run(bclient, f'systemctl is-active {name}')
                pid = checked(bclient, f'systemctl show {name} -p MainPID').strip()
                return state['stdout'].strip() == 'active' and pid not in (old_pid, 'MainPID=0')

            until(f'{name} systemd crash restart', restarted, 30)
        until('B HTTP after crash restart', lambda: request('b', '/api/v1/session')[0] == 401)
        assert request('b', '/api/v1/monitor', btoken)[0] == 401
        btoken = login('b')['token']
        until('B after crash reobserves online', all_online, 50)
        assert observation()['instanceId'] != before_instance
        assert retained.issubset({e['id'] for e in events()})
        assert not [e for e in events() if e['id'] > last_id], 'restart fabricated an event'
        checks.extend(['systemd restarts A and B after SIGKILL with new main PIDs', 'B crash restart preserves SQLite events without fabricated recovery'])
        revoked = cli('a1', 'issue-token --name vm-revocation-check')
        secrets.append(revoked['token'])
        assert request('a1', '/api/v1/status', revoked['token'])[0] == 200
        cli('a1', 'revoke-token --id ' + revoked['id'])
        assert request('a1', '/api/v1/status', revoked['token'])[0] == 401
        checks.append('runtime machine token revocation')
        service_details = {}
        for host in HOSTS:
            client = clients[host]
            for role in (('a', 'b') if host == HOSTS[0] else ('a',)):
                name = f'fleetops-{role}'
                assert checked(client, f'systemctl is-enabled {name}').strip() == 'enabled'
                details = checked(client, f'systemctl show {name} -p User -p Group -p MainPID -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp -p CapabilityBoundingSet')
                assert f'User={name}' in details
                process_user = checked(client, f'ps -o user:32= -p $(systemctl show {name} -p MainPID | cut -d= -f2)').strip()
                assert process_user == name
                modes = checked(client, f'stat -c "%a %U %G" /var/lib/{name} /etc/fleetops/{role}/config.yaml').splitlines()
                assert modes == [f'700 {name} {name}', f'600 {name} {name}']
                logs = checked(client, f'journalctl -u {name} --no-pager -n 300')
                assert not any(secret in logs for secret in secrets), 'secret in service journal'
                service_details[f'{host}/{role}'] = details.strip().splitlines()
        assert checked(bclient, 'stat -c "%a %U %G" /etc/fleetops/b/targets.yaml').strip() == '600 fleetops-b fleetops-b'
        assert checked(bclient, 'systemctl is-active mysqld').strip() == 'active'
        checks.extend(['enabled services run as dedicated non-root users with private config/data', 'journals contain no test secrets', 'existing MySQL service remains active'])
        report.update({'passed': True, 'services': service_details, 'eventsObserved': recent, 'notValidated': ['whole-VM reboot and boot startup (enabled only verified)', 'trusted HTTPS and browser CORS end-to-end', '1Panel deployment'], 'servicesLeftRunning': ['192.168.245.11/A', '192.168.245.11/B', '192.168.245.12/A']})
        return report
    finally:
        for host, client in clients.items():
            for role in (('a', 'b') if host == HOSTS[0] else ('a',)):
                try:
                    result = run(client, f'systemctl start fleetops-{role}')
                    restored = result['exitCode'] == 0
                except (paramiko.SSHException, OSError, EOFError):
                    restored = False
                if not restored:
                    report['passed'] = False
                    report.setdefault('restoreErrors', []).append(f'{host}/{role}')
            client.close()
        RUNTIME.mkdir(parents=True, exist_ok=True)
        (RUNTIME / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    payload = json.load(sys.stdin)
    actions = {'inspect': inspect, 'deploy': deploy, 'verify': verify}
    if payload['action'] not in actions:
        raise SystemExit('unsupported action')
    print(json.dumps(actions[payload['action']](payload['password']), ensure_ascii=True, indent=2))
