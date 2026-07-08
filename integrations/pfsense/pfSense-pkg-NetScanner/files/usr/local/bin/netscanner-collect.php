#!/usr/local/bin/php
<?php
/**
 * NetScanner pfSense collector — gathers network state and POSTs JSON to the main agent.
 *
 * Install: integrations/pfsense/install.sh
 * Config:  /usr/local/etc/netscanner/agent.conf
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

const NETSCANNER_CONF = '/usr/local/etc/netscanner/agent.conf';
const NETSCANNER_LOG  = '/var/log/netscanner-push.log';

function log_msg(string $msg): void {
    $line = sprintf("[%s] %s\n", gmdate('c'), $msg);
    @file_put_contents(NETSCANNER_LOG, $line, FILE_APPEND);
}

function read_conf(string $path): array {
    if (!is_readable($path)) {
        return [];
    }
    $out = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $pos = strpos($line, '=');
        if ($pos === false) {
            continue;
        }
        $key = trim(substr($line, 0, $pos));
        $val = trim(substr($line, $pos + 1));
        $out[$key] = $val;
    }
    return $out;
}

function pfsense_bootstrap(): bool {
    if (!is_file('/etc/inc/config.inc')) {
        return false;
    }
    require_once '/etc/inc/config.inc';
    require_once '/etc/inc/interfaces.inc';
    if (is_file('/etc/inc/gwlb.inc')) {
        require_once '/etc/inc/gwlb.inc';
    }
    if (is_file('/etc/inc/system.inc')) {
        require_once '/etc/inc/system.inc';
    }
    return true;
}

function collect_dhcp_leases(): array {
    $leases = [];
    $paths = glob('/var/dhcpd/var/db/dhcpd.leases*') ?: [];
    foreach ($paths as $path) {
        $leases = array_merge($leases, parse_isc_leases(file_get_contents($path) ?: ''));
    }
    return $leases;
}

function parse_isc_leases(string $raw): array {
    $out = [];
    if ($raw === '') {
        return $out;
    }
    if (!preg_match_all('/lease\s+(\S+)\s*\{([^}]*)\}/s', $raw, $matches, PREG_SET_ORDER)) {
        return $out;
    }
    foreach ($matches as $m) {
        $ip = trim($m[1]);
        $body = $m[2];
        $mac = null;
        $hostname = null;
        $state = 'active';
        if (preg_match('/hardware\s+ethernet\s+([0-9a-f:]+)/i', $body, $hm)) {
            $mac = strtolower($hm[1]);
        }
        if (preg_match('/client-hostname\s+"([^"]+)"/i', $body, $hn)) {
            $hostname = $hn[1];
        }
        if (preg_match('/binding\s+state\s+(\S+)/i', $body, $bs)) {
            $state = strtolower($bs[1]);
        }
        if ($ip === '0.0.0.0' || !$mac) {
            continue;
        }
        $out[] = [
            'ip' => $ip,
            'mac' => $mac,
            'hostname' => $hostname,
            'online_status' => in_array($state, ['active', 'bound'], true) ? 'active/online' : 'idle/offline',
        ];
    }
    return $out;
}

function collect_arp(): array {
    $out = [];
    exec('arp -an 2>/dev/null', $lines);
    foreach ($lines as $line) {
        if (!preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $line, $m)) {
            continue;
        }
        $iface = null;
        if (preg_match('/on\s+(\S+)/', $line, $im)) {
            $iface = $im[1];
        }
        $out[] = [
            'ip' => $m[1],
            'mac' => strtolower($m[2]),
            'interface' => $iface,
            'permanent' => stripos($line, 'permanent') !== false,
        ];
    }
    return $out;
}

function collect_gateways(): array {
    $out = [];
    if (function_exists('return_gateways_array')) {
        $gw = return_gateways_array(true);
        foreach ($gw as $name => $row) {
            $out[] = [
                'name' => (string)$name,
                'gateway' => $row['gateway'] ?? null,
                'monitor' => $row['monitor'] ?? null,
                'interface' => $row['interface'] ?? null,
                'weight' => $row['weight'] ?? null,
            ];
        }
        return $out;
    }
    exec('netstat -rn -f inet 2>/dev/null', $lines);
    foreach ($lines as $line) {
        if (!preg_match('/^default\s+(\S+)\s+\S+\s+\S+\s+(\S+)/', $line, $m)) {
            continue;
        }
        $out[] = ['name' => 'default', 'gateway' => $m[1], 'interface' => $m[2]];
    }
    return $out;
}

function collect_interfaces(): array {
    $out = [];
    global $config;
    if (isset($config['interfaces']) && is_array($config['interfaces'])) {
        foreach ($config['interfaces'] as $if => $row) {
            if (!is_array($row)) {
                continue;
            }
            $out[] = [
                'if' => (string)$if,
                'descr' => $row['descr'] ?? $if,
                'ipaddr' => $row['ipaddr'] ?? null,
                'subnet' => $row['subnet'] ?? null,
                'vlan' => $row['vlanif'] ?? ($row['vlan'] ?? null),
                'mac' => $row['hwif'] ?? null,
            ];
        }
        return $out;
    }
    exec('ifconfig -a 2>/dev/null', $lines);
    $cur = null;
    foreach ($lines as $line) {
        if (preg_match('/^(\w+):/', $line, $m)) {
            $cur = $m[1];
            $out[] = ['if' => $cur, 'descr' => $cur];
        } elseif ($cur && preg_match('/inet\s+(\d+\.\d+\.\d+\.\d+)/', $line, $im)) {
            $out[count($out) - 1]['ipaddr'] = $im[1];
        }
    }
    return $out;
}

function collect_dhcp_static(): array {
    $out = [];
    global $config;
    if (!isset($config['dhcpd']) || !is_array($config['dhcpd'])) {
        return $out;
    }
    foreach ($config['dhcpd'] as $if => $pool) {
        if (!isset($pool['staticmap']) || !is_array($pool['staticmap'])) {
            continue;
        }
        foreach ($pool['staticmap'] as $row) {
            $out[] = [
                'interface' => (string)$if,
                'mac' => $row['mac'] ?? null,
                'ipaddr' => $row['ipaddr'] ?? null,
                'hostname' => $row['hostname'] ?? null,
                'descr' => $row['descr'] ?? null,
            ];
        }
    }
    return $out;
}

function enrich_leases_with_interface(array $leases, array $interfaces): array {
    $ipToIf = [];
    foreach ($interfaces as $iface) {
        $ip = $iface['ipaddr'] ?? null;
        $descr = $iface['descr'] ?? ($iface['if'] ?? null);
        if (!$ip || !$descr) {
            continue;
        }
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            continue;
        }
        $prefix = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.';
        $ipToIf[$prefix] = $descr;
    }
    foreach ($leases as &$lease) {
        if (!empty($lease['if'])) {
            continue;
        }
        $ip = $lease['ip'] ?? '';
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            continue;
        }
        $prefix = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.';
        if (isset($ipToIf[$prefix])) {
            $lease['if'] = $ipToIf[$prefix];
        }
    }
    unset($lease);
    return $leases;
}

function collect_payload(array $conf): array {
    $pfsense_ok = pfsense_bootstrap();
    $leases = collect_dhcp_leases();
    $interfaces = collect_interfaces();
    $leases = enrich_leases_with_interface($leases, $interfaces);

    $version = null;
    $hostname = null;
    if ($pfsense_ok) {
        if (function_exists('g_getversion')) {
            $version = g_getversion();
        }
        global $config;
        $hostname = $config['system']['hostname'] ?? null;
    }

    return [
        'agentId' => $conf['AGENT_ID'] ?? 'pfsense',
        'sentAt' => gmdate('c'),
        'pfsenseVersion' => $version,
        'hostname' => $hostname,
        'leases' => $leases,
        'arp' => collect_arp(),
        'gateways' => collect_gateways(),
        'interfaces' => $interfaces,
        'dhcpStatic' => collect_dhcp_static(),
    ];
}

function post_payload(string $url, string $token, array $payload): array {
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return ['ok' => false, 'error' => 'json_encode failed'];
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $json,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token,
            'User-Agent: netscanner-pfsense/0.1',
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'error' => $err ?: 'curl failed'];
    }
    return ['ok' => $code >= 200 && $code < 300, 'code' => $code, 'body' => $body];
}

// --- main ---
$conf = read_conf(NETSCANNER_CONF);
$url = $conf['AGENT_URL'] ?? '';
$token = $conf['PUSH_TOKEN'] ?? '';

if ($url === '' || $token === '') {
    fwrite(STDERR, "Missing AGENT_URL or PUSH_TOKEN in " . NETSCANNER_CONF . "\n");
    exit(2);
}

$payload = collect_payload($conf);
$result = post_payload(rtrim($url, '/') . '/api/integrations/pfsense/push', $token, $payload);

if (!$result['ok']) {
    $msg = $result['error'] ?? ('HTTP ' . ($result['code'] ?? '?') . ' ' . ($result['body'] ?? ''));
    log_msg('push failed: ' . $msg);
    fwrite(STDERR, $msg . "\n");
    exit(1);
}

$summary = sprintf(
    'pushed %d leases, %d arp, %d gw, %d if — %s',
    count($payload['leases']),
    count($payload['arp']),
    count($payload['gateways']),
    count($payload['interfaces']),
    $result['body'] ?? 'ok'
);
log_msg($summary);
echo $summary . "\n";
exit(0);
