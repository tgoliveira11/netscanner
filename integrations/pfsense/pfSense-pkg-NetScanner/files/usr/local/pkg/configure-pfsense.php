#!/usr/local/bin/php
<?php
/*
 * Configure NetScanner package from pfSense shell (no GUI required).
 *
 * Usage:
 *   php configure-pfsense.php AGENT_URL PUSH_TOKEN [AGENT_ID] [INTERVAL_MIN] [on|off]
 */

if (php_sapi_name() !== 'cli') {
	fwrite(STDERR, "CLI only\n");
	exit(1);
}

require_once('guiconfig.inc');
require_once('/usr/local/pkg/netscanner.inc');

$agentUrl = trim($argv[1] ?? '');
$token = trim($argv[2] ?? '');
$agentId = trim($argv[3] ?? 'pfsense');
$interval = max(1, (int)($argv[4] ?? 2));
$enableArg = strtolower(trim($argv[5] ?? 'on'));
$enable = ($enableArg === 'off' || $enableArg === '0' || $enableArg === 'false') ? '' : 'on';

if ($agentUrl === '' || $token === '') {
	fwrite(STDERR, "Usage: php configure-pfsense.php AGENT_URL PUSH_TOKEN [AGENT_ID] [INTERVAL_MIN] [on|off]\n");
	exit(1);
}

$cfg = array_merge(netscanner_config(), [
	'enable' => $enable,
	'agent_url' => $agentUrl,
	'push_token' => $token,
	'agent_id' => $agentId,
	'interval' => (string)$interval,
]);

config_set_path('installedpackages/netscanner/config/0', $cfg);
write_config('NetScanner configured via CLI');
netscanner_sync_package();

echo "NetScanner configured\n";
echo "  Agent URL : {$agentUrl}\n";
echo "  Agent ID  : {$agentId}\n";
echo "  Interval  : {$interval} min\n";
echo "  Push      : " . ($enable === 'on' ? 'enabled' : 'disabled') . "\n";
echo "  Config    : " . NETSCANNER_CONF . "\n";
