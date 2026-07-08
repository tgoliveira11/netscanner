<?php
/*
 * NetScanner package — status page (Services → NetScanner)
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/netscanner.inc');

$pgtitle = array(gettext('Services'), gettext('NetScanner'));
$pglinks = array('', '@self');
require_once('head.inc');

$run_now = $_POST['run_now'] ?? '';
$result = null;
if ($run_now === 'yes') {
	$result = netscanner_run_collect_now();
}

$tab_array = array();
$tab_array[] = array(gettext('Status'), true, 'index.php');
$tab_array[] = array(gettext('Settings'), false, '/pkg_edit.php?xml=netscanner.xml');
display_top_tabs($tab_array);

$cfg = netscanner_config();
?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('NetScanner push status'); ?></h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?=gettext('Enabled');?></dt>
			<dd><?= netscanner_enabled() ? gettext('Yes') : gettext('No'); ?></dd>
			<dt><?=gettext('Agent URL');?></dt>
			<dd><?=htmlspecialchars($cfg['agent_url'] ?? '—'); ?></dd>
			<dt><?=gettext('Agent ID');?></dt>
			<dd><?=htmlspecialchars($cfg['agent_id'] ?? 'pfsense'); ?></dd>
			<dt><?=gettext('Interval');?></dt>
			<dd><?=htmlspecialchars(($cfg['interval'] ?? '2') . ' min'); ?></dd>
			<dt><?=gettext('Config file');?></dt>
			<dd><code><?=NETSCANNER_CONF;?></code></dd>
		</dl>

		<form method="post" class="form-inline">
			<input type="hidden" name="run_now" value="yes" />
			<button type="submit" class="btn btn-primary" name="submit" value="submit">
				<i class="fa fa-play icon-embed-btn"></i>
				<?=gettext('Push now');?>
			</button>
			<a class="btn btn-default" href="/pkg_edit.php?xml=netscanner.xml"><?=gettext('Settings');?></a>
		</form>

		<?php if ($result !== null): ?>
			<div class="alert <?= $result['code'] === 0 ? 'alert-success' : 'alert-danger'; ?>" style="margin-top:1em;">
				<pre style="margin:0;white-space:pre-wrap;"><?=htmlspecialchars($result['output']); ?></pre>
			</div>
		<?php endif; ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Recent log');?></h2></div>
	<div class="panel-body">
		<pre style="max-height:320px;overflow:auto;"><?=htmlspecialchars(netscanner_tail_log(40) ?: gettext('No log entries yet.')); ?></pre>
	</div>
</div>

<?php require_once('foot.inc'); ?>
