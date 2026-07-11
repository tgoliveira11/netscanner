#!/usr/bin/env node
/**
 * Stand-alone scan-only CLI (max features without full gateway UI/control).
 *
 * Usage:
 *   pnpm --filter @netscanner/scanner scan --cidr 192.168.1.0/24
 *   node --import tsx src/cli.ts --cidr 10.0.0.0/24 --json
 */
import { shardCidrs } from '@netscanner/contracts';

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return fallback;
}

function flag(name: string): boolean {
  return process.argv.includes(name);
}

async function main(): Promise<void> {
  const cidr = arg('--cidr') || arg('-c');
  const workers = Number(arg('--workers', '1'));
  const asJson = flag('--json');

  if (!cidr) {
    console.error(`netscanner-scan — scan-only agent CLI

Usage:
  scan --cidr <CIDR> [--workers N] [--json]

Shards large multi-CIDR jobs with shardCidrs() for cluster workers.
Full host probing uses the gateway scan-only profile or library APIs.
`);
    process.exit(1);
  }

  const cidrs = cidr.split(',').map((s) => s.trim()).filter(Boolean);
  const shards = shardCidrs(cidrs, Math.max(1, workers));

  const result = {
    mode: 'scan-only',
    cidrs,
    workers: shards.length,
    shards,
    note: 'Execute each shard on a worker agent (AGENT_PROFILE=scan-only) or via gateway POST /api/scans',
  };

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`scan-only plan for ${cidrs.length} CIDR(s) across ${shards.length} worker(s):`);
    shards.forEach((s, i) => console.log(`  worker ${i}: ${s.join(', ') || '(idle)'}`));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
