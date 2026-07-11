import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname as osHostname } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AgentIdentity, AgentProfile } from '@netscanner/contracts';
import type { AppConfig } from '@netscanner/config';

function netscannerHome(): string {
  return (
    process.env.NETSCANNER_HOME?.trim() ||
    path.join(process.env.HOME || process.env.USERPROFILE || '/tmp', '.netscanner')
  );
}

function resolveProfile(config: AppConfig): AgentProfile {
  if (config.UI_ONLY) return 'ui-only';
  return config.AGENT_PROFILE;
}

/** Load or create persistent agent identity under NETSCANNER_HOME/agent.json. */
export function loadOrCreateAgentIdentity(config: AppConfig): AgentIdentity {
  const home = netscannerHome();
  mkdirSync(home, { recursive: true });
  const file = path.join(home, 'agent.json');
  const now = new Date().toISOString();
  const profile = resolveProfile(config);

  if (existsSync(file)) {
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8')) as Partial<AgentIdentity>;
      const identity: AgentIdentity = {
        id: raw.id && /^[0-9a-f-]{36}$/i.test(raw.id) ? raw.id : randomUUID(),
        hostname: raw.hostname || osHostname(),
        preferLeader: config.CLUSTER_PREFER_LEADER || Boolean(raw.preferLeader),
        dedicated: config.CLUSTER_DEDICATED || Boolean(raw.dedicated),
        profile,
        createdAt: raw.createdAt || now,
        updatedAt: now,
      };
      writeFileSync(file, `${JSON.stringify(identity, null, 2)}\n`);
      return identity;
    } catch {
      /* recreate below */
    }
  }

  const identity: AgentIdentity = {
    id: randomUUID(),
    hostname: osHostname(),
    preferLeader: config.CLUSTER_PREFER_LEADER,
    dedicated: config.CLUSTER_DEDICATED,
    profile,
    createdAt: now,
    updatedAt: now,
  };
  writeFileSync(file, `${JSON.stringify(identity, null, 2)}\n`);
  return identity;
}

export function agentHomePath(): string {
  return netscannerHome();
}
