import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import {
  CloudRemoteCommandSchema,
  InventoryEventSchema,
  type CloudRemoteCommand,
  type InventoryEvent,
} from '@netscanner/contracts';

/**
 * Minimal self-host cloud: ingest inventory events, queue remote commands.
 * Persist to JSON files under CLOUD_DATA_DIR (swap for Postgres later).
 */
const PORT = Number(process.env.CLOUD_PORT || 8080);
const TOKEN = (process.env.CLOUD_SITE_TOKEN || '').trim();
const DATA = process.env.CLOUD_DATA_DIR || path.join(process.cwd(), 'data');

mkdirSync(DATA, { recursive: true });
const eventsFile = path.join(DATA, 'events.jsonl');
const commandsFile = path.join(DATA, 'commands.json');

function auth(header: string | undefined): boolean {
  if (!TOKEN) return true;
  return header === `Bearer ${TOKEN}`;
}

function loadCommands(): CloudRemoteCommand[] {
  if (!existsSync(commandsFile)) return [];
  try {
    return JSON.parse(readFileSync(commandsFile, 'utf8')) as CloudRemoteCommand[];
  } catch {
    return [];
  }
}

function saveCommands(cmds: CloudRemoteCommand[]): void {
  writeFileSync(commandsFile, `${JSON.stringify(cmds, null, 2)}\n`);
}

const app = Fastify({ logger: true });

app.get('/health', async () => ({ status: 'ok', service: 'netscanner-cloud' }));

app.post('/api/v1/events', async (request, reply) => {
  if (!auth(request.headers.authorization)) return reply.code(401).send({ error: 'unauthorized' });
  const body = request.body as { events?: unknown[] };
  const events = Array.isArray(body.events) ? body.events : [];
  const accepted: InventoryEvent[] = [];
  for (const raw of events) {
    const parsed = InventoryEventSchema.safeParse(raw);
    if (parsed.success) accepted.push(parsed.data);
  }
  if (accepted.length) {
    const lines = accepted.map((e) => JSON.stringify(e)).join('\n') + '\n';
    writeFileSync(eventsFile, lines, { flag: 'a' });
  }
  return { ok: true, accepted: accepted.length };
});

app.get('/api/v1/events/recent', async (request, reply) => {
  if (!auth(request.headers.authorization)) return reply.code(401).send({ error: 'unauthorized' });
  if (!existsSync(eventsFile)) return { data: [] };
  const lines = readFileSync(eventsFile, 'utf8').trim().split('\n').filter(Boolean);
  const tail = lines.slice(-200).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter(Boolean);
  return { data: tail };
});

app.post('/api/v1/commands', async (request, reply) => {
  if (!auth(request.headers.authorization)) return reply.code(401).send({ error: 'unauthorized' });
  const parsed = CloudRemoteCommandSchema.safeParse({
    ...(request.body as object),
    id: randomUUID(),
    createdAt: new Date().toISOString(),
  });
  if (!parsed.success) return reply.code(400).send({ error: parsed.error.message });
  const cmds = loadCommands();
  cmds.push(parsed.data);
  saveCommands(cmds);
  return { ok: true, command: parsed.data };
});

app.get('/api/v1/commands/pending', async (request, reply) => {
  if (!auth(request.headers.authorization)) return reply.code(401).send({ error: 'unauthorized' });
  const cmds = loadCommands();
  // Return and clear (at-most-once delivery for v1)
  saveCommands([]);
  return { data: cmds };
});

await app.listen({ port: PORT, host: '0.0.0.0' });
console.log(`netscanner-cloud listening on :${PORT}`);
