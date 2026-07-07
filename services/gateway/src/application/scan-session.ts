import { v4 as uuid } from 'uuid';
import type { ScanSession, ScanType } from '@netscanner/contracts';

/** In-memory registry of scan sessions and their live progress counters. */
export class ScanSessionStore {
  private readonly sessions = new Map<string, ScanSession>();

  create(cidr: string, scanType: ScanType): ScanSession {
    return this.createWithId(uuid(), cidr, scanType);
  }

  createWithId(id: string, cidr: string, scanType: ScanType): ScanSession {
    const session: ScanSession = {
      id,
      cidr,
      scanType,
      status: 'pending',
      hostsTotal: 0,
      hostsDiscovered: 0,
      devicesClassified: 0,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      error: null,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  update(id: string, patch: Partial<ScanSession>): ScanSession | undefined {
    const current = this.sessions.get(id);
    if (!current) return undefined;
    const next = { ...current, ...patch };
    this.sessions.set(id, next);
    return next;
  }

  get(id: string): ScanSession | undefined {
    return this.sessions.get(id);
  }

  /** True while a user- or background-initiated scan is in flight. */
  activeScan(): ScanSession | undefined {
    return [...this.sessions.values()].find(
      (s) => s.status === 'pending' || s.status === 'discovering' || s.status === 'fingerprinting',
    );
  }

  latest(): ScanSession | undefined {
    return [...this.sessions.values()].sort((a, b) => b.startedAt.localeCompare(a.startedAt))[0];
  }
}
