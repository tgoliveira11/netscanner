import type { Device } from './device.js';
import type { ScanSession, DiscoveredHost } from './scan.js';

/**
 * Domain event catalogue shared by every service and the WebSocket hub.
 * A discriminated union keeps producers and consumers type-safe (LSP/ISP).
 */
export type DomainEvent =
  | { type: 'scan.started'; payload: ScanSession }
  | { type: 'scan.progress'; payload: ScanSession }
  | { type: 'scan.completed'; payload: ScanSession }
  | { type: 'scan.failed'; payload: { scanId: string; error: string } }
  | { type: 'host.discovered'; payload: { scanId: string; host: DiscoveredHost } }
  | { type: 'device.classified'; payload: { scanId: string; device: Device } }
  | { type: 'device.new'; payload: { scanId: string; device: Device } }
  | { type: 'device.changed'; payload: { scanId: string; device: Device; changes: string[] } }
  | { type: 'device.offline'; payload: { deviceId: string; device?: Device } }
  | { type: 'device.online'; payload: { device: Device } }
  | {
      type: 'device.anomaly';
      payload: { scanId: string; device: Device; code: string; severity: string; message: string };
    };

export type DomainEventType = DomainEvent['type'];

/** Publisher port (ISP): infrastructure/services depend only on emit(). */
export interface IEventPublisher {
  emit(event: DomainEvent): void;
}

/** Subscriber port. Returns an unsubscribe function. */
export interface IEventSubscriber {
  on(handler: (event: DomainEvent) => void): () => void;
}
