import { EventEmitter } from 'node:events';
import type { DomainEvent, IEventPublisher, IEventSubscriber } from '@netscanner/contracts';

/**
 * In-process event bus wiring producers (services) to consumers (WebSocket hub,
 * loggers). It implements the contract ports so the rest of the system depends
 * only on IEventPublisher/IEventSubscriber — swapping to Redis/NATS later needs
 * no changes outside this file (DIP).
 */
export class InProcessEventBus implements IEventPublisher, IEventSubscriber {
  private readonly emitter = new EventEmitter();

  constructor() {
    this.emitter.setMaxListeners(100);
  }

  emit(event: DomainEvent): void {
    this.emitter.emit('event', event);
  }

  on(handler: (event: DomainEvent) => void): () => void {
    this.emitter.on('event', handler);
    return () => this.emitter.off('event', handler);
  }
}
