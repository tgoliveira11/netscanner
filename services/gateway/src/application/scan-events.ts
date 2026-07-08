import type { Device, IEventPublisher } from '@netscanner/contracts';
import type { UpsertResult, BehavioralAnomaly } from '@netscanner/inventory';
import type { DnsActivityLog } from './dns-activity-log.js';

function deviceLabel(device: Device): string {
  return device.label ?? device.hostname ?? device.ip;
}

/** Route DNS destination anomalies to the relations log — not the alerts bell. */
export function emitDeviceAnomalies(
  events: IEventPublisher,
  scanId: string,
  device: Device,
  anomalies: BehavioralAnomaly[],
  dnsLog?: DnsActivityLog,
): void {
  for (const anomaly of anomalies) {
    if (anomaly.code === 'NEW_EXTERNAL_DEST' || anomaly.code === 'DEVICE_OFFLINE') {
      if (anomaly.code === 'NEW_EXTERNAL_DEST') {
        dnsLog?.push({
          at: new Date().toISOString(),
          deviceId: device.id,
          deviceLabel: deviceLabel(device),
          message: anomaly.message,
        });
      }
      continue;
    }
    events.emit({
      type: 'device.anomaly',
      payload: {
        scanId,
        device,
        code: anomaly.code,
        severity: anomaly.severity,
        message: anomaly.message,
      },
    });
  }
}

/** Emit standard device lifecycle events after persistence. */
export function emitDeviceUpsertEvents(
  events: IEventPublisher,
  scanId: string,
  result: UpsertResult,
  dnsLog?: DnsActivityLog,
): void {
  const { device, isNew, changes, anomalies } = result;
  events.emit({ type: 'device.classified', payload: { scanId, device } });
  if (isNew) {
    events.emit({ type: 'device.new', payload: { scanId, device } });
  } else if (changes.length) {
    events.emit({ type: 'device.changed', payload: { scanId, device, changes } });
  }
  emitDeviceAnomalies(events, scanId, device, anomalies, dnsLog);
}
