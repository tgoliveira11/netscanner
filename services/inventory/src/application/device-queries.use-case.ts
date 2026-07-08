import type { Device } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository } from '../domain/device-repository.js';
import { toPublicDevice, type StoredDevice } from '../domain/device-public.js';

/** Read-side use cases (queries) kept separate from the write side (CQRS-lite). */
export class ListDevicesUseCase {
  constructor(private readonly repo: IDeviceRepository) {}
  execute(filter?: DeviceFilter): Promise<Device[]> {
    return this.repo.list(filter);
  }
}

export class GetDeviceUseCase {
  constructor(private readonly repo: IDeviceRepository) {}
  execute(id: string): Promise<Device | null> {
    return this.repo.findById(id);
  }
}

export interface UpdateMetaInput {
  id: string;
  label?: string | null;
  notes?: string | null;
  routerScrapeUser?: string | null;
  routerScrapePassword?: string | null;
}

/** Updates user-owned metadata (label/notes/router credentials) without touching scan data. */
export class UpdateDeviceMetaUseCase {
  constructor(private readonly repo: IDeviceRepository) {}

  async execute(input: UpdateMetaInput): Promise<Device | null> {
    const existing = await this.repo.findStoredById(input.id);
    if (!existing) return null;

    const password =
      input.routerScrapePassword === undefined
        ? existing.routerScrapePassword ?? null
        : input.routerScrapePassword;

    const updated: StoredDevice = {
      ...existing,
      label: input.label === undefined ? existing.label : input.label,
      notes: input.notes === undefined ? existing.notes : input.notes,
      routerScrapeUser:
        input.routerScrapeUser === undefined ? existing.routerScrapeUser ?? null : input.routerScrapeUser,
      routerScrapePassword: password,
    };
    await this.repo.save(updated);
    return toPublicDevice(updated);
  }
}
