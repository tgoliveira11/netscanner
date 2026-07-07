import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OuiLookup, loadOuiTable } from '@netscanner/kernel';
import { loadConfig, loadEnvFile, resolveConfigFilePath, resolveSnmpCommunities, parseWifiPorts, resolveSnmpV3, type AppConfig } from '@netscanner/config';
import { createLogger, type Logger } from '@netscanner/logger';
import {
  NodeCommandRunner,
  detectCapabilities,
  detectPrimaryCidr,
  listLocalInterfaces,
  listScanCidrs,
  type ScanCapabilities,
} from '@netscanner/os-abstraction';
import {
  DiscoverHostsUseCase,
  PingSweepProbe,
  ArpTableProbe,
  MdnsProbe,
  SsdpProbe,
  NetbiosProbe,
  LlmnrProbe,
  Ipv6NeighborProbe,
  PfSenseRestAdapter,
  FritzBoxHttpAdapter,
  SnmpArpLeaseSource,
  CompositeLeaseSource,
  DhcpSniffer,
  FingerbankClient,
  PassiveListeners,
  InMemoryPassiveSignalStore,
  HttpRouterScrapeAdapter,
  ProtocolProbe,
  MacDnsCacheProbe,
  MasscanProbe,
  type IHostProbe,
  type IRouterLeaseSource,
  type IDhcpFingerprintSource,
  type IDeviceFingerprintResolver,
  type IPassiveSignalStore,
} from '@netscanner/discovery';
import {
  FingerprintHostUseCase,
  NetworkEnricher,
  NmapScanner,
  TcpConnectScanner,
  SnmpEnricher,
  SnmpConnectionSource,
  CompositeConnectionSource,
  UnifiConnectionSource,
  OmadaConnectionSource,
  type SnmpV3Config,
} from '@netscanner/scanner';
import {
  ClassificationEngine,
  ClassifyDeviceUseCase,
  SecurityAnalyzer,
  defaultRules,
} from '@netscanner/classification';
import {
  ExportDevicesUseCase,
  GetDeviceUseCase,
  InMemoryDeviceRepository,
  InMemoryDhcpFingerprintStore,
  ListDevicesUseCase,
  PrismaDeviceRepository,
  PrismaDhcpFingerprintStore,
  PrismaPassiveSignalStore,
  UpdateDeviceMetaUseCase,
  UpsertDeviceUseCase,
  type IDeviceRepository,
  type IDhcpFingerprintStore,
} from '@netscanner/inventory';
import type { IConnectionSource } from '@netscanner/contracts';
import { InProcessEventBus } from './infrastructure/event-bus.js';
import { ScanSessionStore } from './application/scan-session.js';
import { RunScanUseCase } from './application/run-scan.use-case.js';
import { DeviceEnrichmentService } from './application/device-enrichment.service.js';
import { BackgroundWorker } from './application/background-worker.js';
import { createRuntimeSettings, type RuntimeSettingsService } from './application/runtime-settings.service.js';
import { LogRingBuffer } from './infrastructure/log-ring-buffer.js';

/** Fully assembled application graph handed to the HTTP/WS layer. */
export interface Container {
  config: AppConfig;
  logger: Logger;
  capabilities: ScanCapabilities;
  events: InProcessEventBus;
  sessions: ScanSessionStore;
  runScan: RunScanUseCase;
  listDevices: ListDevicesUseCase;
  getDevice: GetDeviceUseCase;
  updateMeta: UpdateDeviceMetaUseCase;
  exportDevices: ExportDevicesUseCase;
  leaseSource?: IRouterLeaseSource;
  dhcpSource?: IDhcpFingerprintSource;
  dhcpStore?: IDhcpFingerprintStore;
  passiveStore?: IPassiveSignalStore;
  passiveListeners?: PassiveListeners;
  backgroundWorker: BackgroundWorker;
  snmp: SnmpEnricher;
  fingerbank?: FingerbankClient;
  connectionSource?: IConnectionSource;
  logBuffer: LogRingBuffer;
  runtimeSettings: RuntimeSettingsService;
  agentLogPath: string;
  detectPrimaryCidr: () => string | null;
  listScanCidrs: () => string[];
  listInterfaces: typeof listLocalInterfaces;
}

/**
 * Resolve a relative SQLite `file:` URL to an absolute path anchored at the
 * inventory package, so persistence works no matter which directory the process
 * was launched from (pnpm runs scripts in the package dir).
 */
function resolveSqliteUrl(url: string): string {
  if (!url.startsWith('file:')) return url;
  const rel = url.slice('file:'.length);
  if (path.isAbsolute(rel)) return url;
  let dir = path.dirname(fileURLToPath(import.meta.url));
  while (dir !== path.dirname(dir) && !existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
    dir = path.dirname(dir);
  }
  return `file:${path.resolve(dir, 'services/inventory/prisma', rel)}`;
}

/** Attempt Prisma persistence; fall back to in-memory if the client isn't ready. */
async function buildRepository(config: AppConfig, logger: Logger): Promise<IDeviceRepository> {
  if (process.env.PERSISTENCE === 'memory') return new InMemoryDeviceRepository();
  try {
    const prismaSpecifier = '@prisma/client';
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prismaMod: any = await import(prismaSpecifier);
    const url = resolveSqliteUrl(config.DATABASE_URL);
    const prisma = new prismaMod.PrismaClient({ datasources: { db: { url } } });
    await prisma.$connect();
    logger.info('using Prisma persistence');
    return new PrismaDeviceRepository(prisma);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    const mustPersist =
      process.env.PERSISTENCE !== 'memory' &&
      (process.env.NODE_ENV === 'production' || config.NODE_ENV === 'production');
    if (mustPersist) {
      throw new Error(
        `Prisma persistence required in production but unavailable (${msg}). Run pnpm db:push.`,
      );
    }
    logger.warn({ error: msg }, 'Prisma unavailable (run `pnpm db:push`); falling back to in-memory storage');
    return new InMemoryDeviceRepository();
  }
}

async function buildDhcpFingerprintStore(
  config: AppConfig,
  logger: Logger,
): Promise<IDhcpFingerprintStore> {
  if (process.env.PERSISTENCE === 'memory') return new InMemoryDhcpFingerprintStore();
  try {
    const prismaSpecifier = '@prisma/client';
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prismaMod: any = await import(prismaSpecifier);
    const url = resolveSqliteUrl(config.DATABASE_URL);
    const prisma = new prismaMod.PrismaClient({ datasources: { db: { url } } });
    await prisma.$connect();
    logger.info('using Prisma DHCP fingerprint persistence');
    return new PrismaDhcpFingerprintStore(prisma);
  } catch (error) {
    logger.warn(
      { error: error instanceof Error ? error.message : error },
      'DHCP fingerprint Prisma unavailable; using in-memory store',
    );
    return new InMemoryDhcpFingerprintStore();
  }
}

async function buildPassiveSignalStore(
  config: AppConfig,
  logger: Logger,
): Promise<IPassiveSignalStore> {
  if (process.env.PERSISTENCE === 'memory') return new InMemoryPassiveSignalStore();
  try {
    const prismaSpecifier = '@prisma/client';
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prismaMod: any = await import(prismaSpecifier);
    const url = resolveSqliteUrl(config.DATABASE_URL);
    const prisma = new prismaMod.PrismaClient({ datasources: { db: { url } } });
    await prisma.$connect();
    const store = new PrismaPassiveSignalStore(prisma);
    await store.hydrate();
    logger.info('using Prisma passive signal persistence');
    return store;
  } catch (error) {
    logger.warn(
      { error: error instanceof Error ? error.message : error },
      'passive signal Prisma unavailable; using in-memory store',
    );
    return new InMemoryPassiveSignalStore();
  }
}

/**
 * Composition root: the single place where interfaces are bound to concrete
 * implementations. Nothing else in the codebase constructs infrastructure,
 * keeping the dependency graph pointing inward (Clean Architecture / DIP).
 */
export async function buildContainer(): Promise<Container> {
  const configPath = resolveConfigFilePath(process.cwd());
  loadEnvFile(configPath);
  const config = loadConfig();
  const logBuffer = new LogRingBuffer(500);
  const logger: Logger = createLogger('gateway', logBuffer.asStream());
  const agentLogPath = path.join(process.cwd(), 'agent.log');
  const runner = new NodeCommandRunner();
  const capabilities = await detectCapabilities(runner, config.DISABLE_NMAP);

  logger.info({ capabilities }, 'scan capabilities detected');

  const ping = new PingSweepProbe(runner);
  const arp = new ArpTableProbe(runner);

  const snmpCommunities = resolveSnmpCommunities(config);
  const snmpV3: SnmpV3Config | null = resolveSnmpV3(config);

  const enrichProbes: IHostProbe[] = [
    new MdnsProbe(),
    new SsdpProbe(),
    new NetbiosProbe(),
    new LlmnrProbe(),
    new Ipv6NeighborProbe(runner),
  ];
  if (config.PROTOCOL_PROBE_ENABLED) enrichProbes.push(new ProtocolProbe());
  if (config.MAC_DNS_CACHE_ENABLED) enrichProbes.push(new MacDnsCacheProbe(runner));

  const discover = new DiscoverHostsUseCase(
    [
      ping,
      arp,
      new MasscanProbe(runner, {
        enabled: config.MASSCAN_ENABLED,
        rate: config.MASSCAN_RATE,
      }),
      ...enrichProbes,
    ],
    logger,
  );
  const lightDiscover = new DiscoverHostsUseCase([ping, arp], logger);

  const fingerprint = new FingerprintHostUseCase(
    [
      new TcpConnectScanner(),
      new NmapScanner(runner, { elevated: capabilities.elevated, disabled: !capabilities.nmap }),
    ],
    logger,
  );

  const vendorLookup = new OuiLookup(loadOuiTable());
  logger.info({ ouiVendors: vendorLookup.size }, 'OUI vendor database loaded');
  const engine = new ClassificationEngine(defaultRules());
  const classify = new ClassifyDeviceUseCase(engine, vendorLookup, new SecurityAnalyzer());

  const repo = await buildRepository(config, logger);
  const upsert = new UpsertDeviceUseCase(repo);
  const dhcpStore = await buildDhcpFingerprintStore(config, logger);
  const passiveStore = await buildPassiveSignalStore(config, logger);
  const enricher = new NetworkEnricher();
  const snmp = new SnmpEnricher(runner, logger, snmpCommunities, config.SNMP_ENABLED, snmpV3);

  const connectionSources: IConnectionSource[] = [];
  if (config.SNMP_SWITCH_HOST && config.SNMP_ENABLED) {
    connectionSources.push(
      new SnmpConnectionSource(
        runner,
        logger,
        config.SNMP_SWITCH_HOST,
        snmpCommunities.join(','),
        parseWifiPorts(config.SNMP_WIFI_PORTS),
        true,
        snmpV3,
      ),
    );
    logger.info({ switch: config.SNMP_SWITCH_HOST }, 'SNMP BRIDGE-MIB connection source enabled');
  }
  if (config.UNIFI_URL && config.UNIFI_API_KEY) {
    connectionSources.push(
      new UnifiConnectionSource(config.UNIFI_URL, config.UNIFI_API_KEY, config.UNIFI_SITE, logger),
    );
    logger.info({ url: config.UNIFI_URL }, 'UniFi connection source enabled');
  }
  if (config.OMADA_URL && config.OMADA_CLIENT_ID && config.OMADA_CLIENT_SECRET && config.OMADA_SITE_ID) {
    connectionSources.push(
      new OmadaConnectionSource(
        config.OMADA_URL,
        config.OMADA_CLIENT_ID,
        config.OMADA_CLIENT_SECRET,
        config.OMADA_SITE_ID,
        logger,
      ),
    );
    logger.info({ url: config.OMADA_URL }, 'Omada connection source enabled');
  }
  let connectionSource: IConnectionSource | undefined;
  if (connectionSources.length === 1) connectionSource = connectionSources[0];
  else if (connectionSources.length > 1) connectionSource = new CompositeConnectionSource(connectionSources);

  const leaseSources: IRouterLeaseSource[] = [];
  if (config.PFSENSE_URL && config.PFSENSE_API_KEY) {
    leaseSources.push(
      new PfSenseRestAdapter(
        {
          baseUrl: config.PFSENSE_URL,
          apiKey: config.PFSENSE_API_KEY,
          leasesPath: config.PFSENSE_LEASES_PATH,
          insecureTls: config.PFSENSE_INSECURE_TLS,
        },
        logger,
      ),
    );
    logger.info({ url: config.PFSENSE_URL }, 'pfSense lease integration enabled');
  }
  if (config.ROUTER_SNMP_HOST && config.SNMP_ENABLED) {
    leaseSources.push(
      new SnmpArpLeaseSource(runner, logger, config.ROUTER_SNMP_HOST, snmpCommunities, true),
    );
    logger.info({ host: config.ROUTER_SNMP_HOST }, 'SNMP ARP lease source enabled');
  }
  if (config.ROUTER_SCRAPE_URL && config.ROUTER_SCRAPE_KIND) {
    leaseSources.push(
      new HttpRouterScrapeAdapter(
        {
          baseUrl: config.ROUTER_SCRAPE_URL,
          kind: config.ROUTER_SCRAPE_KIND,
          username: config.ROUTER_SCRAPE_USER,
          password: config.ROUTER_SCRAPE_PASSWORD,
          insecureTls: true,
        },
        logger,
      ),
    );
    logger.info({ url: config.ROUTER_SCRAPE_URL, kind: config.ROUTER_SCRAPE_KIND }, 'router HTTP scrape enabled');
  }
  if (config.FRITZBOX_URL) {
    leaseSources.push(
      new FritzBoxHttpAdapter(
        {
          baseUrl: config.FRITZBOX_URL,
          username: config.FRITZBOX_USER,
          password: config.FRITZBOX_PASSWORD,
          insecureTls: true,
        },
        logger,
      ),
    );
    logger.info({ url: config.FRITZBOX_URL }, 'Fritz!Box lease integration enabled');
  }
  let leaseSource: IRouterLeaseSource | undefined;
  if (leaseSources.length === 1) leaseSource = leaseSources[0];
  else if (leaseSources.length > 1) leaseSource = new CompositeLeaseSource(leaseSources, logger);

  let fingerbank: FingerbankClient | undefined;
  if (config.FINGERBANK_API_KEY) {
    fingerbank = new FingerbankClient(config.FINGERBANK_API_KEY, logger);
    logger.info('Fingerbank device identification enabled');
  }

  let dhcpSource: IDhcpFingerprintSource | undefined;
  const ifaces = listLocalInterfaces();
  const primaryIface = ifaces.find((i) => i.cidr === detectPrimaryCidr()) ?? ifaces[0];
  if (config.DHCP_SNIFF && capabilities.elevated) {
    dhcpSource = new DhcpSniffer(logger, {
      iface: primaryIface?.name ?? 'en0',
      persist: async (fp) =>
        dhcpStore.save({
          mac: fp.mac,
          fingerprint: fp.fingerprint,
          vendorClass: fp.vendorClass,
          hostname: fp.hostname,
          capturedAt: new Date().toISOString(),
        }),
      hydrate: () => dhcpStore.loadAll(),
    });
  }

  const enrichment = new DeviceEnrichmentService({
    classify,
    upsert,
    repo,
    dhcpSource,
    fingerbank,
    passiveStore,
    snmp,
    connectionSource,
  });

  let passiveListeners: PassiveListeners | undefined;
  if (config.PASSIVE_LISTENERS_ENABLED) {
    passiveListeners = new PassiveListeners({
      store: passiveStore,
      logger,
      runner,
      iface: primaryIface?.name ?? 'en0',
      lldpEnabled: config.LLDP_PASSIVE_ENABLED && capabilities.elevated,
      lldpStream: config.LLDP_STREAM_ENABLED,
      dnsEnabled: config.PASSIVE_DNS_ENABLED,
      igmpEnabled: config.PASSIVE_IGMP_ENABLED,
      dhcpv6Enabled: config.PASSIVE_DHCPV6_ENABLED,
      elevated: capabilities.elevated,
    });
  }

  const events = new InProcessEventBus();
  const sessions = new ScanSessionStore();
  const runScan = new RunScanUseCase({
    discover,
    lightDiscover,
    fingerprint,
    enricher,
    enrichment,
    leaseSource,
    dhcpSource,
    fingerbank,
    passiveStore,
    snmp,
    connectionSource,
    classify,
    upsert,
    repo,
    sessions,
    events,
    logger,
    config,
    elevated: capabilities.elevated,
  });

  const backgroundWorker = new BackgroundWorker({
    config,
    logger,
    enrichment,
    repo,
    lightDiscover,
    runScan,
    sessions,
    events,
    detectPrimaryCidr,
    dhcpSource,
    passiveStore,
  });

  const listDevices = new ListDevicesUseCase(repo);
  const getDevice = new GetDeviceUseCase(repo);
  const updateMeta = new UpdateDeviceMetaUseCase(repo);
  const exportDevices = new ExportDevicesUseCase(repo);

  const container: Container = {
    config,
    logger,
    capabilities,
    events,
    sessions,
    runScan,
    listDevices,
    getDevice,
    updateMeta,
    exportDevices,
    leaseSource,
    dhcpSource,
    dhcpStore,
    passiveStore,
    passiveListeners,
    backgroundWorker,
    snmp,
    fingerbank,
    connectionSource,
    logBuffer,
    runtimeSettings: null as unknown as RuntimeSettingsService,
    agentLogPath,
    detectPrimaryCidr,
    listScanCidrs: () => listScanCidrs(config.SCAN_CIDRS),
    listInterfaces: listLocalInterfaces,
  };
  container.runtimeSettings = createRuntimeSettings(container, configPath);
  return container;
}
