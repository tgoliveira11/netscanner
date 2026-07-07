// node-ssdp is CommonJS; default export holds Client/Server under Node ESM.
import * as NodeSsdp from 'node-ssdp';

const ssdpMod = (NodeSsdp as unknown as { default?: typeof NodeSsdp }).default ?? NodeSsdp;

export const SsdpClient = ssdpMod.Client;
