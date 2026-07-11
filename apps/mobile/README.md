# NetScanner Mobile (Fase D)

iOS/Android app that:

1. Discovers agents via mDNS / UDP beacon (`_netscanner._tcp`, port 4010).
2. **Aggregates** inventory from multiple agents (and optional cloud).
3. Runs a **limited stand-alone scan** when no agent is present (no root).

## Status

Library shell + aggregation helpers in `src/discovery.ts`. Wire Expo (`npx create-expo-app` merge) for UI, Zeroconf, and native ping/ARP modules.

```bash
pnpm --filter @netscanner/mobile typecheck
```
