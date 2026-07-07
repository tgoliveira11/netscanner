import { readFileSync } from 'node:fs';
import { OUI_TABLE } from './oui-data.js';

/**
 * Loads the bundled IEEE OUI registry (~39k vendors) from oui-db.json at runtime.
 * Read via fs (not `import`) so the huge dataset never enters TypeScript's type
 * graph. Falls back to the small curated table if the file is missing.
 */
export function loadOuiTable(): Record<string, string> {
  try {
    const url = new URL('./oui-db.json', import.meta.url);
    const raw = readFileSync(url, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, string>;
    // Merge curated overrides on top so friendly names win where we set them.
    return { ...parsed, ...OUI_TABLE };
  } catch {
    return { ...OUI_TABLE };
  }
}
