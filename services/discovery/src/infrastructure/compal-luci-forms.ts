const MESH_ENABLE_FIELD = 'cbid.meshwifi.basic.enable';
const MESH_SECTION_FIELD = 'cbi.cbe.meshwifi.basic.enable';

/** Parse Compal mesh Wi‑Fi enable checkbox from LuCI HTML. */
export function parseCompalMeshEnabled(html: string): boolean | null {
  if (!/meshwifi|mesh_wifi/i.test(html)) return null;
  const tag = html.match(/<input[^>]*name=["']cbid\.meshwifi\.basic\.enable["'][^>]*>/i)?.[0];
  if (!tag) return null;
  if (/checked/i.test(tag)) return true;
  if (/type=["']checkbox["']/i.test(tag)) return false;
  return null;
}

/** Build LuCI CBI POST body to toggle mesh Wi‑Fi. */
export function buildCompalMeshForm(html: string, enabled: boolean): Record<string, string> {
  const fields = parseLuciCbiFields(html);
  fields['cbi.submit'] = '1';
  fields[MESH_SECTION_FIELD] = '1';
  if (enabled) fields[MESH_ENABLE_FIELD] = '1';
  else delete fields[MESH_ENABLE_FIELD];
  const apply = findSubmitValue(html, 'cbi.apply') ?? findSubmitValue(html, 'cbi.save') ?? 'Apply';
  fields['cbi.apply'] = apply;
  return fields;
}

/** @deprecated Compal LuCI reboot uses GET ?reboot=1 — see LuciClient.rebootCompal(). */
export function buildCompalRebootForm(html: string): Record<string, string> {
  const fields: Record<string, string> = { 'cbi.submit': '1' };
  const reboot =
    findSubmitValue(html, 'reboot') ??
    findSubmitValue(html, 'cbi.apply') ??
    findSubmitValue(html, 'cbi.button') ??
    'Reboot';
  if (html.match(/name=["']reboot["']/i)) fields.reboot = reboot;
  else fields['cbi.apply'] = reboot;
  return fields;
}

function parseLuciCbiFields(html: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const tag of html.match(/<input[^>]+>/gi) ?? []) {
    const name = tag.match(/name=["']([^"']+)["']/i)?.[1];
    if (!name || name === 'controler-status') continue;
    const type = tag.match(/type=["']([^"']+)["']/i)?.[1]?.toLowerCase() ?? 'text';
    if (type === 'radio' || type === 'button') continue;
    if (type === 'submit') continue;
    if (type === 'checkbox') {
      if (/checked/i.test(tag)) fields[name] = tag.match(/value=["']([^"']*)["']/i)?.[1] ?? '1';
      continue;
    }
    fields[name] = tag.match(/value=["']([^"']*)["']/i)?.[1] ?? '';
  }
  return fields;
}

function findSubmitValue(html: string, name: string): string | undefined {
  const re = new RegExp(`<input[^>]*name=["']${name}["'][^>]*>`, 'i');
  const tag = html.match(re)?.[0];
  if (!tag) return undefined;
  return tag.match(/value=["']([^"']*)["']/i)?.[1];
}
