/** Domains queried in normal browsing — not a device hostname. */
const DNS_NOISE_RE =
  /(?:^|\.)((google|gstatic|googleusercontent|googleapis|gvt\d|1e100|apple|icloud|apple-dns|mzstatic|cursor|brave|github|githubusercontent|linkedin|licdn|cloudflare|amazonaws|akamai|fastly|fbcdn|microsoft|office|live|azure|doubleclick|googlesyndication|google-analytics|fonts)\.(com|net|org|io|sh|ai))$/i;

const QUERY_RE = /(\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.\d+:.*\? ([\w.-]+)\./;

export function isPrivateLanIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

/** Parse a tcpdump DNS query line into LAN client IP + queried domain. */
export function parseDnsTcpdumpLine(line: string): { clientIp: string; query: string } | null {
  const q = QUERY_RE.exec(line);
  if (!q) return null;

  const left = q[1]!;
  const right = q[2]!;
  const clientIp = isPrivateLanIp(left) ? left : isPrivateLanIp(right) ? right : null;
  if (!clientIp) return null;

  const query = q[3]!.replace(/\.$/, '').toLowerCase();
  if (query.length < 2 || /^(localhost|local)$/i.test(query)) return null;
  if (DNS_NOISE_RE.test(query)) return null;

  return { clientIp, query };
}
