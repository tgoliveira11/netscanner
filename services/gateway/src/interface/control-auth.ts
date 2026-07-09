import type { FastifyRequest } from 'fastify';
import type { AppConfig } from '@netscanner/config';

/** Control plane requires bearer only when CONTROL_TOKEN is explicitly set.
 *  AGENT_CONTROL_TOKEN is for CLI /api/agent/restart — not dashboard control APIs. */
export function authorizeControl(request: FastifyRequest, config: AppConfig): boolean {
  const token = config.CONTROL_TOKEN?.trim();
  if (!token) return true;
  return request.headers.authorization === `Bearer ${token}`;
}
