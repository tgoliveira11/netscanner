import type { FastifyRequest } from 'fastify';
import type { AppConfig } from '@netscanner/config';

/** Localhost-only agent control (restart). Token optional but recommended. */
export function authorizeAgentControl(request: FastifyRequest, config: AppConfig): boolean {
  const token = config.AGENT_CONTROL_TOKEN?.trim();
  if (!token) return true;
  const auth = request.headers.authorization;
  return auth === `Bearer ${token}`;
}
