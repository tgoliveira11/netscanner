export type CpeAccessSessionRow = {
  id: string;
  ip: string;
  port: number;
  tls: boolean;
  label: string | null;
  username: string;
  /** Encrypted or plaintext password at rest. */
  passwordEnc: string;
  via: 'direct' | 'pfsense-tunnel';
  autoLoginPending: boolean;
  createdAt: Date;
};

export interface ICpeAccessSessionStore {
  list(): Promise<CpeAccessSessionRow[]>;
  upsert(row: CpeAccessSessionRow): Promise<void>;
  updateAutoLogin(id: string, autoLoginPending: boolean): Promise<void>;
  delete(id: string): Promise<void>;
}
