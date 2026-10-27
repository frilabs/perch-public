// Type declarations for scripts/licenses.mjs (kept as plain JS so it runs on Node without a build step).

type LicenseShape = 'MIT' | 'MIT-0' | 'MIT-truncated' | 'ISC' | 'BSD-2-Clause' | 'BSD-3-Clause';
/** A full template body, the same followed by extra material (`<id>+extra`), or UNKNOWN. */
export type LicenseClass = LicenseShape | `${LicenseShape}+extra` | 'UNKNOWN';

export interface ProductionPackage {
  key: string;
  name: string;
  version: string;
  declared: string | null;
  sourceUrl: string | null;
  resolved: string | null;
  integrity: string | null;
  paths: string[];
}

export interface DevelopmentPackage {
  key: string;
  name: string;
  version: string;
  license: string | null;
  optional: boolean;
  resolved: string | null;
  paths: string[];
}

export interface Inventory {
  lockfileVersion: number;
  production: ProductionPackage[];
  development: DevelopmentPackage[];
  errors: string[];
}

export interface LicensesResult {
  ok: boolean;
  errors: string[];
  production?: number;
  locations?: number;
  development?: number;
  licenses?: [string, number][];
}

export const OUTPUTS: { notices: string; development: string };
export function classifyLicenseText(text: string): LicenseClass;
export function normalizeRepositoryUrl(repository: unknown): string | null;
export function collectInventory(root: string): Inventory;
export function runLicenses(root: string, mode: 'check' | 'generate'): LicensesResult;
