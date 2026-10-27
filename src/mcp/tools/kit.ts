import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Principal } from '../../auth/grants.js';
import type { PerchContext } from '../../context.js';

/**
 * Shared shapes for tool modules (src/mcp/tools/*.ts). Each module registers its own MCP tools and declares
 * their names, so createMcpServer only wires modules together.
 */

/** The shared audit runner of createMcpServer: session guard, grant re-resolution, audit, error mapping. */
export type ToolRunner = (name: string, args: unknown, fn: (p: Principal) => Promise<unknown>) => Promise<CallToolResult>;

export interface ToolModule {
  /** Read tools offered to the read-only operator (part of TOOL_NAMES). */
  readTools: readonly string[];
  /** Tools offered only to client grants holding the matching capability (part of WRITE_TOOL_NAMES). */
  writeTools: readonly string[];
  /** Tools whose service audits itself (e.g. through the send workflow); the runner records only denials. */
  selfAudited: readonly string[];
  /** Writes whose attempt the runner records durably BEFORE the provider call (fail closed). */
  auditedWrites: readonly string[];
  register(server: McpServer, ctx: PerchContext, principal: Principal, operator: boolean, tool: ToolRunner): void;
}

export const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
export const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } as const;
/** Sending, sharing and moving to trash cannot be silently undone. */
export const DESTRUCTIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } as const;
