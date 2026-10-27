import { z } from 'zod';
import { REQUEST_ID_PATTERN } from '../../mail/workflow.js';
import { microsoftSessionOperations, sessionCapability } from '../../microsoft/session/service.js';
import { DESTRUCTIVE, READ_ONLY, type ToolModule } from './kit.js';

const operations = Object.entries(microsoftSessionOperations);
export const microsoftSessionToolName = (operation: string): string => `microsoft_${operation.replace('.', '_').replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)}`;
const STATUS = 'microsoft_session_write_status';
const writeOperations = operations.filter(([, operation]) => operation.mode !== 'read');
const WRITE_NOTE = ' Requires a client write grant and local service write opt-in. Use a fresh requestId for each intended operation and reuse it only for the identical operation. Replays never write again. An indeterminate outcome may include partial changes: inspect the resource before using a new requestId. Full results are returned once; the ledger retains only status and a safe resource ID.';
const requestId = z.string().min(8).max(128).regex(REQUEST_ID_PATTERN).describe('Stable idempotency key for this exact intended write');

export const microsoftSessionTools: ToolModule = {
  readTools: operations.filter(([, operation]) => operation.mode === 'read').map(([name]) => microsoftSessionToolName(name)),
  writeTools: [...writeOperations.map(([name]) => microsoftSessionToolName(name)), STATUS],
  selfAudited: writeOperations.map(([name]) => microsoftSessionToolName(name)),
  auditedWrites: [],
  register(server, ctx, principal, operator, tool) {
    for (const [name, operation] of operations) {
      const read = operation.mode === 'read';
      if (!(read && operator) && !principal.capabilities.has(sessionCapability(operation))) continue;
      if (!read && operator) continue;
      const prefix = operation.service === 'teams' ? 'msteams' : operation.service === 'calendar' ? 'mscalendar' : 'msfiles';
      const accountId = z.string().regex(new RegExp(`^${prefix}-[a-f0-9]{8}$`)).describe('Explicit Microsoft service account ID from perch_list_accounts');
      // safeExtend retains the adapter's cross-field validation in Zod 4.
      const schema = operation.schema.safeExtend({ accountId, ...(!read ? { requestId } : {}) });
      const toolName = microsoftSessionToolName(name);
      server.registerTool(toolName, { description: operation.description + (read ? '' : WRITE_NOTE), inputSchema: schema, annotations: read ? READ_ONLY : DESTRUCTIVE },
        (args) => tool(toolName, args, (p) => ctx.microsoftSession.execute(p, name, args)));
    }
    const allowedWrites = writeOperations.filter(([, operation]) => !operator && principal.capabilities.has(sessionCapability(operation))).map(([name]) => name);
    if (allowedWrites.length) server.registerTool(STATUS, {
      description: 'Read the recorded outcome of your earlier Microsoft session write without making a Microsoft request. Full result content is not retained.',
      inputSchema: z.object({ accountId: z.string().regex(/^(msteams|mscalendar|msfiles)-[a-f0-9]{8}$/), operation: z.enum(allowedWrites as [string, ...string[]]), requestId }).strict(), annotations: READ_ONLY,
    }, (args) => tool(STATUS, args, (p) => ctx.microsoftSession.writeStatus(p, args)));
  },
};
