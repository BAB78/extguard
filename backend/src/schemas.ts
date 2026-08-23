import { z } from 'zod';

export const checkoutSchema = z.object({
  email: z.string().trim().email().max(254).transform((email) => email.toLowerCase()),
  seats: z.number().int().min(1).max(500),
}).strict();

export const checkoutSessionSchema = z.object({
  session_id: z.string().regex(/^cs_(test|live)_[A-Za-z0-9]+$/),
}).strict();

export const activationSchema = z.object({
  licenseKey: z.string().trim().regex(/^EXTG_[A-Za-z0-9_-]{40,60}$/),
  machineId: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

const findingSchema = z.object({
  category: z.string().trim().min(1).max(80).regex(/^[a-zA-Z0-9_.:-]+$/),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  count: z.number().int().min(1).max(1_000_000),
}).strict();

const extensionSchema = z.object({
  id: z.string().trim().min(3).max(255).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]+$/),
  name: z.string().trim().min(1).max(200),
  riskScore: z.number().int().min(0).max(100),
  findings: z.array(findingSchema).max(100),
}).strict();

export const reportSchema = z.object({
  schemaVersion: z.literal(1),
  machineId: z.string().regex(/^[a-f0-9]{64}$/),
  snapshotAt: z.string().datetime({ offset: true }),
  summary: z.object({
    extensionsScanned: z.number().int().min(0).max(10_000),
    findings: z.number().int().min(0).max(1_000_000),
    critical: z.number().int().min(0).max(1_000_000),
    high: z.number().int().min(0).max(1_000_000),
    medium: z.number().int().min(0).max(1_000_000),
    low: z.number().int().min(0).max(1_000_000),
    info: z.number().int().min(0).max(1_000_000),
  }).strict(),
  extensions: z.array(extensionSchema).max(10_000),
}).strict().superRefine((report, context) => {
  if (report.summary.extensionsScanned !== report.extensions.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['summary', 'extensionsScanned'],
      message: 'must equal extensions.length',
    });
  }
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const extension of report.extensions) {
    for (const finding of extension.findings) severityCounts[finding.severity] += finding.count;
  }
  const findingCount = Object.values(severityCounts).reduce((sum, count) => sum + count, 0);
  if (report.summary.findings !== findingCount) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['summary', 'findings'],
      message: 'must equal the sum of extension finding counts',
    });
  }
  for (const severity of Object.keys(severityCounts) as Array<keyof typeof severityCounts>) {
    if (report.summary[severity] !== severityCounts[severity]) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['summary', severity],
        message: `must equal the ${severity} finding count`,
      });
    }
  }
  if (new Date(report.snapshotAt).getTime() > Date.now() + 5 * 60 * 1000) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['snapshotAt'],
      message: 'must not be more than five minutes in the future',
    });
  }
});

export const reportQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().min(1).max(1024).optional(),
}).strict();
