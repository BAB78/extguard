export type SubscriptionStatus =
  | 'active'
  | 'trialing'
  | 'past_due'
  | 'unpaid'
  | 'canceled'
  | 'incomplete'
  | 'incomplete_expired'
  | 'paused';

export const isPaidStatus = (status: SubscriptionStatus): boolean =>
  status === 'active' || status === 'trialing';

export interface LicenseMaterial {
  keyHash: string;
  keyCiphertext: string;
}

export interface LicenseRecord {
  id: string;
  email: string;
  status: SubscriptionStatus;
  seats: number;
  activeSeats: number;
  stripeCustomerId: string;
  stripeSubscriptionId: string;
  stripeCheckoutSessionId: string | null;
  keyHash: string;
  keyCiphertext: string;
  currentPeriodEnd: Date | null;
}

export interface ProvisionLicenseInput {
  email: string;
  status: SubscriptionStatus;
  seats: number;
  stripeCustomerId: string;
  stripeSubscriptionId: string;
  stripeCheckoutSessionId?: string;
  currentPeriodEnd: Date | null;
}

export type BillingMutation =
  | { kind: 'none' }
  | ({ kind: 'upsert' } & ProvisionLicenseInput)
  | {
      kind: 'update';
      stripeSubscriptionId: string;
      stripeCustomerId?: string;
      status: SubscriptionStatus;
      seats?: number;
      currentPeriodEnd?: Date | null;
    };

export interface BillingWebhook {
  id: string;
  type: string;
  createdAt: Date;
  mutation: BillingMutation;
}

export type ActivationResult =
  | { outcome: 'ok'; activationId: string; machineHash: string; license: LicenseRecord }
  | { outcome: 'invalid' }
  | { outcome: 'inactive' }
  | { outcome: 'seat_limit' };

export interface AuthenticatedActivation {
  activationId: string;
  machineHash: string;
  license: LicenseRecord;
}

export interface StoredReport {
  id: string;
  schemaVersion: 1;
  machineId: string;
  snapshotAt: string;
  summary: {
    extensionsScanned: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  extensions: Array<{
    id: string;
    name: string;
    riskScore: number;
    findings: Array<{
      category: string;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
      count: number;
    }>;
  }>;
  receivedAt: string;
}

export interface ReportInput {
  schemaVersion: 1;
  machineId: string;
  snapshotAt: string;
  summary: StoredReport['summary'];
  extensions: StoredReport['extensions'];
}

export interface ReportPage {
  reports: StoredReport[];
  nextCursor: string | null;
}
