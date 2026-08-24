import { randomUUID } from 'node:crypto';
import {
  ActivationResult,
  AuthenticatedActivation,
  BillingWebhook,
  isPaidStatus,
  LicenseMaterial,
  LicenseRecord,
  ProvisionLicenseInput,
  ReportInput,
  ReportPage,
  StoredReport,
} from './domain';

export interface Repository {
  health(): Promise<void>;
  provisionLicense(input: ProvisionLicenseInput, material: LicenseMaterial): Promise<LicenseRecord>;
  findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null>;
  applyWebhook(webhook: BillingWebhook, material: LicenseMaterial): Promise<boolean>;
  activateLicense(keyHash: string, machineHash: string): Promise<ActivationResult>;
  getAuthenticatedActivation(
    licenseId: string,
    activationId: string,
    machineHash: string,
  ): Promise<AuthenticatedActivation | null>;
  deactivateActivation(licenseId: string, activationId: string): Promise<boolean>;
  createReport(auth: AuthenticatedActivation, input: ReportInput): Promise<StoredReport>;
  listReports(licenseId: string, limit: number, cursor: string | null): Promise<ReportPage>;
  close(): Promise<void>;
}

interface MutableActivation {
  id: string;
  licenseId: string;
  machineHash: string;
  active: boolean;
}

function cloneLicense(license: LicenseRecord, activeSeats: number): LicenseRecord {
  return {
    ...license,
    activeSeats,
    currentPeriodEnd: license.currentPeriodEnd ? new Date(license.currentPeriodEnd) : null,
  };
}

/** A deterministic, dependency-free repository used by API tests. Production never selects it. */
export class MemoryRepository implements Repository {
  private readonly licenses = new Map<string, LicenseRecord>();
  private readonly processedEvents = new Set<string>();
  private readonly activations = new Map<string, MutableActivation>();
  private readonly reports: Array<StoredReport & { licenseId: string }> = [];

  async health(): Promise<void> {}

  async provisionLicense(input: ProvisionLicenseInput, material: LicenseMaterial): Promise<LicenseRecord> {
    const existing = [...this.licenses.values()].find(
      (license) => license.stripeSubscriptionId === input.stripeSubscriptionId
        || (input.stripeCheckoutSessionId
          && license.stripeCheckoutSessionId === input.stripeCheckoutSessionId),
    );
    if (existing) {
      Object.assign(existing, {
        email: input.email.toLowerCase(),
        status: input.status,
        seats: input.seats,
        stripeCustomerId: input.stripeCustomerId,
        stripeSubscriptionId: input.stripeSubscriptionId,
        stripeCheckoutSessionId: input.stripeCheckoutSessionId ?? existing.stripeCheckoutSessionId,
        currentPeriodEnd: input.currentPeriodEnd,
      });
      return this.withSeatCount(existing);
    }

    const license: LicenseRecord = {
      id: randomUUID(),
      email: input.email.toLowerCase(),
      status: input.status,
      seats: input.seats,
      activeSeats: 0,
      stripeCustomerId: input.stripeCustomerId,
      stripeSubscriptionId: input.stripeSubscriptionId,
      stripeCheckoutSessionId: input.stripeCheckoutSessionId ?? null,
      keyHash: material.keyHash,
      keyCiphertext: material.keyCiphertext,
      currentPeriodEnd: input.currentPeriodEnd,
    };
    this.licenses.set(license.id, license);
    return this.withSeatCount(license);
  }

  async findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null> {
    const license = [...this.licenses.values()].find(
      (candidate) => candidate.stripeCheckoutSessionId === sessionId,
    );
    return license ? this.withSeatCount(license) : null;
  }

  async applyWebhook(webhook: BillingWebhook, material: LicenseMaterial): Promise<boolean> {
    if (this.processedEvents.has(webhook.id)) return false;
    if (webhook.mutation.kind === 'upsert') {
      await this.provisionLicense(webhook.mutation, material);
    } else if (webhook.mutation.kind === 'update') {
      const mutation = webhook.mutation;
      const license = [...this.licenses.values()].find(
        (candidate) => candidate.stripeSubscriptionId === mutation.stripeSubscriptionId,
      );
      if (license) {
        license.status = mutation.status;
        if (mutation.seats !== undefined) license.seats = mutation.seats;
        if (mutation.currentPeriodEnd !== undefined) {
          license.currentPeriodEnd = mutation.currentPeriodEnd;
        }
        if (mutation.stripeCustomerId) {
          license.stripeCustomerId = mutation.stripeCustomerId;
        }
      }
    }
    this.processedEvents.add(webhook.id);
    return true;
  }

  async activateLicense(keyHash: string, machineHash: string): Promise<ActivationResult> {
    const license = [...this.licenses.values()].find((candidate) => candidate.keyHash === keyHash);
    if (!license) return { outcome: 'invalid' };
    if (!isPaidStatus(license.status)) return { outcome: 'inactive' };

    const existing = [...this.activations.values()].find(
      (activation) => activation.licenseId === license.id && activation.machineHash === machineHash,
    );
    if (existing?.active) {
      return {
        outcome: 'ok',
        activationId: existing.id,
        machineHash,
        license: this.withSeatCount(license),
      };
    }
    if (this.activeSeats(license.id) >= license.seats) return { outcome: 'seat_limit' };

    const activation = existing ?? {
      id: randomUUID(),
      licenseId: license.id,
      machineHash,
      active: false,
    };
    activation.active = true;
    this.activations.set(activation.id, activation);
    return {
      outcome: 'ok',
      activationId: activation.id,
      machineHash,
      license: this.withSeatCount(license),
    };
  }

  async getAuthenticatedActivation(
    licenseId: string,
    activationId: string,
    machineHash: string,
  ): Promise<AuthenticatedActivation | null> {
    const license = this.licenses.get(licenseId);
    const activation = this.activations.get(activationId);
    if (!license || !activation || !activation.active || !isPaidStatus(license.status)) return null;
    if (activation.licenseId !== licenseId || activation.machineHash !== machineHash) return null;
    return { activationId, machineHash, license: this.withSeatCount(license) };
  }

  async deactivateActivation(licenseId: string, activationId: string): Promise<boolean> {
    const activation = this.activations.get(activationId);
    if (!activation || activation.licenseId !== licenseId || !activation.active) return false;
    activation.active = false;
    return true;
  }

  async createReport(auth: AuthenticatedActivation, input: ReportInput): Promise<StoredReport> {
    const report: StoredReport & { licenseId: string } = {
      id: randomUUID(),
      ...structuredClone(input),
      licenseId: auth.license.id,
      receivedAt: new Date().toISOString(),
    };
    this.reports.push(report);
    const { licenseId: _licenseId, ...stored } = report;
    return stored;
  }

  async listReports(licenseId: string, limit: number, cursor: string | null): Promise<ReportPage> {
    const offset = cursor ? Number.parseInt(Buffer.from(cursor, 'base64url').toString('utf8'), 10) : 0;
    const reports = this.reports
      .filter((report) => report.licenseId === licenseId)
      .sort((left, right) => right.receivedAt.localeCompare(left.receivedAt));
    const page = reports.slice(offset, offset + limit);
    return {
      reports: page.map(({ licenseId: _licenseId, ...report }) => structuredClone(report)),
      nextCursor: offset + limit < reports.length
        ? Buffer.from(String(offset + limit)).toString('base64url')
        : null,
    };
  }

  async close(): Promise<void> {}

  private activeSeats(licenseId: string): number {
    return [...this.activations.values()].filter(
      (activation) => activation.licenseId === licenseId && activation.active,
    ).length;
  }

  private withSeatCount(license: LicenseRecord): LicenseRecord {
    return cloneLicense(license, this.activeSeats(license.id));
  }
}
