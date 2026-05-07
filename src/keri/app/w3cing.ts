import { SignifyClient } from './clienting.ts';
import { SignedReplyEnvelope } from './signaling.ts';
import { decodeBase64Url } from '../core/base64.ts';

export const W3C_SIGNING_ROUTE = '/w3c/signing/request';
export const W3C_REQUEST_DATA_INTEGRITY_PROOF = 'data_integrity_proof';
export const W3C_REQUEST_VC_JWT = 'vc_jwt';

export const W3C_DEDUPE_IN_FLIGHT = 'in_flight';
export const W3C_DEDUPE_SUBMITTED = 'submitted';
export const W3C_DEDUPE_COMPLETE = 'complete';
export const W3C_DEDUPE_FAILED = 'failed';
export const W3C_DEDUPE_REJECTED = 'rejected';
export const W3C_DEDUPE_TERMINAL_RETENTION_MS = 10 * 60 * 1000;
export const W3C_DEDUPE_IN_FLIGHT_RETENTION_MS = 10 * 60 * 1000;

const W3C_DEDUPE_DB_NAME = 'signify-w3c-projection';
const W3C_DEDUPE_STORE_NAME = 'requestDedupe';

type MaybePromise<T> = T | Promise<T>;

export type W3CProjectionDedupeStatus =
    | typeof W3C_DEDUPE_IN_FLIGHT
    | typeof W3C_DEDUPE_SUBMITTED
    | typeof W3C_DEDUPE_COMPLETE
    | typeof W3C_DEDUPE_FAILED
    | typeof W3C_DEDUPE_REJECTED;

const W3C_TERMINAL_DEDUPE_STATUSES = new Set<W3CProjectionDedupeStatus>([
    W3C_DEDUPE_COMPLETE,
    W3C_DEDUPE_FAILED,
    W3C_DEDUPE_REJECTED,
]);

export interface W3CVerifier {
    id: string;
    label: string;
    kind: string;
    verifyUrl: string;
    healthUrl?: string | null;
}

export interface W3CProjectionSession {
    d: string;
    aid: string;
    name: string;
    credentialSaid: string;
    issuerDid: string;
    verifierId: string;
    state: string;
    created: string;
    updated: string;
    expires: string;
    proofRequest?: string | null;
    jwtRequest?: string | null;
    verifierStatus?: number | null;
    verifierResponse?: unknown;
    error?: string | null;
}

export interface W3CSigningRequest {
    d: string;
    session: string;
    type: string;
    kind: string;
    agent: string;
    aid: string;
    name: string;
    credentialSaid: string;
    signingInputB64: string;
    encoding: 'base64url';
    verificationMethod: string;
    created: string;
    expires: string;
    state?: string;
    lastSignaled?: string | null;
    error?: string | null;
    envelope?: SignedReplyEnvelope;
}

export interface W3CProjectionDedupeRecord {
    id: string;
    aid: string;
    kind: string;
    status: W3CProjectionDedupeStatus;
    updated: string;
    error?: string | null;
}

export interface W3CProjectionDedupeStore {
    get(id: string): MaybePromise<W3CProjectionDedupeRecord | undefined>;
    put(record: W3CProjectionDedupeRecord): MaybePromise<void>;
    delete(id: string): MaybePromise<void>;
    purgeTerminal(maxAgeMs?: number, now?: string): MaybePromise<number>;
}

export class MemoryW3CProjectionDedupeStore
    implements W3CProjectionDedupeStore
{
    records = new Map<string, W3CProjectionDedupeRecord>();

    get(id: string): W3CProjectionDedupeRecord | undefined {
        return this.records.get(id);
    }

    put(record: W3CProjectionDedupeRecord): void {
        this.records.set(record.id, record);
    }

    delete(id: string): void {
        this.records.delete(id);
    }

    purgeTerminal(
        maxAgeMs: number = W3C_DEDUPE_TERMINAL_RETENTION_MS,
        now: string = new Date().toISOString()
    ): number {
        let deleted = 0;
        for (const record of this.records.values()) {
            if (shouldPurgeTerminalRecord(record, maxAgeMs, now)) {
                this.records.delete(record.id);
                deleted += 1;
            }
        }
        return deleted;
    }
}

export class IndexedDbW3CProjectionDedupeStore
    implements W3CProjectionDedupeStore
{
    private dbPromise?: Promise<IDBDatabase>;

    constructor(
        private readonly factory: IDBFactory = globalThis.indexedDB,
        private readonly dbName: string = W3C_DEDUPE_DB_NAME,
        private readonly storeName: string = W3C_DEDUPE_STORE_NAME
    ) {
        if (factory === undefined) {
            throw new Error('IndexedDB is unavailable');
        }
    }

    async get(id: string): Promise<W3CProjectionDedupeRecord | undefined> {
        return await this.request('readonly', (store) => store.get(id));
    }

    async put(record: W3CProjectionDedupeRecord): Promise<void> {
        await this.request('readwrite', (store) => store.put(record));
    }

    async delete(id: string): Promise<void> {
        await this.request('readwrite', (store) => store.delete(id));
    }

    async purgeTerminal(
        maxAgeMs: number = W3C_DEDUPE_TERMINAL_RETENTION_MS,
        now: string = new Date().toISOString()
    ): Promise<number> {
        const db = await this.open();
        return await new Promise((resolve, reject) => {
            let deleted = 0;
            const transaction = db.transaction(this.storeName, 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.getAll();

            request.onsuccess = () => {
                for (const record of request.result as W3CProjectionDedupeRecord[]) {
                    if (shouldPurgeTerminalRecord(record, maxAgeMs, now)) {
                        store.delete(record.id);
                        deleted += 1;
                    }
                }
            };
            request.onerror = () => reject(request.error);
            transaction.oncomplete = () => resolve(deleted);
            transaction.onerror = () => reject(transaction.error);
            transaction.onabort = () => reject(transaction.error);
        });
    }

    private async request<T>(
        mode: IDBTransactionMode,
        create: (store: IDBObjectStore) => IDBRequest<T>
    ): Promise<T> {
        const db = await this.open();
        return await new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, mode);
            const request = create(transaction.objectStore(this.storeName));
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
            transaction.onerror = () => reject(transaction.error);
            transaction.onabort = () => reject(transaction.error);
        });
    }

    private async open(): Promise<IDBDatabase> {
        if (this.dbPromise === undefined) {
            this.dbPromise = new Promise((resolve, reject) => {
                const request = this.factory.open(this.dbName, 1);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(this.storeName)) {
                        db.createObjectStore(this.storeName, { keyPath: 'id' });
                    }
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
                request.onblocked = () =>
                    reject(new Error('IndexedDB W3C dedupe store is blocked'));
            });
        }
        return await this.dbPromise;
    }
}

export function defaultW3CProjectionDedupeStore(): W3CProjectionDedupeStore {
    if (typeof globalThis.indexedDB !== 'undefined') {
        return new IndexedDbW3CProjectionDedupeStore(globalThis.indexedDB);
    }
    return new MemoryW3CProjectionDedupeStore();
}

export class W3C {
    constructor(private readonly client: SignifyClient) {}

    async verifiers(): Promise<W3CVerifier[]> {
        const res = await this.client.fetch('/w3c/verifiers', 'GET', null);
        const body = await res.json();
        return body.verifiers;
    }

    async project(
        name: string,
        credentialSaid: string,
        verifierId: string
    ): Promise<W3CProjectionSession> {
        const res = await this.client.fetch(
            `/identifiers/${encodeURIComponent(name)}/w3c/projections`,
            'POST',
            { credentialSaid, verifierId }
        );
        return await res.json();
    }

    async projection(
        name: string,
        sessionId: string
    ): Promise<W3CProjectionSession> {
        const res = await this.client.fetch(
            `/identifiers/${encodeURIComponent(name)}/w3c/projections/${encodeURIComponent(sessionId)}`,
            'GET',
            null
        );
        return await res.json();
    }

    async requests(
        name?: string,
        includeComplete: boolean = false
    ): Promise<W3CSigningRequest[]> {
        const names =
            name !== undefined ? [name] : await this.managedIdentifierNames();
        const requests: W3CSigningRequest[] = [];
        for (const aidName of names) {
            const params = new URLSearchParams();
            if (includeComplete) {
                params.set('includeComplete', 'true');
            }
            const query = params.size > 0 ? `?${params.toString()}` : '';
            const res = await this.client.fetch(
                `/identifiers/${encodeURIComponent(aidName)}/w3c/signing-requests${query}`,
                'GET',
                null
            );
            const body = await res.json();
            requests.push(...body.requests);
        }
        return requests;
    }

    async submitSignature(
        request: W3CSigningRequest,
        signature: string
    ): Promise<W3CSigningRequest> {
        const res = await this.client.fetch(
            `/identifiers/${encodeURIComponent(request.name)}/w3c/signing-requests/${encodeURIComponent(request.d)}/signatures`,
            'POST',
            { signature }
        );
        return await res.json();
    }

    private async managedIdentifierNames(): Promise<string[]> {
        const result = await this.client.identifiers().list();
        return result.aids.map((aid: { name: string }) => aid.name);
    }
}

export type W3CProjectionRequestSource = 'sse' | 'polling';

export type W3CProjectionAutoApproveOutcome =
    | 'submitted'
    | 'skipped'
    | 'complete'
    | 'failed'
    | 'rejected';

export interface W3CProjectionAutoApproveResult {
    outcome: W3CProjectionAutoApproveOutcome;
    requestId?: string;
    source?: W3CProjectionRequestSource;
    record?: W3CProjectionDedupeRecord;
    error?: string;
}

export interface W3CProjectionAutoApproverOptions {
    store?: W3CProjectionDedupeStore;
    now?: () => string;
    terminalRetentionMs?: number;
    inFlightRetentionMs?: number;
}

export class W3CProjectionAutoApprover {
    private readonly client: SignifyClient;
    private readonly w3c: W3C;
    private readonly store: W3CProjectionDedupeStore;
    private readonly now: () => string;
    private readonly terminalRetentionMs: number;
    private readonly inFlightRetentionMs: number;
    private activeApprovals = new Map<
        string,
        Promise<W3CProjectionAutoApproveResult>
    >();

    constructor(
        client: SignifyClient,
        options: W3CProjectionAutoApproverOptions = {}
    ) {
        this.client = client;
        this.w3c = new W3C(client);
        this.store = options.store ?? defaultW3CProjectionDedupeStore();
        this.now = options.now ?? (() => new Date().toISOString());
        this.terminalRetentionMs =
            options.terminalRetentionMs ?? W3C_DEDUPE_TERMINAL_RETENTION_MS;
        this.inFlightRetentionMs =
            options.inFlightRetentionMs ?? W3C_DEDUPE_IN_FLIGHT_RETENTION_MS;
    }

    async handleEnvelope(
        envelope: SignedReplyEnvelope
    ): Promise<W3CProjectionAutoApproveResult> {
        const verified = this.client.signals().verifyReplyEnvelope(envelope, {
            route: W3C_SIGNING_ROUTE,
        });
        if (!verified) {
            return {
                outcome: 'rejected',
                error: 'W3C signing request envelope failed verification',
            };
        }
        return await this.handleRequest(
            (envelope.rpy as { a?: W3CSigningRequest }).a,
            'sse'
        );
    }

    async handleRequest(
        request: W3CSigningRequest | undefined,
        source: W3CProjectionRequestSource = 'polling'
    ): Promise<W3CProjectionAutoApproveResult> {
        if (request?.d === undefined || request.d === '') {
            return {
                outcome: 'rejected',
                source,
                error: 'W3C signing request is missing request SAID',
            };
        }

        const active = this.activeApprovals.get(request.d);
        if (active !== undefined) {
            return await active;
        }

        const approval = this.handleRequestOnce(request, source);
        this.activeApprovals.set(request.d, approval);
        try {
            return await approval;
        } finally {
            this.activeApprovals.delete(request.d);
        }
    }

    async pollOnce(name?: string): Promise<W3CProjectionAutoApproveResult[]> {
        const requests = await this.w3c.requests(name);
        const results: W3CProjectionAutoApproveResult[] = [];
        for (const request of requests) {
            results.push(await this.handleRequest(request, 'polling'));
        }
        return results;
    }

    async reconcile(name?: string): Promise<W3CProjectionDedupeRecord[]> {
        await this.store.purgeTerminal(this.terminalRetentionMs, this.now());
        const requests = await this.w3c.requests(name, true);
        const records: W3CProjectionDedupeRecord[] = [];
        for (const request of requests) {
            if (request.state === W3C_DEDUPE_COMPLETE) {
                records.push(
                    await this.putRecord(request, W3C_DEDUPE_COMPLETE)
                );
            } else if (request.state === W3C_DEDUPE_FAILED) {
                records.push(
                    await this.putRecord(
                        request,
                        W3C_DEDUPE_FAILED,
                        request.error ?? 'KERIA reported W3C request failure'
                    )
                );
            }
        }
        return records;
    }

    private async handleRequestOnce(
        request: W3CSigningRequest,
        source: W3CProjectionRequestSource
    ): Promise<W3CProjectionAutoApproveResult> {
        const now = this.now();
        await this.store.purgeTerminal(this.terminalRetentionMs, now);
        const existing = await this.store.get(request.d);
        if (this.shouldSkip(existing, now)) {
            return {
                outcome: 'skipped',
                requestId: request.d,
                source,
                record: existing,
            };
        }

        await this.putRecord(request, W3C_DEDUPE_IN_FLIGHT);
        const ownershipError = await this.localOwnershipError(request);
        if (ownershipError !== undefined) {
            const record = await this.putRecord(
                request,
                W3C_DEDUPE_REJECTED,
                ownershipError
            );
            return {
                outcome: 'rejected',
                requestId: request.d,
                source,
                record,
                error: ownershipError,
            };
        }

        try {
            const signature = await this.signRequest(request);
            await this.w3c.submitSignature(request, signature);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            const record = await this.putRecord(
                request,
                W3C_DEDUPE_FAILED,
                message
            );
            return {
                outcome: 'failed',
                requestId: request.d,
                source,
                record,
                error: message,
            };
        }

        const record = await this.putRecord(request, W3C_DEDUPE_SUBMITTED);
        return {
            outcome: 'submitted',
            requestId: request.d,
            source,
            record,
        };
    }

    private async signRequest(request: W3CSigningRequest): Promise<string> {
        if (
            ![W3C_REQUEST_DATA_INTEGRITY_PROOF, W3C_REQUEST_VC_JWT].includes(
                request.kind
            )
        ) {
            throw new Error(
                `unsupported W3C signing request kind ${request.kind}`
            );
        }
        const hab = await this.client.identifiers().get(request.name);
        const keeper = this.client.manager!.get(hab);
        const sigs = await keeper.sign(
            decodeBase64Url(request.signingInputB64),
            false
        );
        return sigs[0];
    }

    private async localOwnershipError(
        request: W3CSigningRequest
    ): Promise<string | undefined> {
        let hab;
        try {
            hab = await this.client.identifiers().get(request.name);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            return `W3C request ${request.d} targets ${request.aid}, but local identifier ${request.name} is unavailable: ${message}`;
        }
        if (hab.prefix !== request.aid) {
            return `W3C request ${request.d} targets ${request.aid}, but local identifier ${request.name} is ${hab.prefix}`;
        }
        return undefined;
    }

    private shouldSkip(
        record: W3CProjectionDedupeRecord | undefined,
        now: string
    ): record is W3CProjectionDedupeRecord {
        if (
            record?.status === W3C_DEDUPE_IN_FLIGHT &&
            recordAgeMs(record, now) >= this.inFlightRetentionMs
        ) {
            return false;
        }
        return (
            record !== undefined &&
            [
                W3C_DEDUPE_IN_FLIGHT,
                W3C_DEDUPE_SUBMITTED,
                W3C_DEDUPE_COMPLETE,
                W3C_DEDUPE_FAILED,
                W3C_DEDUPE_REJECTED,
            ].includes(record.status)
        );
    }

    private async putRecord(
        request: W3CSigningRequest,
        status: W3CProjectionDedupeStatus,
        error: string | null = null
    ): Promise<W3CProjectionDedupeRecord> {
        const record = {
            id: request.d,
            aid: request.aid,
            kind: request.kind,
            status,
            updated: this.now(),
            error,
        };
        await this.store.put(record);
        return record;
    }
}

function shouldPurgeTerminalRecord(
    record: W3CProjectionDedupeRecord,
    maxAgeMs: number,
    now: string
): boolean {
    if (!W3C_TERMINAL_DEDUPE_STATUSES.has(record.status)) {
        return false;
    }
    return recordAgeMs(record, now) >= maxAgeMs;
}

function recordAgeMs(record: W3CProjectionDedupeRecord, now: string): number {
    const updated = Date.parse(record.updated);
    const current = Date.parse(now);
    if (Number.isNaN(updated) || Number.isNaN(current)) {
        return 0;
    }
    return current - updated;
}
