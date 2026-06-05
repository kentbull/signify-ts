import { SignifyClient } from './clienting.ts';
import { SignedReplyEnvelope } from './signaling.ts';

/**
 * KERI reply route used inside signed did:webs publication requests.
 *
 * Live delivery comes through `client.signals().stream()`. Durable fallback and
 * request retrieval stay under `client.didwebs()`.
 */
export const DWS_SIGNING_ROUTE = '/didwebs/signing/request';
export const DWS_ACTION_CREATE_REGISTRY = 'create_registry';
export const DWS_ACTION_ISSUE_DESIGNATED_ALIAS = 'issue_designated_alias';
export const DWS_DEDUPE_IN_FLIGHT = 'in_flight';
export const DWS_DEDUPE_SUBMITTED = 'submitted';
export const DWS_DEDUPE_COMPLETE = 'complete';
export const DWS_DEDUPE_FAILED = 'failed';
export const DWS_DEDUPE_REJECTED = 'rejected';
export const DWS_DEDUPE_TERMINAL_RETENTION_MS = 10 * 60 * 1000;
export const DWS_DEDUPE_IN_FLIGHT_RETENTION_MS = 10 * 60 * 1000;
const DWS_DEDUPE_DB_NAME = 'signify-didwebs';
const DWS_DEDUPE_STORE_NAME = 'requestDedupe';

type MaybePromise<T> = T | Promise<T>;

export type DidWebsRequestDedupeStatus =
    | typeof DWS_DEDUPE_IN_FLIGHT
    | typeof DWS_DEDUPE_SUBMITTED
    | typeof DWS_DEDUPE_COMPLETE
    | typeof DWS_DEDUPE_FAILED
    | typeof DWS_DEDUPE_REJECTED;

const DWS_TERMINAL_DEDUPE_STATUSES = new Set<DidWebsRequestDedupeStatus>([
    DWS_DEDUPE_COMPLETE,
    DWS_DEDUPE_FAILED,
    DWS_DEDUPE_REJECTED,
]);

export interface DidWebsRequestDedupeRecord {
    id: string;
    aid: string;
    action: string;
    status: DidWebsRequestDedupeStatus;
    updated: string;
    error?: string | null;
}

export interface DidWebsRequestDedupeStore {
    get(id: string): MaybePromise<DidWebsRequestDedupeRecord | undefined>;
    put(record: DidWebsRequestDedupeRecord): MaybePromise<void>;
    delete(id: string): MaybePromise<void>;
    purgeTerminal(maxAgeMs?: number, now?: string): MaybePromise<number>;
}

export class MemoryDidWebsRequestDedupeStore
    implements DidWebsRequestDedupeStore
{
    records = new Map<string, DidWebsRequestDedupeRecord>();

    get(id: string): DidWebsRequestDedupeRecord | undefined {
        return this.records.get(id);
    }

    put(record: DidWebsRequestDedupeRecord): void {
        this.records.set(record.id, record);
    }

    delete(id: string): void {
        this.records.delete(id);
    }

    purgeTerminal(
        maxAgeMs: number = DWS_DEDUPE_TERMINAL_RETENTION_MS,
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

function shouldPurgeTerminalRecord(
    record: DidWebsRequestDedupeRecord,
    maxAgeMs: number,
    now: string
): boolean {
    if (!DWS_TERMINAL_DEDUPE_STATUSES.has(record.status)) {
        return false;
    }

    return recordAgeMs(record, now) >= maxAgeMs;
}

function recordAgeMs(record: DidWebsRequestDedupeRecord, now: string): number {
    const updated = Date.parse(record.updated);
    const current = Date.parse(now);
    if (Number.isNaN(updated) || Number.isNaN(current)) {
        return 0;
    }

    return current - updated;
}

export class IndexedDbDidWebsRequestDedupeStore
    implements DidWebsRequestDedupeStore
{
    private dbPromise?: Promise<IDBDatabase>;

    constructor(
        private readonly factory: IDBFactory = globalThis.indexedDB,
        private readonly dbName: string = DWS_DEDUPE_DB_NAME,
        private readonly storeName: string = DWS_DEDUPE_STORE_NAME
    ) {
        if (factory === undefined) {
            throw new Error('IndexedDB is unavailable');
        }
    }

    async get(id: string): Promise<DidWebsRequestDedupeRecord | undefined> {
        return await this.request('readonly', (store) => store.get(id));
    }

    async put(record: DidWebsRequestDedupeRecord): Promise<void> {
        await this.request('readwrite', (store) => store.put(record));
    }

    async delete(id: string): Promise<void> {
        await this.request('readwrite', (store) => store.delete(id));
    }

    async purgeTerminal(
        maxAgeMs: number = DWS_DEDUPE_TERMINAL_RETENTION_MS,
        now: string = new Date().toISOString()
    ): Promise<number> {
        const db = await this.open();
        return await new Promise((resolve, reject) => {
            let deleted = 0;
            const transaction = db.transaction(this.storeName, 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.getAll();

            request.onsuccess = () => {
                for (const record of request.result as DidWebsRequestDedupeRecord[]) {
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
                    reject(
                        new Error('IndexedDB did:webs dedupe store is blocked')
                    );
            });
        }
        return await this.dbPromise;
    }
}

export function defaultDidWebsRequestDedupeStore(): DidWebsRequestDedupeStore {
    if (typeof globalThis.indexedDB !== 'undefined') {
        return new IndexedDbDidWebsRequestDedupeStore(globalThis.indexedDB);
    }
    return new MemoryDidWebsRequestDedupeStore();
}

export type DidWebsRequestSource = 'sse' | 'polling';

export type DidWebsAutoApproveOutcome =
    | 'submitted'
    | 'skipped'
    | 'complete'
    | 'failed'
    | 'rejected';

export interface DidWebsAutoApproveResult {
    outcome: DidWebsAutoApproveOutcome;
    requestId?: string;
    source?: DidWebsRequestSource;
    record?: DidWebsRequestDedupeRecord;
    error?: string;
}

/**
 * Durable did:webs publication request prepared by KERIA for edge signing.
 */
export interface DidWebsSigningRequest {
    d: string;
    type: string;
    action: string;
    agent: string;
    aid: string;
    name: string;
    did: string;
    registryName: string;
    registryId?: string;
    schema: string;
    credentialData: Record<string, unknown>;
    rules: Record<string, unknown>;
    didJsonUrl: string;
    keriCesrUrl: string;
    dt: string;
    state?: string;
    lastSignaled?: string | null;
    error?: string | null;
    envelope?: SignedReplyEnvelope;
}

/**
 * did:webs publication request helper.
 *
 * `DidWebs` owns only did:webs-specific polling and approval behavior. Generic
 * SSE transport and signed KERI `rpy` envelope verification live on
 * `client.signals()` so future KERIA workflows can reuse the same signaling
 * channel without importing did:webs.
 */
export class DidWebs {
    client: SignifyClient;

    constructor(client: SignifyClient) {
        this.client = client;
    }

    /**
     * List durable did:webs publication requests from KERIA.
     *
     * This is the recovery path when a client was not connected to
     * `/signals/stream` or missed a transient SSE event.
     */
    async requests(
        aid?: string,
        includeComplete: boolean = false
    ): Promise<DidWebsSigningRequest[]> {
        const params = new URLSearchParams();
        if (aid !== undefined) {
            params.set('aid', aid);
        }
        if (includeComplete) {
            params.set('includeComplete', 'true');
        }
        const query = params.size > 0 ? `?${params.toString()}` : '';
        const res = await this.client.fetch(
            `/didwebs/signing/requests${query}`,
            'GET',
            null
        );
        const body = await res.json();
        return body.requests;
    }

    /**
     * Fetch one durable did:webs publication request by request SAID.
     */
    async request(requestId: string): Promise<DidWebsSigningRequest> {
        const res = await this.client.fetch(
            `/didwebs/signing/requests/${requestId}`,
            'GET',
            null
        );
        return await res.json();
    }

    /**
     * Perform the edge-signed action requested by KERIA.
     *
     * The caller should verify `request.envelope` with
     * `client.signals().verifyReplyEnvelope(..., { route:
     * DIDWEBS_SIGNING_ROUTE })` before auto-approving a live SSE request.
     * Polling fallback can trust normal authenticated KERIA transport but still
     * uses the same request shape.
     */
    async approve(request: DidWebsSigningRequest) {
        if (request.action === DWS_ACTION_CREATE_REGISTRY) {
            return await this.client.registries().create({
                name: request.name,
                registryName: request.registryName,
            });
        }
        if (request.action === DWS_ACTION_ISSUE_DESIGNATED_ALIAS) {
            if (request.registryId === undefined) {
                throw new Error(
                    'did:webs designated-alias request is missing registryId'
                );
            }
            return await this.client.credentials().issue(request.name, {
                ri: request.registryId,
                s: request.schema,
                a: request.credentialData,
                r: request.rules,
            });
        }

        throw new Error(
            `unsupported did:webs signing request action ${request.action}`
        );
    }
}

export interface DidWebsAutoApproverOptions {
    store?: DidWebsRequestDedupeStore;
    now?: () => string;
    terminalRetentionMs?: number;
    inFlightRetentionMs?: number;
}

export class DidWebsAutoApprover {
    client: SignifyClient;
    didwebs: DidWebs;
    store: DidWebsRequestDedupeStore;
    now: () => string;
    terminalRetentionMs: number;
    inFlightRetentionMs: number;
    private activeApprovals = new Map<
        string,
        Promise<DidWebsAutoApproveResult>
    >();

    constructor(
        client: SignifyClient,
        options: DidWebsAutoApproverOptions = {}
    ) {
        this.client = client;
        this.didwebs = new DidWebs(client);
        this.store = options.store ?? defaultDidWebsRequestDedupeStore();
        this.now = options.now ?? (() => new Date().toISOString());
        this.terminalRetentionMs =
            options.terminalRetentionMs ?? DWS_DEDUPE_TERMINAL_RETENTION_MS;
        this.inFlightRetentionMs =
            options.inFlightRetentionMs ?? DWS_DEDUPE_IN_FLIGHT_RETENTION_MS;
    }

    async handleEnvelope(
        envelope: SignedReplyEnvelope
    ): Promise<DidWebsAutoApproveResult> {
        const verified = this.client.signals().verifyReplyEnvelope(envelope, {
            route: DWS_SIGNING_ROUTE,
        });
        if (!verified) {
            return {
                outcome: 'rejected',
                error: 'did:webs signing request envelope failed verification',
            };
        }

        return await this.handleRequest(
            (envelope.rpy as { a?: DidWebsSigningRequest }).a,
            'sse'
        );
    }

    async handleRequest(
        request: DidWebsSigningRequest | undefined,
        source: DidWebsRequestSource = 'polling'
    ): Promise<DidWebsAutoApproveResult> {
        if (request?.d === undefined || request.d === '') {
            return {
                outcome: 'rejected',
                source,
                error: 'did:webs signing request is missing request SAID',
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

    private async handleRequestOnce(
        request: DidWebsSigningRequest,
        source: DidWebsRequestSource
    ): Promise<DidWebsAutoApproveResult> {
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

        await this.putRecord(request, DWS_DEDUPE_IN_FLIGHT);
        const ownershipError = await this.localOwnershipError(request);
        if (ownershipError !== undefined) {
            const record = await this.putRecord(
                request,
                DWS_DEDUPE_REJECTED,
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
            await this.didwebs.approve(request);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            const record = await this.putRecord(
                request,
                DWS_DEDUPE_FAILED,
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

        const record = await this.putRecord(request, DWS_DEDUPE_SUBMITTED);
        return {
            outcome: 'submitted',
            requestId: request.d,
            source,
            record,
        };
    }

    async pollOnce(aid?: string): Promise<DidWebsAutoApproveResult[]> {
        const requests = await this.didwebs.requests(aid);
        const results: DidWebsAutoApproveResult[] = [];
        for (const request of requests) {
            results.push(await this.handleRequest(request, 'polling'));
        }
        return results;
    }

    async reconcile(aid?: string): Promise<DidWebsRequestDedupeRecord[]> {
        await this.store.purgeTerminal(this.terminalRetentionMs, this.now());
        const requests = await this.didwebs.requests(aid, true);
        const records: DidWebsRequestDedupeRecord[] = [];
        for (const request of requests) {
            if (request.state === DWS_DEDUPE_COMPLETE) {
                records.push(
                    await this.putRecord(request, DWS_DEDUPE_COMPLETE)
                );
            } else if (request.state === DWS_DEDUPE_FAILED) {
                records.push(
                    await this.putRecord(
                        request,
                        DWS_DEDUPE_FAILED,
                        request.error ?? 'KERIA reported request failure'
                    )
                );
            }
        }
        return records;
    }

    private shouldSkip(
        record: DidWebsRequestDedupeRecord | undefined,
        now: string
    ): record is DidWebsRequestDedupeRecord {
        if (
            record?.status === DWS_DEDUPE_IN_FLIGHT &&
            recordAgeMs(record, now) >= this.inFlightRetentionMs
        ) {
            return false;
        }

        return (
            record !== undefined &&
            [
                DWS_DEDUPE_IN_FLIGHT,
                DWS_DEDUPE_SUBMITTED,
                DWS_DEDUPE_COMPLETE,
                DWS_DEDUPE_FAILED,
                DWS_DEDUPE_REJECTED,
            ].includes(record.status)
        );
    }

    private async localOwnershipError(
        request: DidWebsSigningRequest
    ): Promise<string | undefined> {
        let hab;
        try {
            hab = await this.client.identifiers().get(request.name);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            return `did:webs request ${request.d} targets ${request.aid}, but local identifier ${request.name} is unavailable: ${message}`;
        }
        if (hab.prefix !== request.aid) {
            return `did:webs request ${request.d} targets ${request.aid}, but local identifier ${request.name} is ${hab.prefix}`;
        }
        return undefined;
    }

    private async putRecord(
        request: DidWebsSigningRequest,
        status: DidWebsRequestDedupeStatus,
        error: string | null = null
    ): Promise<DidWebsRequestDedupeRecord> {
        const record = {
            id: request.d,
            aid: request.aid,
            action: request.action,
            status,
            updated: this.now(),
            error,
        };
        await this.store.put(record);
        return record;
    }
}
