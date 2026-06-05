import { assert, describe, expect, it } from 'vitest';
import {
    DidWebs,
    DidWebsAutoApprover,
    DWS_ACTION_CREATE_REGISTRY,
    DWS_ACTION_ISSUE_DESIGNATED_ALIAS,
    DWS_DEDUPE_COMPLETE,
    DWS_DEDUPE_FAILED,
    DWS_DEDUPE_IN_FLIGHT,
    DWS_DEDUPE_IN_FLIGHT_RETENTION_MS,
    DWS_DEDUPE_REJECTED,
    DWS_DEDUPE_SUBMITTED,
    DWS_DEDUPE_TERMINAL_RETENTION_MS,
    DWS_SIGNING_ROUTE,
    IndexedDbDidWebsRequestDedupeStore,
    MemoryDidWebsRequestDedupeStore,
    SignifyClient,
    defaultDidWebsRequestDedupeStore,
} from '../../src/index.ts';

function requestFixture(overrides: Record<string, unknown> = {}) {
    return {
        d: 'request-id',
        type: 'didwebs.registry.create',
        action: DWS_ACTION_CREATE_REGISTRY,
        agent: 'agent-aid',
        aid: 'managed-aid',
        name: 'aid1',
        did: 'did:webs:example:aid',
        registryName: 'registry',
        schema: 'schema',
        credentialData: {},
        rules: {},
        didJsonUrl: 'http://example/did.json',
        keriCesrUrl: 'http://example/keri.cesr',
        dt: '2021-06-27T21:26:21.233257+00:00',
        ...overrides,
    };
}

function clientFixture({
    requests = [],
    verify = true,
    prefix = 'managed-aid',
    approveError,
    identifierError,
    approveDelay,
}: {
    requests?: unknown[];
    verify?: boolean;
    prefix?: string;
    approveError?: Error;
    identifierError?: Error;
    approveDelay?: Promise<void>;
} = {}) {
    const approvals: unknown[] = [];
    const fetches: string[] = [];
    const client = {
        signals() {
            return {
                verifyReplyEnvelope(_envelope: unknown, options: unknown) {
                    approvals.push(['verify', options]);
                    return verify;
                },
            };
        },
        identifiers() {
            return {
                async get(name: string) {
                    if (identifierError !== undefined) {
                        throw identifierError;
                    }
                    approvals.push(['identifier', name]);
                    return { prefix };
                },
            };
        },
        registries() {
            return {
                async create(args: unknown) {
                    if (approveError !== undefined) {
                        throw approveError;
                    }
                    await approveDelay;
                    approvals.push(['registry', args]);
                    return 'registry-op';
                },
            };
        },
        credentials() {
            return {
                async issue(name: string, args: unknown) {
                    if (approveError !== undefined) {
                        throw approveError;
                    }
                    await approveDelay;
                    approvals.push(['credential', name, args]);
                    return 'credential-op';
                },
            };
        },
        async fetch(path: string) {
            fetches.push(path);
            return Response.json({ requests });
        },
    } as unknown as SignifyClient;

    return { client, approvals, fetches };
}

function envelopeFixture(request = requestFixture()) {
    return {
        rpy: {
            r: DWS_SIGNING_ROUTE,
            a: request,
        },
        sigs: ['signature'],
    };
}

describe('DidWebs', () => {
    it('lists signing requests', async () => {
        const request = requestFixture();
        const calls: string[] = [];
        const client = {
            async fetch(path: string) {
                calls.push(path);
                return Response.json({ requests: [request] });
            },
        } as unknown as SignifyClient;

        const requests = await new DidWebs(client).requests('aid', true);

        assert.deepEqual(requests, [request]);
        assert.equal(
            calls[0],
            '/didwebs/signing/requests?aid=aid&includeComplete=true'
        );
    });

    it('gets a signing request', async () => {
        const fixture = requestFixture();
        const calls: string[] = [];
        const client = {
            async fetch(path: string) {
                calls.push(path);
                return Response.json(fixture);
            },
        } as unknown as SignifyClient;

        const request = await new DidWebs(client).request('request-id');

        assert.deepEqual(request, fixture);
        assert.equal(calls[0], '/didwebs/signing/requests/request-id');
    });

    it('approves registry requests through the registry API', async () => {
        const calls: Record<string, string>[] = [];
        const client = {
            registries() {
                return {
                    async create(args: Record<string, string>) {
                        calls.push(args);
                        return 'registry-op';
                    },
                };
            },
        } as unknown as SignifyClient;

        const result = await new DidWebs(client).approve(requestFixture());

        assert.equal(result as unknown, 'registry-op');
        assert.deepEqual(calls[0], { name: 'aid1', registryName: 'registry' });
    });

    it('approves designated-alias requests through the credential API', async () => {
        const calls: unknown[] = [];
        const client = {
            credentials() {
                return {
                    async issue(name: string, args: unknown) {
                        calls.push([name, args]);
                        return 'credential-op';
                    },
                };
            },
        } as unknown as SignifyClient;

        const result = await new DidWebs(client).approve(
            requestFixture({
                type: 'didwebs.designated-alias.issue',
                action: DWS_ACTION_ISSUE_DESIGNATED_ALIAS,
                registryId: 'registry-said',
                credentialData: { ids: ['did:webs:example:aid'] },
                rules: { usageDisclaimer: {} },
            })
        );

        assert.equal(result as unknown, 'credential-op');
        assert.deepEqual(calls[0], [
            'aid1',
            {
                ri: 'registry-said',
                s: 'schema',
                a: { ids: ['did:webs:example:aid'] },
                r: { usageDisclaimer: {} },
            },
        ]);
    });

    it('requires registryId for credential approval', async () => {
        const client = {} as unknown as SignifyClient;

        await expect(
            new DidWebs(client).approve({
                ...requestFixture({
                    type: 'didwebs.designated-alias.issue',
                    action: DWS_ACTION_ISSUE_DESIGNATED_ALIAS,
                }),
            })
        ).rejects.toThrow('missing registryId');
    });
});

describe('DidWebsAutoApprover', () => {
    it('defaults to IndexedDB when native IndexedDB is available', () => {
        const original = Object.getOwnPropertyDescriptor(
            globalThis,
            'indexedDB'
        );
        Object.defineProperty(globalThis, 'indexedDB', {
            configurable: true,
            value: { open() {} },
        });

        try {
            const store = defaultDidWebsRequestDedupeStore();
            assert.equal(
                store instanceof IndexedDbDidWebsRequestDedupeStore,
                true
            );
        } finally {
            if (original !== undefined) {
                Object.defineProperty(globalThis, 'indexedDB', original);
            } else {
                Reflect.deleteProperty(globalThis, 'indexedDB');
            }
        }
    });

    it('defaults to memory when native IndexedDB is unavailable', () => {
        const original = Object.getOwnPropertyDescriptor(
            globalThis,
            'indexedDB'
        );
        Reflect.deleteProperty(globalThis, 'indexedDB');

        try {
            const store = defaultDidWebsRequestDedupeStore();
            assert.equal(
                store instanceof MemoryDidWebsRequestDedupeStore,
                true
            );
        } finally {
            if (original !== undefined) {
                Object.defineProperty(globalThis, 'indexedDB', original);
            }
        }
    });

    it('purges old terminal dedupe records while retaining active and recent records', async () => {
        const store = new MemoryDidWebsRequestDedupeStore();
        await store.put({
            id: 'old-complete',
            aid: 'managed-aid',
            action: DWS_ACTION_CREATE_REGISTRY,
            status: DWS_DEDUPE_COMPLETE,
            updated: '2021-06-27T21:00:00.000Z',
        });
        await store.put({
            id: 'recent-complete',
            aid: 'managed-aid',
            action: DWS_ACTION_CREATE_REGISTRY,
            status: DWS_DEDUPE_COMPLETE,
            updated: '2021-06-27T21:09:30.000Z',
        });
        await store.put({
            id: 'old-submitted',
            aid: 'managed-aid',
            action: DWS_ACTION_CREATE_REGISTRY,
            status: DWS_DEDUPE_SUBMITTED,
            updated: '2021-06-27T21:00:00.000Z',
        });
        await store.put({
            id: 'old-rejected',
            aid: 'managed-aid',
            action: DWS_ACTION_CREATE_REGISTRY,
            status: DWS_DEDUPE_REJECTED,
            updated: '2021-06-27T21:00:00.000Z',
        });

        const deleted = await store.purgeTerminal(
            DWS_DEDUPE_TERMINAL_RETENTION_MS,
            '2021-06-27T21:10:00.000Z'
        );

        assert.equal(deleted, 2);
        assert.equal(await store.get('old-complete'), undefined);
        assert.equal(await store.get('old-rejected'), undefined);
        assert.equal(
            (await store.get('recent-complete'))?.status,
            DWS_DEDUPE_COMPLETE
        );
        assert.equal(
            (await store.get('old-submitted'))?.status,
            DWS_DEDUPE_SUBMITTED
        );
    });

    it('dedupes duplicate SSE envelopes by request SAID', async () => {
        const { client, approvals } = clientFixture();
        const approver = new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
            now: () => 'now',
        });

        const first = await approver.handleEnvelope(envelopeFixture());
        const second = await approver.handleEnvelope(envelopeFixture());

        assert.equal(first.outcome, 'submitted');
        assert.equal(second.outcome, 'skipped');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            1
        );
        assert.equal(second.record?.status, DWS_DEDUPE_SUBMITTED);
    });

    it('dedupes the same request seen by SSE and polling', async () => {
        const request = requestFixture();
        const { client, approvals } = clientFixture({ requests: [request] });
        const approver = new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        });

        await approver.handleEnvelope(envelopeFixture(request));
        const results = await approver.pollOnce();

        assert.equal(results[0].outcome, 'skipped');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            1
        );
    });

    it('coalesces concurrent sightings for the same request SAID', async () => {
        let releaseApproval!: () => void;
        const approveDelay = new Promise<void>((resolve) => {
            releaseApproval = resolve;
        });
        const { client, approvals } = clientFixture({ approveDelay });
        const approver = new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        });

        const first = approver.handleRequest(requestFixture());
        const second = approver.handleEnvelope(envelopeFixture());
        releaseApproval();
        const results = await Promise.all([first, second]);

        assert.equal(results[0].outcome, 'submitted');
        assert.equal(results[1].outcome, 'submitted');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            1
        );
    });

    it('uses a provided store to suppress duplicates across approvers', async () => {
        const store = new MemoryDidWebsRequestDedupeStore();
        const { client, approvals } = clientFixture();

        await new DidWebsAutoApprover(client, { store }).handleRequest(
            requestFixture()
        );
        const second = await new DidWebsAutoApprover(client, {
            store,
        }).handleRequest(requestFixture());

        assert.equal(second.outcome, 'skipped');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            1
        );
    });

    it('retries stale in-flight records after the active dedupe window', async () => {
        const store = new MemoryDidWebsRequestDedupeStore();
        await store.put({
            id: 'request-id',
            aid: 'managed-aid',
            action: DWS_ACTION_CREATE_REGISTRY,
            status: DWS_DEDUPE_IN_FLIGHT,
            updated: '2021-06-27T21:00:00.000Z',
        });
        const { client, approvals } = clientFixture();
        const result = await new DidWebsAutoApprover(client, {
            store,
            now: () => '2021-06-27T21:10:00.000Z',
            inFlightRetentionMs: DWS_DEDUPE_IN_FLIGHT_RETENTION_MS,
        }).handleRequest(requestFixture());

        assert.equal(result.outcome, 'submitted');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            1
        );
    });

    it('rejects unverified SSE envelopes before approval', async () => {
        const { client, approvals } = clientFixture({ verify: false });

        const result = await new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        }).handleEnvelope(envelopeFixture());

        assert.equal(result.outcome, 'rejected');
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            0
        );
    });

    it('rejects requests for non-local or mismatched AIDs', async () => {
        const { client, approvals } = clientFixture({ prefix: 'other-aid' });

        const result = await new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        }).handleRequest(requestFixture());

        assert.equal(result.outcome, 'rejected');
        assert.equal(result.record?.status, DWS_DEDUPE_REJECTED);
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            0
        );
    });

    it('rejects requests when the local identifier is unavailable', async () => {
        const { client, approvals } = clientFixture({
            identifierError: new Error('not found'),
        });

        const result = await new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        }).handleRequest(requestFixture());

        assert.equal(result.outcome, 'rejected');
        assert.equal(result.record?.status, DWS_DEDUPE_REJECTED);
        assert.match(result.error ?? '', /unavailable: not found/);
        assert.equal(
            approvals.filter((call) => (call as unknown[])[0] === 'registry')
                .length,
            0
        );
    });

    it('marks approval errors failed without completing the request', async () => {
        const { client } = clientFixture({ approveError: new Error('boom') });
        const approver = new DidWebsAutoApprover(client, {
            store: new MemoryDidWebsRequestDedupeStore(),
        });

        const result = await approver.handleRequest(requestFixture());

        assert.equal(result.outcome, 'failed');
        assert.equal(result.record?.status, DWS_DEDUPE_FAILED);
        assert.equal(result.record?.error, 'boom');
    });

    it('reconciles completion only from KERIA request state', async () => {
        const request = requestFixture({ state: DWS_DEDUPE_COMPLETE });
        const pending = requestFixture({ d: 'pending-id', state: 'pending' });
        const { client } = clientFixture({ requests: [request, pending] });
        const store = new MemoryDidWebsRequestDedupeStore();
        const approver = new DidWebsAutoApprover(client, { store });

        await approver.handleRequest(requestFixture());
        const records = await approver.reconcile();

        assert.equal(records.length, 1);
        assert.equal(
            (await store.get('request-id'))?.status,
            DWS_DEDUPE_COMPLETE
        );
        assert.equal(await store.get('pending-id'), undefined);
    });
});
