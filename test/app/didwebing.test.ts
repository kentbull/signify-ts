import { assert, describe, expect, it } from 'vitest';
import * as signify from '../../src/index.ts';
import { DidWebs } from '../../src/index.ts';
import type { SignifyClient } from '../../src/index.ts';

function setupFixture() {
    return {
        name: 'aid1',
        aid: 'Eaid',
        did: 'did:webs:example.com:dws:Eaid',
        dws: null,
        didJsonUrl: 'https://example.com/dws/Eaid/did.json',
        keriCesrUrl: 'https://example.com/dws/Eaid/keri.cesr',
        ready: false,
        registry: {
            name: 'didwebs-designated-aliases-Eaid',
            registryId: null,
            ready: false,
            createArgs: {
                name: 'aid1',
                registryName: 'didwebs-designated-aliases-Eaid',
            },
        },
        designatedAlias: {
            schema: 'schema-said',
            credentialSaid: null,
            ready: false,
            issueArgs: null,
        },
    };
}

describe('DidWebs', () => {
    it('fetches the setup descriptor for an identifier', async () => {
        const fixture = setupFixture();
        const calls: Array<[string, string, unknown]> = [];
        const client = {
            async fetch(path: string, method: string, body: unknown) {
                calls.push([path, method, body]);
                return Response.json(fixture);
            },
        } as unknown as SignifyClient;

        const result = await new DidWebs(client).setup('aid one');

        assert.deepEqual(result, fixture);
        assert.deepEqual(calls, [
            ['/identifiers/aid%20one/dws/setup', 'GET', null],
        ]);
    });

    it('delegates compact readiness to identifiers().dws()', async () => {
        const readiness = {
            dws: 'did:webs:example.com:dws:Eaid',
            didJsonUrl: 'https://example.com/dws/Eaid/did.json',
            keriCesrUrl: 'https://example.com/dws/Eaid/keri.cesr',
        };
        const names: string[] = [];
        const client = {
            identifiers() {
                return {
                    async dws(name: string) {
                        names.push(name);
                        return readiness;
                    },
                };
            },
        } as unknown as SignifyClient;

        const result = await new DidWebs(client).readiness('aid1');

        assert.deepEqual(result, readiness);
        assert.deepEqual(names, ['aid1']);
    });

    it('does not export removed auto-approval and dedupe APIs', () => {
        const exports = signify as Record<string, unknown>;

        expect(exports.DidWebsAutoApprover).toBeUndefined();
        expect(exports.MemoryDidWebsRequestDedupeStore).toBeUndefined();
        expect(exports.IndexedDbDidWebsRequestDedupeStore).toBeUndefined();
        expect(exports.defaultDidWebsRequestDedupeStore).toBeUndefined();
        expect(exports.DWS_SIGNING_ROUTE).toBeUndefined();
    });
});
