import { beforeAll, describe, expect, test } from 'vitest';
import { SignifyClient } from 'signify-ts';
import { getOrCreateClient, getOrCreateIdentifier } from './utils/test-util.ts';

let client: SignifyClient;
let prefix: string;

beforeAll(async () => {
    client = await getOrCreateClient();
    [prefix] = await getOrCreateIdentifier(client, 'binary-contact-image', {
        toad: 0,
        wits: [],
    });
});

describe('contact image byte transport', () => {
    test('uploads and downloads exact bytes through authenticated fetch', async () => {
        const image = new Uint8Array([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00,
            0x85,
        ]);
        const path = `/contacts/${prefix}/img`;

        const uploaded = await client.fetchRequest(path, {
            method: 'POST',
            headers: { 'Content-Type': 'image/png' },
            body: image,
        });
        expect(uploaded.status).toBe(202);

        const downloaded = await client.fetchRequest(path);
        expect(downloaded.status).toBe(200);
        expect(downloaded.headers.get('Content-Type')).toBe('image/png');
        expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(image);
    });
});
