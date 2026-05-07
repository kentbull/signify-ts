import { assert, describe, it } from 'vitest';

import { Matter, MtrDex, Sizage } from '../../src/keri/core/matter.ts';
import {
    decodeBase64Url,
    encodeBase64Url,
} from '../../src/keri/core/base64.ts';

const bytes = (length: number) =>
    Uint8Array.from({ length }, (_, index) => (index * 17 + 3) % 256);

describe('Sizage', () => {
    it('should hold size values in 4 properties', async () => {
        const sizage = new Sizage(1, 2, 3, 4);
        assert.equal(sizage.hs, 1);
        assert.equal(sizage.ss, 2);
        assert.equal(sizage.fs, 3);
        assert.equal(sizage.ls, 4);
    });
});

describe('Matter variable cipher codes', () => {
    it('should round trip X25519 stream cipher lead sizes', () => {
        const cases = [
            { raw: bytes(6), code: MtrDex.X25519_Cipher_L0 },
            { raw: bytes(5), code: MtrDex.X25519_Cipher_L1 },
            { raw: bytes(4), code: MtrDex.X25519_Cipher_L2 },
        ];

        for (const { raw, code } of cases) {
            const matter = new Matter({
                raw,
                code: MtrDex.X25519_Cipher_L0,
            });
            assert.equal(matter.code, code);

            const parsed = new Matter({ qb64: matter.qb64 });
            assert.equal(parsed.code, code);
            assert.deepStrictEqual(parsed.raw, raw);
            assert.equal(parsed.qb64, matter.qb64);
        }
    });

    it('should promote large X25519 stream ciphers to the big code family', () => {
        const raw = bytes(12_288);
        const matter = new Matter({
            raw,
            code: MtrDex.X25519_Cipher_L0,
        });
        assert.equal(matter.code, MtrDex.X25519_Cipher_Big_L0);

        const parsed = new Matter({ qb64: matter.qb64 });
        assert.equal(parsed.code, MtrDex.X25519_Cipher_Big_L0);
        assert.deepStrictEqual(parsed.raw, raw);
    });

    it('should reject raw size lookup for variable cipher codes', () => {
        assert.throws(
            () => Matter._rawSize(MtrDex.X25519_Cipher_L0),
            /Non-fixed raw size code 4C/
        );
    });

    it('should reject nonzero variable lead bytes', () => {
        const matter = new Matter({
            raw: bytes(5),
            code: MtrDex.X25519_Cipher_L0,
        });
        assert.equal(matter.code, MtrDex.X25519_Cipher_L1);

        const sizage = Matter.Sizes.get(matter.code)!;
        const codeSize = sizage.hs + sizage.ss;
        const body = Uint8Array.from(
            decodeBase64Url(matter.qb64.slice(codeSize))
        );
        body[0] = 1;

        const malformed =
            matter.qb64.slice(0, codeSize) + encodeBase64Url(body);
        assert.throws(
            () => new Matter({ qb64: malformed }),
            /Nonzero midpad bytes/
        );
    });

    it('should reject nonzero fixed midpad bytes', () => {
        const matter = new Matter({
            raw: bytes(16),
            code: MtrDex.Salt_128,
        });
        const sizage = Matter.Sizes.get(matter.code)!;
        const codeSize = sizage.hs + sizage.ss;
        const prepadSize = codeSize % 4;
        const padded = Uint8Array.from(
            decodeBase64Url(
                'A'.repeat(prepadSize) + matter.qb64.slice(codeSize)
            )
        );
        padded[prepadSize - 1] = 1;

        const malformed =
            matter.qb64.slice(0, codeSize) +
            encodeBase64Url(padded).slice(prepadSize);
        assert.throws(
            () => new Matter({ qb64: malformed }),
            /Nonzero midpad bytes/
        );
    });
});
