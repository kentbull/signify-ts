import libsodium from 'libsodium-wrappers-sumo';
import { assert, describe, expect, it, vitest } from 'vitest';
import {
    Controller,
    Diger,
    GroupIdentifierManager,
    MtrDex,
    RandyIdentifierManager,
    Salter,
    SaltyIdentifierManager,
    Siger,
    Tier,
    b,
} from '../../src/index.ts';
import { createMockIdentifierState } from '../app/test-utils.ts';

describe('IdentifierManager signing', () => {
    it('uses rotated=true to derive group rotation ondex', async () => {
        await libsodium.ready;

        const { keys, priorNextDigests } = groupSigningFixtures();
        const ser = b('not a keri event');
        const mhab = {
            state: {
                k: [keys[2]],
                n: [priorNextDigests[2]],
            },
        };
        const memberSign = vitest.fn().mockResolvedValue(['signature']);
        const manager = {
            get: vitest.fn().mockReturnValue({ sign: memberSign }),
        };
        const group = new GroupIdentifierManager(
            manager as never,
            mhab as never,
            undefined,
            undefined,
            keys.slice(0, 3),
            priorNextDigests
        );

        // The call-site flag decides whether group signing must expose prior-next ondex for a rotation signature.
        await group.sign(ser, true, undefined, undefined, true);

        expect(memberSign).toHaveBeenCalledWith(ser, true, [2], [2]);
    });

    it('uses rotated=false to keep group signatures current-only', async () => {
        await libsodium.ready;

        const { keys, priorNextDigests } = groupSigningFixtures();
        const ser = b('not a keri event');
        const mhab = {
            state: {
                k: [keys[0]],
                n: [priorNextDigests[0]],
            },
        };
        const memberSign = vitest.fn().mockResolvedValue(['signature']);
        const manager = {
            get: vitest.fn().mockReturnValue({ sign: memberSign }),
        };
        const group = new GroupIdentifierManager(
            manager as never,
            mhab as never,
            undefined,
            undefined,
            keys.slice(0, 3),
            priorNextDigests
        );

        // Non-rotation group signatures satisfy the current signing threshold
        // only, so ondex is intentionally suppressed.
        await group.sign(ser, true, undefined, undefined, false);

        expect(memberSign).toHaveBeenCalledWith(ser, true, [0], [undefined]);
    });

    it('allows SaltyIdentifierManager to create current-only indexed signatures with ondices=[undefined]', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const manager = new SaltyIdentifierManager(
            salter,
            0,
            0,
            Tier.low,
            true
        );
        await manager.incept(true);

        // Group non-rotation signing passes ondices=[undefined]; Salty must
        // preserve that as a current-only indexed signature.
        const sigs = await manager.sign(
            b('current-only-salty'),
            true,
            [0],
            [undefined]
        );

        const siger = new Siger({ qb64: sigs[0] });
        assert.equal(siger.index, 0);
        assert.equal(siger.ondex, undefined);
    });

    it('allows RandyIdentifierManager to create current-only indexed signatures with ondices=[undefined]', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const manager = new RandyIdentifierManager(
            salter,
            MtrDex.Ed25519_Seed,
            1,
            undefined,
            true,
            MtrDex.Ed25519_Seed,
            1,
            [MtrDex.Ed25519_Seed]
        );
        await manager.incept(true);

        // Randy uses encrypted stored keys, so this separately guards the same
        // current-only ondex contract through the Randy keeper path.
        const sigs = await manager.sign(
            b('current-only-randy'),
            true,
            [0],
            [undefined]
        );

        const siger = new Siger({ qb64: sigs[0] });
        assert.equal(siger.index, 0);
        assert.equal(siger.ondex, undefined);
    });
});

describe('IdentifierManagerFactory signer cache', () => {
    it('reconstructs isolated salty managers from signer snapshots', async () => {
        await libsodium.ready;

        const bran = '0123456789abcdefghijk';
        const aid = await createMockIdentifierState('aid1', bran, {
            count: 2,
            ncount: 2,
        });
        if (!('salty' in aid)) {
            throw new Error('Expected a salty identifier fixture.');
        }

        const salter = new Controller(bran, Tier.low).salter;
        const cold = SaltyIdentifierManager.fromState(salter, aid.salty);
        const snapshot = Object.freeze({
            publicKeys: Object.freeze([...aid.state.k]),
            signerQb64s: Object.freeze(
                cold.signers.map((signer) => signer.qb64)
            ),
        });
        const stretch = vitest.spyOn(Salter.prototype, 'signer');

        try {
            const first = SaltyIdentifierManager.fromState(
                salter,
                aid.salty,
                snapshot
            );
            const second = SaltyIdentifierManager.fromState(
                salter,
                aid.salty,
                snapshot
            );

            expect(first).not.toBe(second);
            expect(first.signers).not.toBe(second.signers);
            expect(first.signers[0]).not.toBe(second.signers[0]);
            expect(first.signers[0].raw).not.toBe(second.signers[0].raw);
            expect(first.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );
            expect(second.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );
            expect(stretch).not.toHaveBeenCalled();

            const serialized = b('snapshot-isolation');
            const firstSignatures = await first.sign(serialized);
            const secondSignatures = await second.sign(serialized);
            expect(firstSignatures).toEqual(secondSignatures);
            expect(stretch).not.toHaveBeenCalled();

            const secondRaw = Uint8Array.from(second.signers[0].raw);
            first.signers[0].raw[0] ^= 0xff;
            first.signers.pop();
            const exposedParams = first.params();
            exposedParams.icodes![0] = MtrDex.Ed25519N;
            exposedParams.ncodes!.pop();

            expect(first.params().icodes).toEqual(aid.salty.icodes);
            expect(first.params().ncodes).toEqual(aid.salty.ncodes);
            expect(second.signers[0].raw).toEqual(secondRaw);
            expect(second.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );

            const third = SaltyIdentifierManager.fromState(
                salter,
                aid.salty,
                snapshot
            );
            expect(third.signers[0]).not.toBe(second.signers[0]);
            expect(third.signers[0].raw).not.toBe(second.signers[0].raw);
            expect(await third.sign(serialized)).toEqual(secondSignatures);
            expect(stretch).not.toHaveBeenCalled();

            await first.rotate([...aid.salty.ncodes], false);
            expect(first.signers[0].verfer.transferable).toBe(false);
            expect(second.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );
            expect(second.params().kidx).toBe(aid.salty.kidx);
            expect(stretch).toHaveBeenCalled();
        } finally {
            stretch.mockRestore();
        }
    });
});

function groupSigningFixtures() {
    const salter = new Salter({ raw: b('0123456789abcdef') });
    const signers = [0, 1, 2, 3].map((idx) =>
        salter.signer(
            MtrDex.Ed25519_Seed,
            true,
            `member-${idx}`,
            Tier.low,
            true
        )
    );
    const keys = signers.map((signer) => signer.verfer.qb64);
    const priorNextDigests = signers
        .slice(0, 3)
        .map((signer) => new Diger({}, signer.verfer.qb64b).qb64);

    return { keys, priorNextDigests };
}
