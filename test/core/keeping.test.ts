import libsodium from 'libsodium-wrappers-sumo';
import { assert, describe, expect, it, vitest } from 'vitest';
import {
    Controller,
    Diger,
    GroupIdentifierManager,
    type HabState,
    IdentifierManagerFactory,
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

        expect(manager.get).toHaveBeenCalledOnce();
        expect(manager.get).toHaveBeenCalledWith(mhab);
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

    it('keeps caching opt-in and reuses a verified multi-key establishment', async () => {
        await libsodium.ready;

        const bran = '0123456789abcdefghijk';
        const aid = await createMockIdentifierState('aid1', bran, {
            count: 3,
            ncount: 3,
        });
        const salter = new Controller(bran, Tier.low).salter;
        const stretch = vitest.spyOn(Salter.prototype, 'signer');

        try {
            const uncached = new IdentifierManagerFactory(salter);
            uncached.get(aid);
            stretch.mockClear();
            uncached.get(aid);
            expect(stretch).toHaveBeenCalled();

            const cached = new IdentifierManagerFactory(salter, [], true);
            stretch.mockClear();
            const cold = cached.get(aid);
            expect(cold.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );
            expect(stretch).toHaveBeenCalled();

            stretch.mockClear();
            const warm = cached.get(aid);
            expect(warm).not.toBe(cold);
            expect(warm.signers[0]).not.toBe(cold.signers[0]);
            expect(stretch).not.toHaveBeenCalled();

            const interaction = structuredClone(aid) as HabState;
            interaction.state.s = '1';
            interaction.state.d = 'EInteractionHead';
            const afterInteraction = cached.get(interaction);
            expect(afterInteraction).not.toBe(warm);
            expect(stretch).not.toHaveBeenCalled();
            expect(JSON.stringify(cached)).not.toContain(cold.signers[0].qb64);
        } finally {
            stretch.mockRestore();
        }
    });

    it('rejects invalid or conflicting observations without replacing the verified entry', async () => {
        await libsodium.ready;

        const bran = '0123456789abcdefghijk';
        const aid = await createMockIdentifierState('aid1', bran, {
            count: 3,
            ncount: 3,
        });
        if (!('salty' in aid)) {
            throw new Error('Expected a salty identifier fixture.');
        }

        const factory = new IdentifierManagerFactory(
            new Controller(bran, Tier.low).salter,
            [],
            true
        );
        const accepted = factory.get(aid);
        const signerQb64 = accepted.signers[0].qb64;

        const wrongPrefix = structuredClone(aid) as HabState;
        wrongPrefix.prefix = 'EWrongPrefix';

        const invalidSequence = structuredClone(aid) as HabState;
        invalidSequence.state.ee.s = '0x1';

        const conflictingDigest = structuredClone(aid) as HabState;
        conflictingDigest.state.ee.d = 'EConflictingDigest';

        const conflictingKeys = structuredClone(aid) as HabState;
        conflictingKeys.state.k = [...conflictingKeys.state.k].reverse();

        const invalidHigher = structuredClone(aid) as HabState;
        invalidHigher.state.ee.s = '1';
        invalidHigher.state.ee.d = 'EHigherEstablishment';
        invalidHigher.state.k = [...invalidHigher.state.k].reverse();

        const errors = [
            captureError(() => factory.get(wrongPrefix)),
            captureError(() => factory.get(invalidSequence)),
            captureError(() => factory.get(conflictingDigest)),
            captureError(() => factory.get(conflictingKeys)),
            captureError(() => factory.get(invalidHigher)),
        ];
        for (const message of errors) {
            expect(message).not.toContain(aid.salty.sxlt);
            expect(message).not.toContain(signerQb64);
        }

        const stretch = vitest.spyOn(Salter.prototype, 'signer');
        try {
            const stillWarm = factory.get(aid);
            expect(
                stillWarm.signers.map((signer) => signer.verfer.qb64)
            ).toEqual(aid.state.k);
            expect(stretch).not.toHaveBeenCalled();
        } finally {
            stretch.mockRestore();
        }
    });

    it('replaces only with a verified numerically newer establishment', async () => {
        await libsodium.ready;

        const bran = '0123456789abcdefghijk';
        const aid = await createMockIdentifierState('aid1', bran);
        if (!('salty' in aid)) {
            throw new Error('Expected a salty identifier fixture.');
        }

        const acceptedAtF = structuredClone(aid) as HabState;
        acceptedAtF.state.ee.s = 'f';
        const factory = new IdentifierManagerFactory(
            new Controller(bran, Tier.low).salter,
            [],
            true
        );
        factory.get(acceptedAtF);

        const operation = factory.get(acceptedAtF) as SaltyIdentifierManager;
        const [rotatedKeys] = await operation.rotate(
            [...aid.salty.ncodes],
            true
        );
        const acceptedAtTen = structuredClone(acceptedAtF) as HabState;
        if (!('salty' in acceptedAtTen)) {
            throw new Error('Expected a salty identifier fixture.');
        }
        acceptedAtTen.salty = operation.params() as typeof acceptedAtTen.salty;
        acceptedAtTen.state.ee.s = '10';
        acceptedAtTen.state.ee.d = 'ENumericallyNewerEstablishment';
        acceptedAtTen.state.k = rotatedKeys;

        const stretch = vitest.spyOn(Salter.prototype, 'signer');
        try {
            const replacement = factory.get(acceptedAtTen);
            expect(
                replacement.signers.map((signer) => signer.verfer.qb64)
            ).toEqual(rotatedKeys);
            expect(stretch).toHaveBeenCalled();

            expect(() => factory.get(acceptedAtF)).toThrow(
                'establishment regression'
            );
        } finally {
            stretch.mockRestore();
        }
    });

    it('evicts the least-recently-used signer set and clears the cache', async () => {
        await libsodium.ready;

        const bran = '0123456789abcdefghijk';
        const aid = await createMockIdentifierState('aid1', bran);
        const factory = new IdentifierManagerFactory(
            new Controller(bran, Tier.low).salter,
            [],
            true
        );
        const states = Array.from({ length: 17 }, (_, index) => {
            const state = structuredClone(aid) as HabState;
            state.prefix = `ESyntheticPrefix${index}`;
            state.state.i = state.prefix;
            return state;
        });
        const stretch = vitest.spyOn(Salter.prototype, 'signer');

        try {
            for (const state of states.slice(0, 16)) {
                factory.get(state);
            }

            stretch.mockClear();
            factory.get(states[0]);
            expect(stretch).not.toHaveBeenCalled();

            factory.get(states[16]);
            expect(stretch).toHaveBeenCalled();

            stretch.mockClear();
            factory.get(states[0]);
            expect(stretch).not.toHaveBeenCalled();

            factory.get(states[1]);
            expect(stretch).toHaveBeenCalled();

            factory.clearSignerCache();
            stretch.mockClear();
            factory.get(states[0]);
            expect(stretch).toHaveBeenCalled();
        } finally {
            stretch.mockRestore();
        }
    }, 30000);
});

function captureError(action: () => void): string {
    let thrown: unknown;
    try {
        action();
    } catch (error) {
        thrown = error;
    }

    expect(thrown).toBeInstanceOf(Error);
    return (thrown as Error).message;
}

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
