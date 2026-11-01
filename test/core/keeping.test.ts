import libsodium from 'libsodium-wrappers-sumo';
import { assert, describe, expect, it, vitest } from 'vitest';
import {
    Diger,
    GroupIdentifierManager,
    HabState,
    IdentifierManagerFactory,
    MtrDex,
    RandyIdentifierManager,
    Salter,
    SaltyCreator,
    SaltyIdentifierManager,
    SaltyKeyState,
    Siger,
    Tier,
    b,
} from '../../src/index.ts';

describe('IdentifierManager signing', () => {
    it('reuses retained salty signers across repeated signing', async () => {
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
        const create = vitest.spyOn(SaltyCreator.prototype, 'create');

        try {
            const serialized = b('retained-salty-signers');
            const first = await manager.sign(serialized);
            const second = await manager.sign(serialized);

            expect(second).toEqual(first);
            expect(create).not.toHaveBeenCalled();
        } finally {
            create.mockRestore();
        }
    });

    it('refreshes retained salty signers for inception and rotation', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const manager = new SaltyIdentifierManager(
            salter,
            0,
            0,
            Tier.low,
            true
        );
        const constructedSigner = manager.signers[0];

        const [inceptionKeys] = await manager.incept(true);
        expect(manager.signers[0]).not.toBe(constructedSigner);
        expect(manager.signers.map((signer) => signer.verfer.qb64)).toEqual(
            inceptionKeys
        );

        const inceptionSigner = manager.signers[0];
        const [rotationKeys] = await manager.rotate(
            [MtrDex.Ed25519_Seed],
            true
        );
        expect(manager.signers[0]).not.toBe(inceptionSigner);
        expect(manager.signers.map((signer) => signer.verfer.qb64)).toEqual(
            rotationKeys
        );

        const create = vitest.spyOn(SaltyCreator.prototype, 'create');
        try {
            await manager.sign(b('rotated-retained-salty-signers'));
            expect(create).not.toHaveBeenCalled();
        } finally {
            create.mockRestore();
        }
    });

    it('hydrates fresh managers from cached signer seeds', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const { aid } = await saltyAidFixture(salter);
        const factory = new IdentifierManagerFactory(salter);
        const derive = vitest.spyOn(Salter.prototype, 'signer');

        try {
            const cold = factory.get(aid);
            const coldCalls = derive.mock.calls.length;
            const warm = factory.get(aid);

            expect(coldCalls).toBeGreaterThan(0);
            expect(derive).toHaveBeenCalledTimes(coldCalls);
            expect(warm).not.toBe(cold);
            expect(warm.signers[0]).not.toBe(cold.signers[0]);
            expect(warm.signers[0].raw).not.toBe(cold.signers[0].raw);
            expect(warm.params().icodes).not.toBe(cold.params().icodes);
            expect(warm.signers.map((signer) => signer.verfer.qb64)).toEqual(
                aid.state.k
            );

            const serialized = b('cached-salty-signers');
            expect(await warm.sign(serialized)).toEqual(
                await cold.sign(serialized)
            );
        } finally {
            derive.mockRestore();
        }
    });

    it('reuses only matching signer derivation inputs', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const { aid, manager: source } = await saltyAidFixture(salter);
        const interaction = structuredClone(aid);
        interaction.state.s = '1';
        interaction.state.d = 'interaction';
        interaction.salty.ncodes = [MtrDex.Ed25519_Seed];

        const [rotationKeys] = await source.rotate(
            [MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed],
            true
        );
        const rotated = structuredClone(aid);
        rotated.salty = source.params() as typeof aid.salty;
        rotated.state.k = rotationKeys;

        const factory = new IdentifierManagerFactory(salter);
        factory.get(aid);
        const derive = vitest.spyOn(Salter.prototype, 'signer');

        try {
            factory.get(interaction);
            expect(derive).not.toHaveBeenCalled();

            factory.get(rotated);
            const replacementCalls = derive.mock.calls.length;
            expect(replacementCalls).toBeGreaterThan(0);

            factory.get(rotated);
            expect(derive).toHaveBeenCalledTimes(replacementCalls);
        } finally {
            derive.mockRestore();
        }
    });

    it('bounds cached signer sets to sixteen prefixes', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const { aid } = await saltyAidFixture(salter);
        const aids = Array.from({ length: 17 }, (_, index) => {
            const copy = structuredClone(aid);
            copy.prefix = `aid-${index}`;
            copy.state.i = copy.prefix;
            return copy;
        });
        const factory = new IdentifierManagerFactory(salter);
        for (const state of aids) {
            factory.get(state);
        }

        const derive = vitest.spyOn(Salter.prototype, 'signer');
        try {
            factory.get(aids[16]);
            expect(derive).not.toHaveBeenCalled();

            factory.get(aids[0]);
            expect(derive).toHaveBeenCalled();
        } finally {
            derive.mockRestore();
        }
    });

    it('lazily rotates one hydrated manager without changing another', async () => {
        await libsodium.ready;

        const salter = new Salter({ raw: b('0123456789abcdef') });
        const { aid } = await saltyAidFixture(salter);
        const factory = new IdentifierManagerFactory(salter);
        factory.get(aid);
        const rotating = factory.get(aid);
        const unchanged = factory.get(aid);
        const serialized = b('isolated-hydrated-manager');
        const before = await unchanged.sign(serialized);
        const derive = vitest.spyOn(Salter.prototype, 'signer');

        try {
            await rotating.rotate([MtrDex.Ed25519_Seed], true);
            const rotationCalls = derive.mock.calls.length;
            expect(rotationCalls).toBeGreaterThan(0);
            expect(await unchanged.sign(serialized)).toEqual(before);
            expect(derive).toHaveBeenCalledTimes(rotationCalls);
            expect(rotating.signers[0].verfer.qb64).not.toEqual(
                unchanged.signers[0].verfer.qb64
            );
        } finally {
            derive.mockRestore();
        }
    });

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

async function saltyAidFixture(
    salter: Salter,
    prefix = 'salty-aid'
): Promise<{
    aid: HabState & { salty: SaltyKeyState };
    manager: SaltyIdentifierManager;
}> {
    const codes = [MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed];
    const manager = new SaltyIdentifierManager(
        salter,
        0,
        0,
        Tier.low,
        true,
        'signify:aid',
        MtrDex.Ed25519_Seed,
        codes.length,
        codes,
        MtrDex.Ed25519_Seed,
        codes.length,
        codes,
        MtrDex.Blake3_256,
        '0123456789abcdefghijk'
    );
    const [keys, nextDigests] = await manager.incept(true);
    const aid = {
        name: prefix,
        prefix,
        icp_dt: '2026-08-14T00:00:00.000000+00:00',
        salty: manager.params(),
        transferable: true,
        windexes: [],
        state: {
            i: prefix,
            s: '0',
            p: '',
            d: 'inception',
            f: '0',
            dt: '2026-08-14T00:00:00.000000+00:00',
            et: 'icp',
            kt: '2',
            k: keys,
            nt: '2',
            n: nextDigests,
            bt: '0',
            b: [],
            c: [],
            ee: { s: '0', d: 'inception' },
            di: '',
        },
    } as HabState & { salty: SaltyKeyState };

    return { aid, manager };
}
