// write a test in jest of the Parser class
import { Parser } from '../../src/keri/core/parsing';
import signify, { b, d, Diger, incept, MtrDex, Salter, Tier } from "../../src";

describe('Parser', () => {
    let parser: Parser;

    beforeEach(() => {
        parser = new Parser();
    });

    it('should create a new Parser instance', async () => {
        await signify.ready();
        const raw = b('ABCDEFGH01234567');
        const signers = new Salter({ raw }).signers(8, 'psr', MtrDex.Ed25519_Seed, true, 0, Tier.low, true);

        const signKey1qb64 = signers[0].verfer.qb64;
        const rotKey1qb64b = signers[1].verfer.qb64b;
        const rotKey1Digest = new Diger({code: MtrDex.Blake3_256}, rotKey1qb64b).qb64
        expect(signers[0].verfer.qb64).toEqual(signKey1qb64)

        const icp0 = incept({
            keys: [signKey1qb64],
            ndigs: [rotKey1Digest]
        })


        expect(parser).toBeInstanceOf(Parser);
    });
});
