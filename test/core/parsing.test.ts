// write a test in jest of the Parser class
import { Parser } from '../../src/keri/core/parsing';
import signify, {
    b,
    Counter,
    CtrDex,
    d,
    Diger,
    incept,
    interact,
    MtrDex,
    rotate,
    Salter,
    Serials,
    Tier,
    Vrsn_1_0,
} from '../../src';

describe('Parser', () => {
    let parser: Parser;

    beforeEach(() => {
        parser = new Parser();
    });

    it('should create a new Parser instance', async () => {
        expect(parser).toBeInstanceOf(Parser);
        await signify.ready();
        const raw = b('ABCDEFGH01234567');
        const signers = new Salter({ raw }).signers(
            8,
            'psr',
            MtrDex.Ed25519_Seed,
            true,
            0,
            Tier.low,
            true
        );
        let signKey = signers[0]; // first key is used for inception as signing key
        let nextKey = signers[1]; // second key is used to specify the next key digest

        const icp0KeyQb64 = signKey.verfer.qb64;
        const rot1KeyQb64b = nextKey.verfer.qb64b;
        const rot1KeyDigest = new Diger(
            { code: MtrDex.Blake3_256 },
            rot1KeyQb64b
        ).qb64;
        expect(signKey.verfer.qb64).toEqual(icp0KeyQb64);

        // raw CESR stream for all messages for KEL - to send to Parser later
        let msgs = Buffer.alloc(0);

        // Event 0, inception (first event)
        const icp0Srdr = incept({
            keys: [icp0KeyQb64],
            ndigs: [rot1KeyDigest],
        });
        const eventDigs = [icp0Srdr.said];
        let counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        let siger = signKey.sign(b(icp0Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(icp0Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        expect(d(msgs)).toEqual(
            `{` +
                `"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF",` +
                `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":"1",` +
                `"k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1",` +
                `"n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}` +
                `-AABAAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E`
        );

        // Event 1, Rotation transferable (second event)
        signKey = signers[1];
        nextKey = signers[2];
        const rot1KeyQb64 = signKey.verfer.qb64; // use key from prior event (prior next key) as current signing key
        const rot2KeyQb64b = nextKey.verfer.qb64b;
        const rot2KeyDigest = new Diger(
            { code: MtrDex.Blake3_256 },
            rot2KeyQb64b
        ).qb64;
        const rot1Srdr = rotate({
            pre: icp0Srdr.pre,
            keys: [rot1KeyQb64],
            dig: icp0Srdr.said,
            ndigs: [rot2KeyDigest],
            sn: 1,
        });
        eventDigs.push(rot1Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(rot1Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(rot1Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        expect(d(msgs)).toEqual(
            `{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF",` +
                `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":"1",` +
                `"k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1",` +
                `"n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}` +
                `-AABAAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E` +
                `{"v":"KERI10JSON000160_","t":"rot","d":"EJDbQDHpeEoKjZLbs08GKBxIXhe9T-Xi7mbejQmJdnZG",` +
                `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"1","p":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF",` +
                `"kt":"1","k":["DOwvH3i0ceL1GBqaLxecDIsk6NFDL-Qv6SFq5Gj6JMAB"],` +
                `"nt":"1","n":["EFOcjb2T4uNP6C20sStcAzOyXDU27_2vWpTzAFbTarAc"],"bt":"0","br":[],"ba":[],"a":[]}` +
                `-AABAAD29Xiiek51i8FBEIenIDOOj0j3CuKbIeRK9aNNSyMyyH88ho9qb6ietcQjKy4bcERbCHC5t7fkdt7jMW8YT5IN`
        );

        // Event 2, Rotation Transferable (third event)
        signKey = signers[2];
        nextKey = signers[3];
        const rot2KeyQb64 = signKey.verfer.qb64; // use key from prior event (prior next key) as current signing key
        const rot3KeyQb64b = nextKey.verfer.qb64b; // next key of 8 signers to use as next rotation key
        const rot3KeyDigest = new Diger(
            { code: MtrDex.Blake3_256 },
            rot3KeyQb64b
        ).qb64;
        const rot2Srdr = rotate({
            pre: icp0Srdr.pre,
            keys: [rot2KeyQb64],
            dig: rot1Srdr.said,
            ndigs: [rot3KeyDigest],
            sn: 2,
        });
        eventDigs.push(rot2Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(rot2Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(rot2Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        // Event 3, Interaction (fourth event)
        const ixn3Srdr = interact({
            pre: icp0Srdr.pre,
            dig: rot2Srdr.said,
            sn: 3,
            data: [],
            kind: Serials.JSON,
            version: Vrsn_1_0,
        });
        eventDigs.push(ixn3Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(ixn3Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(ixn3Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        // Event 4, Interaction (fifth event)
        const ixn4Srdr = interact({
            pre: icp0Srdr.pre,
            dig: ixn3Srdr.said,
            sn: 4,
            data: [],
            kind: Serials.JSON,
            version: Vrsn_1_0,
        });
        eventDigs.push(ixn4Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(ixn4Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(ixn4Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        // Event 5, Rotation (sixth event)
        signKey = signers[3];
        nextKey = signers[4];
        const rot3KeyQb64 = signKey.verfer.qb64;
        const rot5KeyQb64b = nextKey.verfer.qb64b;
        const rot5KeyDigest = new Diger(
            { code: MtrDex.Blake3_256 },
            rot5KeyQb64b
        ).qb64;
        const rot5Srdr = rotate({
            pre: icp0Srdr.pre,
            keys: [rot3KeyQb64],
            dig: ixn4Srdr.said,
            ndigs: [rot5KeyDigest],
            sn: 5,
        });
        eventDigs.push(rot5Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(rot5Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(rot5Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        // Event 6, Interaction (seventh event)
        const ixn6Srdr = interact({
            pre: icp0Srdr.pre,
            dig: rot5Srdr.said,
            sn: 6,
            data: [],
            kind: Serials.JSON,
            version: Vrsn_1_0,
        });
        eventDigs.push(ixn6Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(ixn6Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(ixn6Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        // Event 7, Rotation to null non-transferable (abandon keypair) - eighth event
        signKey = signers[4];
        const rot5KeyQb64 = signKey.verfer.qb64;
        const rot7Srdr = rotate({
            pre: icp0Srdr.pre,
            keys: [rot5KeyQb64],
            dig: ixn6Srdr.said,
            sn: 7,
        });
        eventDigs.push(rot7Srdr.said);
        counter = new Counter({ code: CtrDex.ControllerIdxSigs });
        siger = signKey.sign(b(rot7Srdr.raw), 0);
        msgs = Buffer.concat([msgs, b(rot7Srdr.raw)]);
        msgs = Buffer.concat([msgs, counter.qb64b]);
        msgs = Buffer.concat([msgs, siger.qb64b]);

        expect(msgs.length).toEqual(3006);
        // @formatter:off
        // prettier-ignore
        const keripyCESRStr =
          // event 1 icp, sn 0
           `{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0",`
          + `"kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],`
          + `"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}`
          + `-AABAAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E`
          // event 2 rot, sn 1
          +`{"v":"KERI10JSON000160_","t":"rot","d":"EJDbQDHpeEoKjZLbs08GKBxIXhe9T-Xi7mbejQmJdnZG",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"1","p":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF",`
          + `"kt":"1","k":["DOwvH3i0ceL1GBqaLxecDIsk6NFDL-Qv6SFq5Gj6JMAB"],`
          + `"nt":"1","n":["EFOcjb2T4uNP6C20sStcAzOyXDU27_2vWpTzAFbTarAc"],"bt":"0","br":[],"ba":[],"a":[]}`
          + `-AABAAD29Xiiek51i8FBEIenIDOOj0j3CuKbIeRK9aNNSyMyyH88ho9qb6ietcQjKy4bcERbCHC5t7fkdt7jMW8YT5IN`
          // event 3 rot, sn 2
          +`{"v":"KERI10JSON000160_","t":"rot","d":"EHdVYE9HBxEBFMzEyo8Cbp1BBzsbbUFyZ4qQ3L5kZVnO",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"2","p":"EJDbQDHpeEoKjZLbs08GKBxIXhe9T-Xi7mbejQmJdnZG",`
          + `"kt":"1","k":["DAGO1PiBVK8Jzj0GqN871WJJAL6DXtZ_7BeSb8LakAbS"],`
          + `"nt":"1","n":["EEPCpzJEEBdbSkTVJB92tn5aLmWyeBMUdz0iDtyNdgdn"],"bt":"0","br":[],"ba":[],"a":[]}`
          + `-AABAADEpCJe4OAw-L7_NFx7Cm-SEBva6pHTE7PzcemJ8LDv5sBaak0F3v9DkqSKXAjT8xe0dF6CAAiprpnt9-NompUB`
          // event 4 ixn, sn 3
          +`{"v":"KERI10JSON0000cb_","t":"ixn","d":"EK0IxKaIRCIW197CaM24cjlOP9dLuvcRQ4hsUbI-czFc",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"3","p":"EHdVYE9HBxEBFMzEyo8Cbp1BBzsbbUFyZ4qQ3L5kZVnO","a":[]}`
          + `-AABAABSGEUpho310XVTOJs355Yz6zruY4T6DwAEOln20nvfu-NtG8KhUimxvcL98V2oibSdtD3KZQc5wDmkkDG6duQN`
          +`{"v":"KERI10JSON0000cb_","t":"ixn","d":"EDia68NPn8go5ZEG-aFRVQx35bTbd2KdkX8wjaDZnfQT",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"4","p":"EK0IxKaIRCIW197CaM24cjlOP9dLuvcRQ4hsUbI-czFc","a":[]}`
          + `-AABAACmmvkaQSj6GIsi6GY2gM6dF0j6jJldCDlPSllK9F-rB8oBsf6Zw5RNgtQf1ybkAdO_QF6-zjsH8X4DwN1PLAMH`
          // event 5 rot, sn 5
          +`{"v":"KERI10JSON000160_","t":"rot","d":"EM0X0dMakhwj_H-WoaAtESja6d952Fi1JDrUtp1tGQTf",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"5","p":"EDia68NPn8go5ZEG-aFRVQx35bTbd2KdkX8wjaDZnfQT",`
          + `"kt":"1","k":["DMkoIldTmEcAPMTUYvdG40e0MMYXJYVQKVMe8RnZCctX"],`
          + `"nt":"1","n":["EMYJJC96GwDK0rO6RKgz5R8ehShJbRPk6Y4NYq7URiNp"],"bt":"0","br":[],"ba":[],"a":[]}`
          + `-AABAACVy62ybeKd4spCvB0w0q3vop9Vgs6loCMyfBYssfUbHM7iR59a9eZBWSdrOGR_684br3j_7QB6FFs0yhgI9-UB`
          // event 6 ixn, sn 6
          +`{"v":"KERI10JSON0000cb_","t":"ixn","d":"ECMrnSaWbI9lHX5GtuWu4_cNDNW--8jyn2RTUepjGUBn",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"6","p":"EM0X0dMakhwj_H-WoaAtESja6d952Fi1JDrUtp1tGQTf","a":[]}`
          + `-AABAACfFj5T8P1caAC_wmn8D7MQYzgFai8WP8BN8HI42cpBmE7wU2gJy4HSzt6CKFJgKmrjWx1qYMupiZoGgQg-9nME`
          // event 7 rot, sn 7
          +`{"v":"KERI10JSON000132_","t":"rot","d":"EHTwtT_CHN5WjnbNIwmHzOtXIJ7oN0mntOSYZISYob6A",`
          + `"i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"7","p":"ECMrnSaWbI9lHX5GtuWu4_cNDNW--8jyn2RTUepjGUBn",`
          + `"kt":"1","k":["DHMGP2ArtkaBPTXyY48smcESmoaUFT5hYBrLNi8ul2tZ"],`
          + `"nt":"0","n":[],"bt":"0","br":[],"ba":[],"a":[]}`
          + `-AABAABLPx9jZm8wjHMJaUw176A59cRWLitDnjx1F0C1y2E2T8QNnL2F6YsA1DdkueixoaMN0bCVqxAHL80xfrADfycP`;
        // @formatter:on
        // TODO try to interact and rotate after abandonment and verify that an error is thrown
        expect(d(msgs)).toEqual(keripyCESRStr);

        const cesrMsgs = [];
        for (const msg of parser.parse(msgs)) {
            if (msg) {
                cesrMsgs.push(msg);
            }
        }
        expect(cesrMsgs.length).toBe(8);
    });
});
