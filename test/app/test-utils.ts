import { Mock, vitest } from 'vitest';
import {
    Algos,
    Authenticater,
    Controller,
    CreateIdentiferArgs,
    HEADER_SIG_TIME,
    IdentifierManagerFactory,
    MtrDex,
    Salter,
    Serials,
    Tier,
    Vrsn_1_0,
    incept,
} from '../../src/index.ts';
import {
    EstablishmentState,
    HabState,
    KeyState,
} from '../../src/keri/core/keyState.ts';

const boot_url = 'http://127.0.0.1:3903';

export async function createMockIdentifierState(
    name: string,
    bran: string,
    kargs: CreateIdentiferArgs = {}
): Promise<HabState> {
    const controller = new Controller(bran, Tier.low);
    const manager = new IdentifierManagerFactory(controller.salter);
    const algo = kargs.algo == undefined ? Algos.salty : kargs.algo;

    const transferable = kargs.transferable ?? true;
    const isith = kargs.isith ?? '1';
    const nsith = kargs.nsith ?? '1';
    const wits = kargs.wits ?? [];
    const toad = kargs.toad ?? 0;
    const dcode = kargs.dcode ?? MtrDex.Blake3_256;
    const proxy = kargs.proxy;
    const delpre = kargs.delpre;
    const data = kargs.data != undefined ? [kargs.data] : [];
    const pre = kargs.pre;
    const states = kargs.states;
    const rstates = kargs.rstates;
    const prxs = kargs.prxs;
    const nxts = kargs.nxts;
    const mhab = kargs.mhab;
    const _keys = kargs.keys;
    const _ndigs = kargs.ndigs;
    const count = kargs.count;
    const ncount = kargs.ncount;
    const tier = kargs.tier;
    const extern_type = kargs.extern_type;
    const extern = kargs.extern;

    const keeper = manager!.new(algo, 0, {
        transferable: transferable,
        isith: isith,
        nsith: nsith,
        wits: wits,
        toad: toad,
        proxy: proxy,
        delpre: delpre,
        dcode: dcode,
        data: data,
        algo: algo,
        pre: pre,
        prxs: prxs,
        nxts: nxts,
        mhab: mhab,
        states: states,
        rstates: rstates,
        keys: _keys,
        ndigs: _ndigs,
        bran: bran,
        count: count,
        ncount: ncount,
        tier: tier,
        extern_type: extern_type,
        extern: extern,
    });
    const [keys, ndigs] = await keeper!.incept(transferable);
    const serder = incept({
        keys: keys!,
        isith: isith,
        ndigs: ndigs,
        nsith: nsith,
        toad: toad,
        wits: wits,
        cnfg: [],
        data: data,
        version: Vrsn_1_0,
        kind: Serials.JSON,
        code: dcode,
        intive: false,
        ...(delpre ? { delpre } : {}),
    });

    return {
        name: name,
        prefix: serder.pre,
        [algo]: keeper.params(),
        transferable,
        windexes: [],
        state: {
            vn: [serder.version.major, serder.version.minor],
            s: serder.sad.s,
            d: serder.sad.d,
            i: serder.pre,
            ee: serder.sad as EstablishmentState,
            kt: serder.sad.kt,
            k: serder.sad.k,
            nt: serder.sad.nt,
            n: serder.sad.n,
            bt: serder.sad.bt,
            b: serder.sad.b,
            p: serder.sad.p ?? '',
            f: '',
            dt: new Date().toISOString().replace('Z', '000+00:00'),
            et: '',
            c: [],
            di: serder.sad.di ?? '',
        } as KeyState,
        icp_dt: '2023-12-01T10:05:25.062609+00:00',
    };
}

export const mockConnect = {
    agent: {
        vn: [1, 0],
        i: 'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei',
        s: '0',
        p: '',
        d: 'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei',
        f: '0',
        dt: '2023-08-19T21:04:57.948863+00:00',
        et: 'dip',
        kt: '1',
        k: ['DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a'],
        nt: '1',
        n: ['EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC'],
        bt: '0',
        b: [],
        c: [],
        ee: {
            s: '0',
            d: 'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei',
            br: [],
            ba: [],
        },
        di: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
    },
    controller: {
        state: {
            vn: [1, 0],
            i: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
            s: '0',
            p: '',
            d: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
            f: '0',
            dt: '2023-08-19T21:04:57.959047+00:00',
            et: 'icp',
            kt: '1',
            k: ['DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc'],
            nt: '1',
            n: ['EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL'],
            bt: '0',
            b: [],
            c: [],
            ee: {
                s: '0',
                d: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                br: [],
                ba: [],
            },
            di: '',
        },
        ee: {
            v: 'KERI10JSON00012b_',
            t: 'icp',
            d: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
            i: 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
            s: '0',
            kt: '1',
            k: ['DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc'],
            nt: '1',
            n: ['EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL'],
            bt: '0',
            b: [],
            c: [],
            a: [],
        },
    },
    ridx: 0,
    pidx: 0,
};

export const mockGetAID = {
    name: 'aid1',
    prefix: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
    salty: {
        sxlt: '1AAHnNQTkD0yxOC9tSz_ukbB2e-qhDTStH18uCsi5PCwOyXLONDR3MeKwWv_AVJKGKGi6xiBQH25_R1RXLS2OuK3TN3ovoUKH7-A',
        pidx: 0,
        kidx: 0,
        stem: 'signify:aid',
        tier: 'low',
        dcode: 'E',
        icodes: ['A'],
        ncodes: ['A'],
        transferable: true,
    },
    transferable: true,
    state: {
        vn: [1, 0],
        i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
        s: '0',
        p: '',
        d: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
        f: '0',
        dt: '2023-08-21T22:30:46.473545+00:00',
        et: 'icp',
        kt: '1',
        k: ['DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9'],
        nt: '1',
        n: ['EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc'],
        bt: '0',
        b: [],
        c: [],
        ee: {
            s: '0',
            d: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
            br: [],
            ba: [],
        },
        di: '',
    },
    windexes: [],
};

export function createMockFetch(): Mock<typeof globalThis.fetch> {
    const spy = vitest.spyOn(globalThis, 'fetch');
    function resolveUrl(input: unknown) {
        if (input instanceof URL) {
            return input;
        }

        if (typeof input === 'string') {
            return new URL(input);
        }

        if (input instanceof Request) {
            return new URL(input.url);
        }

        throw new Error('Invalid URL: ' + input);
    }

    function resolveMethod(input: unknown, init?: unknown): string {
        if (input instanceof Request) {
            return input.method ?? 'GET';
        }

        if (
            init &&
            typeof init === 'object' &&
            'method' in init &&
            typeof init.method === 'string'
        ) {
            return init.method ?? 'GET';
        }

        return 'GET';
    }

    spy.mockImplementation(async (input, init) => {
        const url = resolveUrl(input);
        const method = resolveMethod(input, init);

        if (url.pathname.startsWith('/agent')) {
            return Response.json(mockConnect, { status: 202 });
        } else if (url.toString() === boot_url + '/boot') {
            return Response.json('', { status: 202 });
        } else {
            const headers = new Headers();
            let signed_headers = new Headers();

            headers.set(
                'Signify-Resource',
                'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei'
            );
            headers.set(
                HEADER_SIG_TIME,
                new Date().toISOString().replace('Z', '000+00:00')
            );
            headers.set('Content-Type', 'application/json');

            const salter = new Salter({ qb64: '0AAwMTIzNDU2Nzg5YWJjZGVm' });
            const signer = salter.signer(
                'A',
                true,
                'agentagent-ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose00',
                Tier.low
            );

            const authn = new Authenticater(signer!, signer!.verfer);

            signed_headers = authn.sign(
                headers,
                method,

                url.pathname.split('?')[0]
            );

            if (url.pathname.startsWith('/credentials')) {
                return Response.json(mockCredential, {
                    status: 200,
                    headers: signed_headers,
                });
            }

            return Response.json(mockGetAID, {
                status: 202,
                headers: signed_headers,
            });
        }
    });

    return spy as Mock<typeof fetch>;
}

export const mockCredential = {
    sad: {
        v: 'ACDC10JSON000197_',
        d: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
        i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
        ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
        s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
        a: {
            d: 'EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P',
            i: 'EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby',
            dt: '2023-08-23T15:16:07.553000+00:00',
            LEI: '5493001KJTIIGC8Y1R17',
        },
    },
    pre: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
    sadsigers: [
        {
            path: '-',
            pre: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
            sn: 0,
            d: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
        },
    ],
    sadcigars: [],
    chains: [],
    status: {
        v: 'KERI10JSON000135_',
        i: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
        s: '0',
        d: 'ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW',
        ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
        ra: {},
        a: { s: 2, d: 'EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt' },
        dt: '2023-08-23T15:16:07.553000+00:00',
        et: 'iss',
    },
};
