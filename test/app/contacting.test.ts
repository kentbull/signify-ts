import { strict as assert } from 'assert';
import { SignifyClient } from '../../src/keri/app/clienting';
import { Authenticater } from '../../src/keri/core/authing';
import { Salter, Tier } from '../../src/keri/core/salter';
import libsodium from 'libsodium-wrappers-sumo';
import fetchMock from 'jest-fetch-mock';
import 'whatwg-fetch';

fetchMock.enableMocks();

const url = 'http://127.0.0.1:3901';
const boot_url = 'http://127.0.0.1:3903';

const mockConnect =
    '{"agent":{"vn":[1,0],"i":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",' +
    '"s":"0","p":"","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","f":"0",' +
    '"dt":"2023-08-19T21:04:57.948863+00:00","et":"dip","kt":"1",' +
    '"k":["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],"nt":"1",' +
    '"n":["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],"bt":"0","b":[],' +
    '"c":[],"ee":{"s":"0","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","br":[],"ba":[]},' +
    '"di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"},"controller":{"state":{"vn":[1,0],' +
    '"i":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","s":"0","p":"",' +
    '"d":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","f":"0","dt":"2023-08-19T21:04:57.959047+00:00",' +
    '"et":"icp","kt":"1","k":["DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc"],"nt":"1",' +
    '"n":["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],"bt":"0","b":[],"c":[],"ee":{"s":"0",' +
    '"d":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","br":[],"ba":[]},"di":""},' +
    '"ee":{"v":"KERI10JSON00012b_","t":"icp","d":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",' +
    '"i":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","s":"0","kt":"1",' +
    '"k":["DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc"],"nt":"1",' +
    '"n":["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],"bt":"0","b":[],"c":[],"a":[]}},"ridx":0,' +
    '"pidx":0}';
const mockGetAID = {
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

fetchMock.mockResponse((req) => {
    if (req.url.startsWith(url + '/agent')) {
        return Promise.resolve({ body: mockConnect, init: { status: 202 } });
    } else if (req.url == boot_url + '/boot') {
        return Promise.resolve({ body: '', init: { status: 202 } });
    } else {
        const headers = new Headers();
        let signed_headers = new Headers();

        headers.set(
            'Signify-Resource',
            'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei'
        );
        headers.set(
            'Signify-Timestamp',
            new Date().toISOString().replace('Z', '000+00:00')
        );
        headers.set('Content-Type', 'application/json');

        const requrl = new URL(req.url);
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
            req.method,
            requrl.pathname.split('?')[0]
        );
        const body = mockGetAID;

        return Promise.resolve({
            body: JSON.stringify(body),
            init: { status: 202, headers: signed_headers },
        });
    }
});

describe('Contacting', () => {
    it('Contacts', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';

        const client = new SignifyClient(url, bran, Tier.low, boot_url);

        await client.boot();
        await client.connect();

        const contacts = client.contacts();

        await contacts.list('mygroup', 'company', 'mycompany');
        let lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(
            lastCall[0]!,
            url +
                '/contacts?group=mygroup&filter_field=company&filter_value=mycompany'
        );
        assert.equal(lastCall[1]!.method, 'GET');

        await contacts.get('EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao');
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(
            lastCall[0]!,
            url + '/contacts/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        assert.equal(lastCall[1]!.method, 'GET');

        const info = {
            name: 'John Doe',
            company: 'My Company',
        };
        await contacts.add(
            'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
            info
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        let lastBody = JSON.parse(lastCall[1]!.body!.toString());
        assert.equal(
            lastCall[0]!,
            url + '/contacts/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        assert.equal(lastCall[1]!.method, 'POST');
        assert.deepEqual(lastBody, info);

        await contacts.update(
            'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
            info
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        lastBody = JSON.parse(lastCall[1]!.body!.toString());
        assert.equal(
            lastCall[0]!,
            url + '/contacts/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        assert.equal(lastCall[1]!.method, 'PUT');
        assert.deepEqual(lastBody, info);

        await contacts.delete('EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao');
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(
            lastCall[0]!,
            url + '/contacts/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        assert.equal(lastCall[1]!.method, 'DELETE');
        assert.equal(lastCall[1]!.body, undefined);
    });

    it('Challenges', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';

        const client = new SignifyClient(url, bran, Tier.low, boot_url);

        await client.boot();
        await client.connect();

        const challenges = client.challenges();

        await challenges.generate(128);
        let lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(lastCall[0]!, url + '/challenges?strength=128');
        assert.equal(lastCall[1]!.method, 'GET');

        const words = [
            'shell',
            'gloom',
            'mimic',
            'cereal',
            'stool',
            'furnace',
            'nominee',
            'nation',
            'sauce',
            'sausage',
            'rather',
            'venue',
        ];
        await challenges.respond(
            'aid1',
            'EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p',
            words
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(lastCall[0]!, url + '/identifiers/aid1/exchanges');
        assert.equal(lastCall[1]!.method, 'POST');
        let lastBody = JSON.parse(lastCall[1]!.body!.toString());
        assert.equal(lastBody.tpc, 'challenge');
        assert.equal(lastBody.exn.r, '/challenge/response');
        assert.equal(
            lastBody.exn.i,
            'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK'
        );
        assert.deepEqual(lastBody.exn.a.words, words);
        assert.equal(lastBody.sigs[0].length, 88);

        await challenges.verify(
            'EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p',
            words
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(
            lastCall[0]!,
            url +
                '/challenges_verify/EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p'
        );
        assert.equal(lastCall[1]!.method, 'POST');
        lastBody = JSON.parse(lastCall[1]!.body!.toString());
        assert.deepEqual(lastBody.words, words);

        await challenges.responded(
            'EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p',
            'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert.equal(
            lastCall[0]!,
            url +
                '/challenges_verify/EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p'
        );
        assert.equal(lastCall[1]!.method, 'PUT');
        lastBody = JSON.parse(lastCall[1]!.body!.toString());
        assert.equal(
            lastBody.said,
            'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
    });
});
