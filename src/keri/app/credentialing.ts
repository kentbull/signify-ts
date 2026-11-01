import { SignifyClient } from './clienting.ts';
import { interact, messagize } from '../core/eventing.ts';
import { vdr } from '../core/vdring.ts';
import {
    b,
    d,
    Dict,
    Protocols,
    Ilks,
    Serials,
    versify,
    Vrsn_1_0,
} from '../core/core.ts';
import { Saider } from '../core/saider.ts';
import { Serder } from '../core/serder.ts';
import { Siger } from '../core/siger.ts';
import { TraitDex } from './habery.ts';
import {
    serializeACDCAttachment,
    serializeIssExnAttachment,
} from '../core/utils.ts';
import {
    ExchangeOperation,
    CredentialOperation,
    ExnV1,
    GroupKeyState,
    GroupOperation,
    DelegationOperation,
    WitnessOperation,
    DoneOperation,
    HabState,
    RegistryOperation,
} from '../core/keyState.ts';
import type { ExchangeResourceV1 } from './exchanging.ts';

import { components } from '../../types/keria-api-schema.ts';

export type CredentialResult = components['schemas']['Credential'];
export type Registry = components['schemas']['Registry'];
export type Schema = components['schemas']['Schema'];

type GroupHabState = HabState & { group: GroupKeyState };

function isGroupHab(hab: HabState): hab is GroupHabState {
    return 'group' in hab;
}

/** Types of credentials */
export class CredentialTypes {
    static issued = 'issued';
    static received = 'received';
}

/** Credential filter parameters */
export interface CredentialFilter {
    filter?: object;
    sort?: object[];
    skip?: number;
    limit?: number;
}

export interface CredentialSubject {
    /**
     * Issuee, or holder of the credential.
     */
    i?: string;
    /**
     * Timestamp of issuance.
     */
    dt?: string;
    /**
     * Privacy salt
     */
    u?: string;
    [key: string]: unknown;
}

export interface CredentialData {
    v?: string;
    d?: string;
    /**
     * Privacy salt
     */
    u?: string;
    /**
     * Issuer of the credential.
     */
    i?: string;
    /**
     * Registry id.
     */
    ri?: string;
    /**
     * Schema id
     */
    s?: string;
    /**
     * Credential subject data
     */
    a: CredentialSubject;
    /**
     * Credential source section
     */
    e?: { [key: string]: unknown };
    /**
     * Credential rules section
     */
    r?: { [key: string]: unknown };
}

export interface IssueCredentialResult {
    acdc: Serder;
    anc: Serder;
    iss: Serder;
    op: CredentialOperation;
}

export interface RevokeCredentialResult {
    anc: Serder;
    rev: Serder;
    op: GroupOperation | DelegationOperation | WitnessOperation | DoneOperation;
}

export interface IpexApplyArgs {
    /**
     * Alias for the IPEX sender AID
     */
    senderName: string;

    /**
     * Prefix of the IPEX recipient AID
     */
    recipient: string;

    /**
     * Message to send
     */
    message?: string;

    /**
     * SAID of schema to apply for
     */
    schemaSaid: string;

    /**
     * Optional attributes for selective disclosure
     */
    attributes?: Record<string, unknown>;
    datetime?: string;
}

export interface IpexOfferArgs {
    /**
     * Alias for the IPEX sender AID
     */
    senderName: string;

    /**
     * Prefix of the IPEX recipient AID
     */
    recipient: string;

    /**
     * Message to send
     */
    message?: string;

    /**
     * ACDC to offer
     */
    acdc: Serder;

    /**
     * Optional qb64 SAID of apply message this offer is responding to
     */
    applySaid?: string;
    datetime?: string;
}

export interface IpexAgreeArgs {
    /**
     * Alias for the IPEX sender AID
     */
    senderName: string;

    /**
     * Prefix of the IPEX recipient AID
     */
    recipient: string;

    /**
     * Message to send
     */
    message?: string;

    /**
     * qb64 SAID of offer message this agree is responding to
     */
    offerSaid: string;
    datetime?: string;
}

export interface IpexGrantArgs {
    /**
     * Alias for the IPEX sender AID
     */
    senderName: string;

    /**
     * Prefix of the IPEX recipient AID
     */
    recipient: string;

    /**
     * Message to send
     */
    message?: string;

    /**
     * qb64 SAID of agree message this grant is responding to
     */
    agreeSaid?: string;
    datetime?: string;
    acdc: Serder;
    acdcAttachment?: string;
    iss: Serder;
    issAttachment?: string;
    anc: Serder;
    ancAttachment?: string;
}

export interface IpexAdmitArgs {
    /**
     * Alias for the IPEX sender AID
     */
    senderName: string;

    /**
     * Prefix of the IPEX recipient AID
     */
    recipient: string;

    /**
     * Message to send
     */
    message?: string;

    /**
     * qb64 SAID of agree message this admit is responding to
     */
    grantSaid: string;
    datetime?: string;
}

export type CredentialState = components['schemas']['CredentialState'];

/**
 * Credentials
 */
export class Credentials {
    public client: SignifyClient;
    /**
     * Credentials
     * @param {SignifyClient} client
     */
    constructor(client: SignifyClient) {
        this.client = client;
    }

    /**
     * List credentials
     * @async
     * @param {CredentialFilter} [kargs] Optional parameters to filter the credentials
     * @returns {Promise<CredentialResult[]>} A promise to the list of credentials
     */
    async list(kargs: CredentialFilter = {}): Promise<CredentialResult[]> {
        const path = `/credentials/query`;
        const filtr = kargs.filter === undefined ? {} : kargs.filter;
        const sort = kargs.sort === undefined ? [] : kargs.sort;
        const limit = kargs.limit === undefined ? 25 : kargs.limit;
        const skip = kargs.skip === undefined ? 0 : kargs.skip;

        const data = {
            filter: filtr,
            sort: sort,
            skip: skip,
            limit: limit,
        };
        const method = 'POST';

        const res = await this.client.fetch(path, method, data, undefined);
        return await res.json();
    }

    /**
     * Get a credential
     * @async
     * @param {string} said - SAID of the credential
     * @param {boolean} [includeCESR=false] - Optional flag export the credential in CESR format
     * @returns {Promise<CredentialResult | string>} A promise to the credential
     */
    async get(said: string): Promise<CredentialResult>;
    async get(said: string, includeCESR: false): Promise<CredentialResult>;
    async get(said: string, includeCESR: true): Promise<string>;
    async get(
        said: string,
        includeCESR: boolean
    ): Promise<CredentialResult | string>;
    async get(
        said: string,
        includeCESR: boolean = false
    ): Promise<CredentialResult | string> {
        const path = `/credentials/${said}`;
        const method = 'GET';
        const headers = includeCESR
            ? new Headers({ Accept: 'application/json+cesr' })
            : new Headers({ Accept: 'application/json' });
        const res = await this.client.fetch(path, method, null, headers);

        return includeCESR ? await res.text() : await res.json();
    }

    /**
     * Delete a credential from the DB
     * @async
     * @param {string} said - SAID of the credential
     * @returns {Promise<void>}
     */
    async delete(said: string): Promise<void> {
        const path = `/credentials/${said}`;
        const method = 'DELETE';
        await this.client.fetch(path, method, undefined);
    }

    /**
     * Get the state of a credential
     * @async
     * @param {string} ri - management registry identifier
     * @param {string} said - SAID of the credential
     * @returns {Promise<CredentialState>} A promise to the credential registry state
     */
    async state(ri: string, said: string): Promise<CredentialState> {
        const path = `/registries/${ri}/${said}`;
        const method = 'GET';
        const res = await this.client.fetch(path, method, null);
        return res.json();
    }

    /**
     * Creates a credential in the specified registry to be GRANTed with IPEX to the intended recipient
     */
    async issue(
        name: string,
        args: CredentialData
    ): Promise<IssueCredentialResult> {
        const hab = await this.client.identifiers().get(name);
        const estOnly = hab.state.c !== undefined && hab.state.c.includes('EO');
        if (estOnly) {
            // TODO implement rotation event
            throw new Error('Establishment only not implemented');
        }
        if (!this.client.manager) {
            throw new Error('No manager on client');
        }

        const keeper = this.client.manager.get(hab);

        const [, subject] = Saider.saidify({
            d: '',
            ...args.a,
            dt: args.a.dt ?? new Date().toISOString().replace('Z', '000+00:00'),
        });

        const [, acdc] = Saider.saidify({
            v: versify(Protocols.ACDC, undefined, Serials.JSON, 0),
            d: '',
            u: args.u,
            i: args.i ?? hab.prefix,
            ri: args.ri,
            s: args.s,
            a: subject,
            e: args.e,
            r: args.r,
        });

        const [, iss] = Saider.saidify({
            v: versify(Protocols.KERI, undefined, Serials.JSON, 0),
            t: Ilks.iss,
            d: '',
            i: acdc.d,
            s: '0',
            ri: args.ri,
            dt: subject.dt,
        });

        const sn = parseInt(hab.state.s, 16);
        const anc = interact({
            pre: hab.prefix,
            sn: sn + 1,
            data: [
                {
                    i: iss.i,
                    s: iss.s,
                    d: iss.d,
                },
            ],
            dig: hab.state.d,
            version: undefined,
            kind: undefined,
        });

        const sigs = await keeper.sign(b(anc.raw));

        const path = `/identifiers/${hab.name}/credentials`;
        const method = 'POST';
        const body = {
            acdc: acdc,
            iss: iss,
            ixn: anc.sad,
            sigs,
            [keeper.algo]: keeper.params(),
        };

        const res = await this.client.fetch(path, method, body);
        const op = await res.json();

        return {
            acdc: new Serder(acdc),
            iss: new Serder(iss),
            anc,
            op,
        };
    }

    /**
     * Revoke credential
     * @async
     * @param {string} name Name or alias of the identifier
     * @param {string} said SAID of the credential
     * @param {string} datetime date time of revocation
     * @returns {Promise<RevokeCredentialResult>} A promise to the long-running operation
     */
    async revoke(
        name: string,
        said: string,
        datetime?: string
    ): Promise<RevokeCredentialResult> {
        const hab = await this.client.identifiers().get(name);
        const pre: string = hab.prefix;

        const vs = versify(Protocols.KERI, undefined, Serials.JSON, 0);
        const dt =
            datetime ?? new Date().toISOString().replace('Z', '000+00:00');

        const cred = await this.get(said);

        let registryId: string;
        if ('ri' in cred.sad && cred.sad.ri !== undefined) {
            registryId = cred.sad.ri;
        } else if ('rd' in cred.sad && cred.sad.rd !== undefined) {
            registryId = cred.sad.rd;
        } else {
            throw new Error('Neither ri nor rd property found in credential');
        }

        // Create rev
        const _rev = {
            v: vs,
            t: Ilks.rev,
            d: '',
            i: said,
            s: '1',
            ri: registryId,
            p: cred.status.d,
            dt: dt,
        };

        const [, rev] = Saider.saidify(_rev);

        // create ixn
        let ixn = {};
        let sigs = [];

        const state = hab.state;
        if (state.c !== undefined && state.c.includes('EO')) {
            var estOnly = true;
        } else {
            var estOnly = false;
        }

        const sn = parseInt(state.s, 16);
        const dig = state.d;

        const data: any = [
            {
                i: rev.i,
                s: rev.s,
                d: rev.d,
            },
        ];

        const keeper = this.client!.manager!.get(hab);

        if (estOnly) {
            // TODO implement rotation event
            throw new Error('Establishment only not implemented');
        } else {
            const serder = interact({
                pre: pre,
                sn: sn + 1,
                data: data,
                dig: dig,
                version: undefined,
                kind: undefined,
            });
            sigs = await keeper.sign(b(serder.raw));
            ixn = serder.sad;
        }

        const body = {
            rev: rev,
            ixn: ixn,
            sigs: sigs,
            [keeper.algo]: keeper.params(),
        };

        const path = `/identifiers/${name}/credentials/${said}`;
        const method = 'DELETE';
        const res = await this.client.fetch(path, method, body);
        const op = await res.json();

        return {
            rev: new Serder(rev),
            anc: new Serder(ixn),
            op,
        };
    }
}

export interface CreateRegistryArgs {
    name: string;
    registryName: string;
    toad?: string | number | undefined;
    noBackers?: boolean;
    baks?: string[];
    nonce?: string;
}

export class RegistryResult {
    private readonly _regser: any;
    private readonly _serder: Serder;
    private readonly _sigs: string[];
    private readonly promise: Promise<Response>;

    constructor(
        regser: Serder,
        serder: Serder,
        sigs: any[],
        promise: Promise<Response>
    ) {
        this._regser = regser;
        this._serder = serder;
        this._sigs = sigs;
        this.promise = promise;
    }

    get regser() {
        return this._regser;
    }

    get serder() {
        return this._serder;
    }

    get sigs() {
        return this._sigs;
    }

    async op(): Promise<RegistryOperation> {
        const res = await this.promise;
        return await res.json();
    }
}

/**
 * Registries
 */
export class Registries {
    public client: SignifyClient;
    /**
     * Registries
     * @param {SignifyClient} client
     */
    constructor(client: SignifyClient) {
        this.client = client;
    }

    /**
     * List registries
     * @async
     * @param {string} name Name or alias of the identifier
     * @returns {Promise<Registry[]>} A promise to the list of registries
     */
    async list(name: string): Promise<Registry[]> {
        const path = `/identifiers/${name}/registries`;
        const method = 'GET';
        const res = await this.client.fetch(path, method, null);
        return await res.json();
    }

    /**
     * Create a registry
     * @async
     * @param {CreateRegistryArgs}
     * @returns {Promise<[any, Serder, any[], object]> } A promise to the long-running operation
     */
    async create({
        name,
        registryName,
        noBackers = true,
        toad = 0,
        baks = [],
        nonce,
    }: CreateRegistryArgs): Promise<RegistryResult> {
        const hab = await this.client.identifiers().get(name);
        const pre: string = hab.prefix;

        const cnfg: string[] = [];
        if (noBackers) {
            cnfg.push(TraitDex.NoBackers);
        }

        const state = hab.state;
        const estOnly = state.c !== undefined && state.c.includes('EO');
        if (estOnly) {
            cnfg.push(TraitDex.EstOnly);
        }

        const regser = vdr.incept({ pre, baks, toad, nonce, cnfg });

        if (estOnly) {
            throw new Error('establishment only not implemented');
        } else {
            const state = hab.state;
            const sn = parseInt(state.s, 16);
            const dig = state.d;

            const data: any = [
                {
                    i: regser.pre,
                    s: '0',
                    d: regser.pre,
                },
            ];

            const serder = interact({
                pre: pre,
                sn: sn + 1,
                data: data,
                dig: dig,
                version: Vrsn_1_0,
                kind: Serials.JSON,
            });
            const keeper = this.client.manager!.get(hab);
            const sigs = await keeper.sign(b(serder.raw));
            const res = this.createFromEvents(
                hab,
                name,
                registryName,
                regser.sad,
                serder.sad,
                sigs
            );
            return new RegistryResult(regser, serder, sigs, res);
        }
    }

    createFromEvents(
        hab: HabState,
        name: string,
        registryName: string,
        vcp: Dict<any>,
        ixn: Dict<any>,
        sigs: any[]
    ) {
        const path = `/identifiers/${name}/registries`;
        const method = 'POST';

        const data: any = {
            name: registryName,
            vcp: vcp,
            ixn: ixn,
            sigs: sigs,
        };
        const keeper = this.client!.manager!.get(hab);
        data[keeper.algo] = keeper.params();

        return this.client.fetch(path, method, data);
    }

    /**
     * Rename a registry
     * @async
     * @param {string} name Name or alias of the identifier
     * @param {string} registryName Current registry name
     * @param {string} newName New registry name
     * @returns {Promise<Registry>} A promise to the registry record
     */
    async rename(
        name: string,
        registryName: string,
        newName: string
    ): Promise<Registry> {
        const path = `/identifiers/${name}/registries/${registryName}`;
        const method = 'PUT';
        const data = {
            name: newName,
        };
        const res = await this.client.fetch(path, method, data);
        return await res.json();
    }
}
/**
 * Schemas
 */
export class Schemas {
    client: SignifyClient;
    /**
     * Schemas
     * @param {SignifyClient} client
     */
    constructor(client: SignifyClient) {
        this.client = client;
    }

    /**
     * Get a schema
     * @async
     * @param {string} said SAID of the schema
     * @returns {Promise<Schema>} A promise to the schema
     */
    async get(said: string): Promise<Schema> {
        const path = `/schema/${said}`;
        const method = 'GET';
        const res = await this.client.fetch(path, method, null);
        return await res.json();
    }

    /**
     * List schemas
     * @async
     * @returns {Promise<Schema[]>} A promise to the list of schemas
     */
    async list(): Promise<Schema[]> {
        const path = `/schema`;
        const method = 'GET';
        const res = await this.client.fetch(path, method, null);
        return await res.json();
    }
}

/**
 * IPEX - Issuance and Presentation Exchange protocol
 * Handles credential issuance and disclosure negotiation.
 */

// list IPEX routes and make types to clarify IPEX class logic
const IPEX_JOIN_ROUTES = [
    '/ipex/apply',
    '/ipex/offer',
    '/ipex/agree',
    '/ipex/grant',
    '/ipex/admit',
] as const;

type IpexJoinRoute = (typeof IPEX_JOIN_ROUTES)[number];

function isIpexJoinRoute(route: string): route is IpexJoinRoute {
    for (const supportedRoute of IPEX_JOIN_ROUTES) {
        if (route === supportedRoute) {
            return true;
        }
    }
    return false;
}

// Map IPEX exchange message routes to URL endpoint suffixes with types to clarify IPEX class logic
type IpexJoinEndpoint = 'apply' | 'offer' | 'agree' | 'grant' | 'admit';

const IPEX_JOIN_ENDPOINTS: Record<IpexJoinRoute, IpexJoinEndpoint> = {
    '/ipex/apply': 'apply',
    '/ipex/offer': 'offer',
    '/ipex/agree': 'agree',
    '/ipex/grant': 'grant',
    '/ipex/admit': 'admit',
};

/**
 * Look up IPEX URL endpoint suffix based on IPEX route.
 */
function ipexJoinEndpoint(route: string): IpexJoinEndpoint {
    if (!isIpexJoinRoute(route)) {
        throw new Error(`unsupported embedded IPEX route ${route}`);
    }
    return IPEX_JOIN_ENDPOINTS[route];
}

type IpexJoinPayload = {
    i: string;
    [key: string]: unknown;
};

// The embedded IPEX Exn will have a route and its own attributes
type EmbeddedIpexExn = ExnV1 & {
    r: IpexJoinRoute;
    a: IpexJoinPayload;
};

type JoinMultisigExn = ExnV1 & {
    r: '/multisig/exn';
    a: {
        gid: string;
        [key: string]: unknown;
    };
    e: {
        exn: EmbeddedIpexExn;
        d?: string;
    };
};

type JoinMultisigExnExchange = ExchangeResourceV1 & {
    exn: JoinMultisigExn;
};

// Tagged tuple for a source key-event seal.
type SealEvent = [
    'SealEvent',
    {
        i: string; // AID/prefix of the sealed source event's KEL
        s: string; // sequence number of that source event
        d: string; // SAID/digest of that source event
    },
];

// ensure value is object and not null
function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

/**
 * Main IPEX API class supporting all IPEX verbs
 */
export class Ipex {
    client: SignifyClient;
    /**
     * Schemas
     * @param {SignifyClient} client
     */
    constructor(client: SignifyClient) {
        this.client = client;
    }

    /**
     * Create an IPEX apply EXN message
     */
    async apply(args: IpexApplyArgs): Promise<[Serder, string[], string]> {
        const hab = await this.client.identifiers().get(args.senderName);
        const data = {
            m: args.message ?? '',
            s: args.schemaSaid,
            a: args.attributes ?? {},
        };

        return this.client
            .exchanges()
            .createExchangeMessage(
                hab,
                '/ipex/apply',
                data,
                {},
                args.recipient,
                args.datetime,
                undefined
            );
    }

    async submitApply(
        name: string,
        exn: Serder,
        sigs: string[],
        recp: string[]
    ): Promise<ExchangeOperation> {
        const body = {
            exn: exn.sad,
            sigs,
            rec: recp,
        };

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/apply`,
            'POST',
            body
        );

        return response.json();
    }

    /**
     * Create an IPEX offer EXN message
     */
    async offer(args: IpexOfferArgs): Promise<[Serder, string[], string]> {
        const hab = await this.client.identifiers().get(args.senderName);
        const data = {
            m: args.message ?? '',
        };

        return this.client
            .exchanges()
            .createExchangeMessage(
                hab,
                '/ipex/offer',
                data,
                { acdc: [args.acdc, undefined] },
                args.recipient,
                args.datetime,
                args.applySaid
            );
    }

    async submitOffer(
        name: string,
        exn: Serder,
        sigs: string[],
        atc: string,
        recp: string[]
    ): Promise<ExchangeOperation> {
        const body = {
            exn: exn.sad,
            sigs,
            atc,
            rec: recp,
        };

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/offer`,
            'POST',
            body
        );

        return response.json();
    }

    /**
     * Create an IPEX agree EXN message
     */
    async agree(args: IpexAgreeArgs): Promise<[Serder, string[], string]> {
        const hab = await this.client.identifiers().get(args.senderName);
        const data = {
            m: args.message ?? '',
        };

        return this.client
            .exchanges()
            .createExchangeMessage(
                hab,
                '/ipex/agree',
                data,
                {},
                args.recipient,
                args.datetime,
                args.offerSaid
            );
    }

    async submitAgree(
        name: string,
        exn: Serder,
        sigs: string[],
        recp: string[]
    ): Promise<ExchangeOperation> {
        const body = {
            exn: exn.sad,
            sigs,
            rec: recp,
        };

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/agree`,
            'POST',
            body
        );

        return response.json();
    }

    /**
     * Create an IPEX grant EXN message
     */
    async grant(args: IpexGrantArgs): Promise<[Serder, string[], string]> {
        const hab = await this.client.identifiers().get(args.senderName);
        const data = {
            m: args.message ?? '',
        };

        let atc = args.ancAttachment;
        if (atc === undefined) {
            const keeper = this.client.manager!.get(hab);
            const sigs = await keeper.sign(b(args.anc.raw));
            const sigers = sigs.map((sig: string) => new Siger({ qb64: sig }));
            const ims = d(messagize(args.anc, sigers));
            atc = ims.substring(args.anc.size);
        }

        const acdcAtc =
            args.acdcAttachment === undefined
                ? d(serializeACDCAttachment(args.iss))
                : args.acdcAttachment;
        const issAtc =
            args.issAttachment === undefined
                ? d(serializeIssExnAttachment(args.anc))
                : args.issAttachment;

        const embeds: Record<string, [Serder, string]> = {
            acdc: [args.acdc, acdcAtc],
            iss: [args.iss, issAtc],
            anc: [args.anc, atc],
        };

        return this.client
            .exchanges()
            .createExchangeMessage(
                hab,
                '/ipex/grant',
                data,
                embeds,
                args.recipient,
                args.datetime,
                args.agreeSaid
            );
    }

    async submitGrant(
        name: string,
        exn: Serder,
        sigs: string[],
        atc: string,
        recp: string[]
    ): Promise<ExchangeOperation> {
        const body = {
            exn: exn.sad,
            sigs: sigs,
            atc: atc,
            rec: recp,
        };

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/grant`,
            'POST',
            body
        );

        return response.json();
    }

    /**
     * Create an IPEX admit EXN message
     */
    async admit(args: IpexAdmitArgs): Promise<[Serder, string[], string]> {
        const hab = await this.client.identifiers().get(args.senderName);
        const data: any = {
            m: args.message,
        };

        return this.client
            .exchanges()
            .createExchangeMessage(
                hab,
                '/ipex/admit',
                data,
                {},
                args.recipient,
                args.datetime,
                args.grantSaid
            );
    }

    async submitAdmit(
        name: string,
        exn: Serder,
        sigs: string[],
        atc: string,
        recp: string[]
    ): Promise<ExchangeOperation> {
        const body = {
            exn: exn.sad,
            sigs: sigs,
            atc: atc,
            rec: recp,
        };

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/admit`,
            'POST',
            body
        );

        return response.json();
    }

    private attachmentString(attachment: unknown): string {
        if (attachment === undefined || attachment === null) {
            return '';
        }
        if (Array.isArray(attachment)) {
            return attachment.join('');
        }
        if (typeof attachment === 'string') {
            return attachment;
        }
        if (attachment instanceof Uint8Array) {
            return d(attachment);
        }
        return String(attachment);
    }

    private proposalAttachment(exchange: ExchangeResourceV1): string {
        const pathed = exchange.pathed;
        if (!isRecord(pathed)) {
            return '';
        }
        return this.attachmentString(pathed['exn']);
    }

    private groupHab(hab: HabState): GroupHabState {
        if (!isGroupHab(hab)) {
            throw new Error('identifier is not a multisig group habitat');
        }
        return hab;
    }

    private validateJoinExchange(
        groupHab: GroupHabState,
        exchange: ExchangeResourceV1
    ): JoinMultisigExnExchange {
        const outer = exchange.exn;
        if (!isRecord(outer)) {
            throw new Error('exchange response missing exn');
        }
        const outerRoute = outer['r'];
        if (outerRoute !== '/multisig/exn') {
            throw new Error(`expected /multisig/exn, got ${outerRoute}`);
        }
        const outerAttrs = outer['a'];
        const gid = isRecord(outerAttrs) ? outerAttrs['gid'] : undefined;
        if (gid !== groupHab.prefix) {
            throw new Error(
                `multisig proposal gid ${gid} does not match group ${groupHab.prefix}`
            );
        }

        const outerEmbeds = outer['e'];
        const embedded = isRecord(outerEmbeds)
            ? outerEmbeds['exn']
            : undefined;
        if (!isRecord(embedded)) {
            throw new Error('multisig proposal missing embedded exn');
        }
        const embeddedSender = embedded['i'];
        if (embeddedSender !== groupHab.prefix) {
            throw new Error(
                `embedded IPEX sender ${embeddedSender} does not match group ${groupHab.prefix}`
            );
        }

        const embeddedAttrs = embedded['a'];
        const ipexRecipient = isRecord(embeddedAttrs)
            ? embeddedAttrs['i']
            : undefined;
        if (typeof ipexRecipient !== 'string' || ipexRecipient === '') {
            throw new Error('embedded IPEX message missing recipient a.i');
        }

        const embeddedRoute = embedded['r'];
        if (typeof embeddedRoute !== 'string') {
            throw new Error(
                `unsupported embedded IPEX route ${String(embeddedRoute)}`
            );
        }
        ipexJoinEndpoint(embeddedRoute);
        return exchange as JoinMultisigExnExchange;
    }

    private async signJoinedIpex(
        groupHab: GroupHabState,
        serder: Serder
    ): Promise<string> {
        const keeper = this.client.manager!.get(groupHab);
        const sigs = await keeper.sign(b(serder.raw));
        const sigers = sigs.map((sig: string) => new Siger({ qb64: sig }));
        const seal: SealEvent = [
            'SealEvent',
            {
                i: groupHab.prefix,
                s: groupHab.state.ee.s,
                d: groupHab.state.ee.d,
            },
        ];
        const ims = d(messagize(serder, sigers, seal));
        return ims.substring(serder.size);
    }

    /**
     * Joins an IPEX event sent by an initiator in a `/multisig/exn` message.
     * Assumes the group Hab has only one local member.
     *
     * @param name human-friendly alias of AID
     * @param said SAID of the `/multisig/exn` message containing the IPEX operation to join.
     * @returns response from POSTing the `/multisig/exn` message to KERIA
     */
    async join(name: string, said: string): Promise<ExchangeOperation> {
        const groupHab = this.groupHab(
            await this.client.identifiers().get(name)
        );
        const localMember = groupHab.group.mhab;

        // the /multisig/exn message from the initiator
        const exchange = await this.client.exchanges().get(said);
        const joinExchange = this.validateJoinExchange(groupHab, exchange);
        const embedded = joinExchange.exn.e.exn;
        const endpoint = ipexJoinEndpoint(embedded.r);
        const ipexRecipient = embedded.a.i;

        const members = await this.client.identifiers().members(name);
        const peerRecipients = members.signing
            .map((member) => member.aid)
            .filter((aid) => aid !== localMember.prefix);
        if (peerRecipients.length === 0) {
            throw new Error(
                'no peer signing members available for multisig IPEX join'
            );
        }

        const serder = new Serder(embedded as unknown as Dict<unknown>);
        const localAtc = await this.signJoinedIpex(groupHab, serder);
        const proposalAtc = this.proposalAttachment(exchange);
        const [outer, outerSigs, outerAtc] = await this.client
            .exchanges()
            .createExchangeMessage(
                localMember,
                '/multisig/exn',
                { gid: groupHab.prefix },
                { exn: [serder, localAtc + proposalAtc] },
                ipexRecipient
            );

        const response = await this.client.fetch(
            `/identifiers/${name}/ipex/${endpoint}`,
            'POST',
            {
                exn: outer.sad,
                sigs: outerSigs,
                atc: outerAtc,
                rec: [ipexRecipient],
            }
        );

        const [peerOuter, peerSigs, peerAtc] = await this.client
            .exchanges()
            .createExchangeMessage(
                localMember,
                '/multisig/exn',
                { gid: groupHab.prefix },
                { exn: [serder, localAtc + proposalAtc] },
                peerRecipients[0]
            );
        await this.client
            .exchanges()
            .sendFromEvents(
                localMember.name,
                'multisig',
                peerOuter,
                peerSigs,
                peerAtc,
                peerRecipients
            );

        return response.json();
    }
}
