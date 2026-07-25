import { components } from '../../types/keria-api-schema.ts';
import { Authenticater } from '../core/authing.ts';
import { Ilks } from '../core/core.ts';
import { HEADER_SIG_TIME } from '../core/httping.ts';
import { ExternalModule, IdentifierManagerFactory } from '../core/keeping.ts';
import { CesrNumber } from '../core/number.ts';
import { Tier } from '../core/salter.ts';
import { Seqner } from '../core/seqner.ts';
import { Serder } from '../core/serder.ts';

import { Identifier } from './aiding.ts';
import { Contacts, Challenges } from './contacting.ts';
import { Agent, Controller } from './controller.ts';
import { Oobis, Operations, KeyEvents, KeyStates, Config } from './coring.ts';
import { Credentials, Ipex, Registries, Schemas } from './credentialing.ts';
import { Delegations } from './delegating.ts';
import { Escrows } from './escrowing.ts';
import { Exchanges } from './exchanging.ts';
import { Groups } from './grouping.ts';
import { Notifications } from './notifying.ts';

const DEFAULT_BOOT_URL = 'http://localhost:3903';

// Export type outside the class
export type AgentResourceResult = components['schemas']['AgentResourceResult'];

/** Cancellation options for booting or connecting a Signify client. */
export interface ConnectionOptions {
    signal?: AbortSignal;
}

class State {
    agent: any | null;
    controller: any | null;
    ridx: number;
    pidx: number;

    constructor() {
        this.agent = null;
        this.controller = null;
        this.pidx = 0;
        this.ridx = 0;
    }
}

/**
 * An in-memory key manager that can connect to a KERIA Agent and use it to
 * receive messages and act as a proxy for multi-signature operations and delegation operations.
 */
export class SignifyClient {
    public controller: Controller;
    public url: string;
    public bran: string;
    public pidx: number;
    public agent: Agent | null;
    public authn: Authenticater | null;
    public manager: IdentifierManagerFactory | null;
    public tier: Tier;
    public bootUrl: string;
    public exteralModules: ExternalModule[];
    private _identifiers = new Identifier(this);
    private _operations = new Operations(this);
    private _keyEvents = new KeyEvents(this);
    private _keyStates = new KeyStates(this);
    private _oobis = new Oobis(this);
    private _config = new Config(this);
    private _delegations = new Delegations(this);
    private _exchanges = new Exchanges(this);
    private _groups = new Groups(this);
    private _escrows = new Escrows(this);
    private _credentials = new Credentials(this);
    private _registries = new Registries(this);
    private _ipex = new Ipex(this);
    private _notifications = new Notifications(this);
    private _contacts = new Contacts(this);
    private _challenges = new Challenges(this);
    private _schemas = new Schemas(this);

    /**
     * SignifyClient constructor
     * @param {string} url KERIA admin interface URL
     * @param {string} bran Base64 21 char string that is used as base material for seed of the client AID
     * @param {Tier} tier Security tier for generating keys of the client AID (high | mewdium | low)
     * @param {string} bootUrl KERIA boot interface URL
     * @param {ExternalModule[]} externalModules list of external modules to load
     */
    constructor(
        url: string,
        bran: string,
        tier: Tier = Tier.low,
        bootUrl: string = DEFAULT_BOOT_URL,
        externalModules: ExternalModule[] = []
    ) {
        this.url = url;
        if (bran.length < 21) {
            throw Error('bran must be 21 characters');
        }
        this.bran = bran;
        this.pidx = 0;
        this.controller = new Controller(bran, tier);
        this.authn = null;
        this.agent = null;
        this.manager = null;
        this.tier = tier;
        this.bootUrl = bootUrl;
        this.exteralModules = externalModules;
    }

    get data() {
        return [this.url, this.bran, this.pidx, this.authn];
    }

    /**
     * Boot a KERIA Agent. Call only once per edge Signify Controller.
     *
     * On first call this triggers the KERIA agent to edge controller delegation
     * ceremony causing the KERIA server to provision the agent for a given edge
     * Signify Controller.
     *
     * On subsequent calls the server returns 409 Conflict when the destination
     * Agent already exists.
     *
     * @async
     * @param {ConnectionOptions} [options] Cancellation options
     * @returns {Promise<Response>} Response from the KERIA boot endpoint
     */
    async boot(options: ConnectionOptions = {}): Promise<Response> {
        const [evt, sign] = this.controller?.event ?? [];
        const data = {
            icp: evt.sad,
            sig: sign.qb64,
            stem: this.controller?.stem,
            pidx: 1,
            tier: this.controller?.tier,
        };

        return await fetch(this.bootUrl + '/boot', {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                'Content-Type': 'application/json',
            },
            signal: options.signal,
        });
    }

    /**
     * Get state of the agent and the client
     * @async
     * @param {ConnectionOptions} [options] Cancellation options
     * @returns {Promise<Response>} A promise to the state
     */
    async state(options: ConnectionOptions = {}): Promise<State> {
        const caid = this.controller?.pre;

        const res = await fetch(this.url + `/agent/${caid}`, {
            signal: options.signal,
        });
        if (res.status == 404) {
            throw new Error(`agent does not exist for controller ${caid}`);
        }

        const data = (await res.json()) as AgentResourceResult;
        const state = new State();
        state.agent = data.agent ?? {};
        state.controller = data.controller ?? {};
        state.ridx = data.ridx ?? 0;
        state.pidx = data.pidx ?? 0;
        return state;
    }

    /**
     * Connect to an existing KERIA Agent and restore its in-memory Controller.
     * @async
     * @param {ConnectionOptions} [options] Cancellation options
     */
    async connect(options: ConnectionOptions = {}) {
        await this.connectToAgent(false, options);
    }

    /**
     * Connect immediately after this client successfully booted its controller.
     *
     * The boot request used the controller already held by this instance, so
     * exact state validation lets us avoid deriving identical keys again.
     *
     * @param {ConnectionOptions} [options] Cancellation options
     */
    async connectAfterBoot(options: ConnectionOptions = {}) {
        await this.connectToAgent(true, options);
    }

    /** Check whether KERIA and this client hold the same establishment state. */
    private _controllerMatchesKeriaEstablishment(
        state: State,
        ctrl: Controller
    ): boolean {
        const stateEstEvt = state.controller?.ee;
        const ctrlEstEvt = ctrl.serder;
        const rotationIdxMatches = state.ridx === ctrl.ridx;
        const estEvtPreMatches = stateEstEvt?.i === ctrl.pre;
        const estEvtSeqNoMatches = stateEstEvt?.s === ctrlEstEvt.sad.s;
        const estEvtDigMatches = stateEstEvt?.d === ctrlEstEvt.sad.d;
        return (
            rotationIdxMatches &&
            estEvtPreMatches &&
            estEvtSeqNoMatches &&
            estEvtDigMatches
        );
    }

    /** Compute the Agent delegation seal the controller must anchor. */
    private _agentDelegationSeal() {
        if (
            this.agent === null ||
            this.agent.sn === undefined ||
            this.agent.said === undefined ||
            this.agent.said.length === 0
        ) {
            throw new Error(
                'KERIA agent state is incomplete for delegation verification'
            );
        }

        return {
            i: this.agent.pre,
            s: new Seqner({ sn: this.agent.sn }).snh,
            d: this.agent.said,
        };
    }

    /** Verify the local interaction event anchors this exact Agent. */
    private _verifyAgentDelegationSeal(event: Serder) {
        const expected = this._agentDelegationSeal();
        if (event.sad.t !== Ilks.ixn) {
            throw new Error(
                'controller delegation approval is not an interaction event'
            );
        }

        const seals = event.sad.a;
        if (!Array.isArray(seals) || seals.length !== 1) {
            throw new Error(
                'controller delegation approval must contain exactly one seal'
            );
        }

        const seal = seals[0];
        if (
            seal.i !== expected.i ||
            seal.s !== expected.s ||
            seal.d !== expected.d
        ) {
            throw new Error(
                'controller delegation approval seal does not match KERIA agent'
            );
        }
    }

    /** Load agent state and initialize authenticated client services. */
    private async connectToAgent(
        reuseController: boolean,
        options: ConnectionOptions
    ) {
        const state = await this.state(options);
        this.pidx = state.pidx;
        if (reuseController) {
            if (
                !this._controllerMatchesKeriaEstablishment(
                    state,
                    this.controller
                )
            ) {
                throw new Error(
                    'booted controller does not match KERIA controller state'
                );
            }
        } else {
            // Reconnecting clients must derive the keys for persisted state.
            this.controller = new Controller(
                this.bran,
                this.tier,
                0,
                state.controller
            );
        }
        this.controller.ridx = state.ridx !== undefined ? state.ridx : 0;
        // Create agent representing the AID of KERIA cloud agent
        this.agent = new Agent(state.agent);
        if (this.agent.anchor !== this.controller.pre) {
            throw Error(
                'commitment to controller AID missing in agent inception event'
            );
        }

        const controllerSequence = state.controller?.state?.s;
        if (typeof controllerSequence !== 'string') {
            throw new Error(
                'KERIA controller state is missing a string sequence number'
            );
        }

        if (new CesrNumber({}, controllerSequence).num === 0) {
            await this.approveDelegation(options);
        }

        this.manager = new IdentifierManagerFactory(
            this.controller.salter,
            this.exteralModules
        );
        this.authn = new Authenticater(
            this.controller.signer,
            this.agent.verfer!
        );
    }

    /**
     * Fetch a resource from the KERIA agent
     * @async
     * @param {string} path Path to the resource
     * @param {string} method HTTP method
     * @param {any} data Data to be sent in the body of the resource
     * @param {Headers} [extraHeaders] Optional extra headers to be sent with the request
     * @returns {Promise<Response>} A promise to the result of the fetch
     */
    async fetch(
        path: string,
        method: string,
        data: any,
        extraHeaders?: Headers
    ): Promise<Response> {
        const headers = new Headers();
        let signed_headers = new Headers();
        const final_headers = new Headers();

        headers.set('Signify-Resource', this.controller.pre);
        headers.set(
            HEADER_SIG_TIME,
            new Date().toISOString().replace('Z', '000+00:00')
        );
        headers.set('Content-Type', 'application/json');

        const _body = method === 'GET' ? null : JSON.stringify(data);

        if (this.authn) {
            signed_headers = this.authn.sign(
                headers,
                method,
                path.split('?')[0]
            );
        } else {
            throw new Error('client need to call connect first');
        }

        signed_headers.forEach((value, key) => {
            final_headers.set(key, value);
        });
        if (extraHeaders !== undefined) {
            extraHeaders.forEach((value, key) => {
                final_headers.append(key, value);
            });
        }
        const res = await fetch(this.url + path, {
            method: method,
            body: _body,
            headers: final_headers,
        });
        if (!res.ok) {
            const error = await res.text();
            const message = `HTTP ${method} ${path} - ${res.status} ${res.statusText} - ${error}`;
            throw new Error(message);
        }
        const isSameAgent =
            this.agent?.pre === res.headers.get('signify-resource');
        if (!isSameAgent) {
            throw new Error('message from a different remote agent');
        }

        const verification = this.authn.verify(
            res.headers,
            method,
            path.split('?')[0]
        );
        if (verification) {
            return res;
        } else {
            throw new Error('response verification failed');
        }
    }

    /**
     * Create a Signed Request to fetch a resource from an external URL with headers signed by an AID
     * @async
     * @param {string} aidName Name or alias of the AID to be used for signing
     * @param {string} url URL of the requested resource
     * @param {RequestInit} req Request options should include:
     *     - method: HTTP method
     *     - data Data to be sent in the body of the resource.
     *              If the data is a CESR JSON string then you should also set contentType to 'application/json+cesr'
     *              If the data is a FormData object then you should not set the contentType and the browser will set it to 'multipart/form-data'
     *              If the data is an object then you should use JSON.stringify to convert it to a string and set the contentType to 'application/json'
     *     - contentType Content type of the request.
     * @returns {Promise<Request>} A promise to the created Request
     */
    async createSignedRequest(
        aidName: string,
        url: string,
        req: RequestInit
    ): Promise<Request> {
        const hab = await this.identifiers().get(aidName);
        const keeper = this.manager!.get(hab);

        const authenticator = new Authenticater(
            keeper.signers[0],
            keeper.signers[0].verfer
        );

        const headers = new Headers(req.headers);
        headers.set('Signify-Resource', hab['prefix']);
        headers.set(
            HEADER_SIG_TIME,
            new Date().toISOString().replace('Z', '000+00:00')
        );

        const signed_headers = authenticator.sign(
            new Headers(headers),
            req.method ?? 'GET',
            new URL(url).pathname
        );
        req.headers = signed_headers;

        return new Request(url, req);
    }

    /**
     * Approve the delegation of the client AID to the KERIA agent
     * @async
     * @param {ConnectionOptions} [options] Cancellation options
     * @returns {Promise<Response>} A promise to the result of the approval
     */
    async approveDelegation(
        options: ConnectionOptions = {}
    ): Promise<Response> {
        options.signal?.throwIfAborted();
        const approval = this.controller.approveDelegation(this.agent!);
        this._verifyAgentDelegationSeal(approval.event);

        const data = {
            ixn: approval.event.sad,
            sigs: approval.signatures,
        };

        const response = await fetch(
            this.url + '/agent/' + this.controller.pre + '?type=ixn',
            {
                method: 'PUT',
                body: JSON.stringify(data),
                headers: {
                    'Content-Type': 'application/json',
                },
                signal: options.signal,
            }
        );
        if (!response.ok) {
            const body = await response.text();
            const details = body.length > 0 ? ` - ${body}` : '';
            throw new Error(
                `agent delegation approval failed: ${response.status} ${response.statusText}${details}`
            );
        }

        return response;
    }

    /**
     * Save old client passcode in KERIA agent
     * @async
     * @param {string} passcode Passcode to be saved
     * @returns {Promise<Response>} A promise to the result of the save
     */
    async saveOldPasscode(passcode: string): Promise<Response> {
        const caid = this.controller?.pre;
        const body = { salt: passcode };
        return await fetch(this.url + '/salt/' + caid, {
            method: 'PUT',
            body: JSON.stringify(body),
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    /**
     * Delete a saved passcode from KERIA agent
     * @async
     * @returns {Promise<Response>} A promise to the result of the deletion
     */
    async deletePasscode(): Promise<Response> {
        const caid = this.controller?.pre;
        return await fetch(this.url + '/salt/' + caid, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    /**
     * Rotate the client AID
     * @async
     * @param {string} nbran Base64 21 char string that is used as base material for the new seed
     * @param {Array<string>} aids List of managed AIDs to be rotated
     * @returns {Promise<Response>} A promise to the result of the rotation
     */
    async rotate(nbran: string, aids: string[]): Promise<Response> {
        const data = this.controller.rotate(nbran, aids);
        return await fetch(this.url + '/agent/' + this.controller.pre, {
            method: 'PUT',
            body: JSON.stringify(data),
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    /**
     * Get identifiers resource
     * @returns {Identifier}
     */
    identifiers(): Identifier {
        return this._identifiers;
    }

    /**
     * Get OOBIs resource
     * @returns {Oobis}
     */
    oobis(): Oobis {
        return this._oobis;
    }

    /**
     * Get operations resource
     * @returns {Operations}
     */
    operations(): Operations {
        return this._operations;
    }

    /**
     * Get keyEvents resource
     * @returns {KeyEvents}
     */
    keyEvents(): KeyEvents {
        return this._keyEvents;
    }

    /**
     * Get keyStates resource
     * @returns {KeyStates}
     */
    keyStates(): KeyStates {
        return this._keyStates;
    }

    /**
     * Get credentials resource
     * @returns {Credentials}
     */
    credentials(): Credentials {
        return this._credentials;
    }

    /**
     * Get IPEX resource
     * @returns {Ipex}
     */
    ipex(): Ipex {
        return this._ipex;
    }

    /**
     * Get registries resource
     * @returns {Registries}
     */
    registries(): Registries {
        return this._registries;
    }

    /**
     * Get schemas resource
     * @returns {Schemas}
     */
    schemas(): Schemas {
        return this._schemas;
    }

    /**
     * Get challenges resource
     * @returns {Challenges}
     */
    challenges(): Challenges {
        return this._challenges;
    }

    /**
     * Get contacts resource
     * @returns {Contacts}
     */
    contacts(): Contacts {
        return this._contacts;
    }

    /**
     * Get notifications resource
     * @returns {Notifications}
     */
    notifications(): Notifications {
        return this._notifications;
    }

    /**
     * Get escrows resource
     * @returns {Escrows}
     */
    escrows(): Escrows {
        return this._escrows;
    }

    /**
     * Get groups resource
     * @returns {Groups}
     */
    groups(): Groups {
        return this._groups;
    }

    /**
     * Get exchange resource
     * @returns {Exchanges}
     */
    exchanges(): Exchanges {
        return this._exchanges;
    }

    /**
     * Get delegations resource
     * @returns {Delegations}
     */
    delegations(): Delegations {
        return this._delegations;
    }

    /**
     * Get agent config resource
     * @returns {Config}
     */
    config(): Config {
        return this._config;
    }
}
