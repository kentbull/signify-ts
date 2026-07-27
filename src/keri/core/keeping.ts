import { Salter } from './salter.ts';
import { Algos, SaltyCreator, RandyCreator } from './manager.ts';
import { MtrDex } from './matter.ts';
import { Tier } from './salter.ts';
import { Encrypter } from '../core/encrypter.ts';
import { Decrypter } from './decrypter.ts';
import { b } from './core.ts';
import { Cipher } from './cipher.ts';
import { Diger } from './diger.ts';
import { Prefixer } from './prefixer.ts';
import { Signer } from './signer.ts';
import { Verfer } from './verfer.ts';
import {
    ExternState,
    GroupKeyState,
    HabState,
    RandyKeyState,
    SaltyKeyState,
    KeyState,
} from './keyState.ts';

/** External module definition */
export interface ExternalModuleType {
    new (pidx: number, args: IdentifierManagerParams): IdentifierManager;
}

export interface ExternalModule {
    type: string;
    name: string;
    module: ExternalModuleType;
}

export type IdentifierManagerResult = [string[], string[]];
export type SignResult = string[];

export interface IdentifierManagerParams {
    [key: string]: unknown;
}

export interface SaltyManagerParams extends IdentifierManagerParams {
    pidx: number;
    kidx: number;
    tier: Tier;
    transferable: boolean;
    stem: string | undefined;
    icodes: string[] | undefined;
    ncodes: string[] | undefined;
    dcode: string | undefined;
    sxlt: string | undefined;
}

type SaltySignerSnapshot = Readonly<{
    publicKeys: readonly string[];
    signerQb64s: readonly string[];
}>;

type CachedSaltySignerSet = Readonly<{
    establishmentSequence: number;
    establishmentDigest: string;
    publicKeys: readonly string[];
    signerQb64s: readonly string[];
}>;

type SaltyManagerInitialization = Readonly<{
    pidx: number;
    kidx: number;
    tier: Tier;
    transferable: boolean;
    stem: string | undefined;
    code: string;
    count: number;
    icodes: string[] | undefined;
    ncode: string;
    ncount: number;
    ncodes: string[] | undefined;
    dcode: string | undefined;
    bran: string | undefined;
    sxlt: string | undefined;
}>;

const MAX_CACHED_SIGNER_SETS = 16;

export interface RandyManagerParams extends IdentifierManagerParams {
    nxts?: string[];
    prxs?: string[];
    transferable: boolean;
}

export interface GroupManagerParams extends IdentifierManagerParams {
    mhab: HabState;
}

/**
 * Interface for KERI identifier (prefix) creation, rotation, and signing.
 * @param T Type of the key keeper
 */
export interface IdentifierManager<
    T extends IdentifierManagerParams = IdentifierManagerParams,
> {
    algo: Algos;
    signers: Signer[];
    params(): T;
    incept(transferable: boolean): Promise<IdentifierManagerResult>;
    rotate(
        ncodes: string[],
        transferable: boolean,
        states?: KeyState[],
        rstates?: KeyState[]
    ): Promise<IdentifierManagerResult>;
    /**
     * Sign serialized bytes.
     *
     * `rotated` is meaningful for group identifiers only. Callers building a
     * group rotation must pass `rotated=true` so the group signature exposes
     * prior-next `ondex`; non-rotation calls leave it false/current-only.
     *
     * `ondices === undefined` uses the default dual-index behavior where each
     * `ondex` matches its `index`. `ondices[j] === undefined` is the explicit
     * current-only case for that signature, so no `ondex` is emitted.
     */
    sign(
        ser: Uint8Array,
        indexed?: boolean,
        indices?: number[],
        ondices?: Ondex[],
        rotated?: boolean
    ): Promise<SignResult>;
}

/**
 * Creates IdentifierManager instances based on the algorithm and key indexes.
 */
export class IdentifierManagerFactory {
    private modules: Record<string, ExternalModuleType> = {};
    #saltySignerCache = new Map<string, CachedSaltySignerSet>();

    /**
     * Creates a factory for generating IdentifierManagers. Requires a salt to be specified.
     * Allows external key management modules to be configured.
     * @param salter
     * @param externalModules
     * @param cacheSigners whether to retain verified salty signer snapshots
     */
    constructor(
        private salter: Salter,
        externalModules: ExternalModule[] = [],
        private cacheSigners = false
    ) {
        this.salter = salter;

        for (const mod of externalModules) {
            this.modules[mod.type] = mod.module;
        }
    }

    /**
     *
     * @param algo
     * @param pidx
     * @param kargs
     */
    new(algo: Algos, pidx: number, kargs: any) {
        switch (algo) {
            case Algos.salty:
                return new SaltyIdentifierManager(
                    this.salter!,
                    pidx,
                    kargs['kidx'],
                    kargs['tier'],
                    kargs['transferable'],
                    kargs['stem'],
                    kargs['code'],
                    kargs['count'],
                    kargs['icodes'],
                    kargs['ncode'],
                    kargs['ncount'],
                    kargs['ncodes'],
                    kargs['dcode'],
                    kargs['bran'],
                    kargs['sxlt']
                );
            case Algos.randy:
                return new RandyIdentifierManager(
                    this.salter!,
                    kargs['code'],
                    kargs['count'],
                    kargs['icodes'],
                    kargs['transferable'],
                    kargs['ncode'],
                    kargs['ncount'],
                    kargs['ncodes'],
                    kargs['dcode'],
                    kargs['prxs'],
                    kargs['nxts']
                );
            case Algos.group:
                return new GroupIdentifierManager(
                    this,
                    kargs['mhab'],
                    kargs['states'],
                    kargs['rstates'],
                    kargs['keys'],
                    kargs['ndigs']
                );
            case Algos.extern: {
                const ModuleConstructor = this.modules[kargs.extern_type];
                if (!ModuleConstructor) {
                    throw new Error(
                        `unsupported external module type ${kargs.extern_type}`
                    );
                }

                return new ModuleConstructor(pidx, kargs);
            }
            default:
                throw new Error('Unknown algo');
        }
    }

    /**
     * Generates an algorithm-specific IdentifierManager instance with correct keys based on
     * the indexes provided by the HabState.
     * @param aid HabState with the algorithm and key indexes
     * @returns IdentifierManager instance
     */
    get(aid: HabState): IdentifierManager {
        if (Algos.salty in aid) {
            return this.getSalty(aid as HabState & { salty: SaltyKeyState });
        } else if (Algos.randy in aid) {
            return new RandyIdentifierManager(
                this.salter,
                undefined,
                undefined,
                undefined,
                new Prefixer({ qb64: aid['prefix'] }).transferable,
                undefined,
                undefined,
                [],
                undefined,
                aid.randy.prxs,
                aid.randy.nxts
            );
        } else if (Algos.group in aid) {
            return new GroupIdentifierManager(
                this,
                aid.group.mhab,
                undefined,
                undefined,
                aid.group.keys,
                aid.group.ndigs
            );
        } else if (Algos.extern in aid) {
            const typ = aid.extern.extern_type;
            if (typ in this.modules) {
                const mod = new this.modules[typ](aid.extern.pidx, aid.extern);
                return mod;
            } else {
                throw new Error(`unsupported external module type ${typ}`);
            }
        } else {
            throw new Error('No algo specified');
        }
    }

    /**
     * Drop all cache-owned references to salty signer snapshots.
     *
     * JavaScript cannot guarantee physical zeroization of immutable strings
     * or garbage-collected objects. Managers already returned to callers
     * remain usable.
     */
    clearSignerCache(): void {
        this.#saltySignerCache.clear();
    }

    private getSalty(
        aid: HabState & { salty: SaltyKeyState }
    ): SaltyIdentifierManager {
        if (!this.cacheSigners) {
            return SaltyIdentifierManager.fromState(this.salter, aid.salty);
        }

        const observation = this.validateSaltyObservation(aid);
        const cached = this.#saltySignerCache.get(aid.prefix);
        if (cached !== undefined) {
            if (
                observation.establishmentSequence < cached.establishmentSequence
            ) {
                throw new Error(
                    `Salty signer cache rejected establishment regression for ${aid.prefix}: ${observation.establishmentSequence} is older than ${cached.establishmentSequence}.`
                );
            }

            if (
                observation.establishmentSequence ===
                cached.establishmentSequence
            ) {
                if (
                    observation.establishmentDigest !==
                    cached.establishmentDigest
                ) {
                    throw new Error(
                        `Salty signer cache rejected conflicting establishment digest for ${aid.prefix} at sequence ${observation.establishmentSequence}.`
                    );
                }
                if (!arraysEqual(observation.publicKeys, cached.publicKeys)) {
                    throw new Error(
                        `Salty signer cache rejected conflicting public keys for ${aid.prefix} at sequence ${observation.establishmentSequence}.`
                    );
                }

                this.#saltySignerCache.delete(aid.prefix);
                this.#saltySignerCache.set(aid.prefix, cached);
                return SaltyIdentifierManager.fromState(
                    this.salter,
                    aid.salty,
                    cached
                );
            }
        }

        const manager = SaltyIdentifierManager.fromState(
            this.salter,
            aid.salty
        );
        const derivedPublicKeys = manager.signers.map(
            (signer) => signer.verfer.qb64
        );
        if (!arraysEqual(derivedPublicKeys, observation.publicKeys)) {
            throw new Error(
                `Derived salty signer keys do not match accepted state for ${aid.prefix} at establishment sequence ${observation.establishmentSequence}.`
            );
        }

        const entry = Object.freeze({
            establishmentSequence: observation.establishmentSequence,
            establishmentDigest: observation.establishmentDigest,
            publicKeys: Object.freeze([...observation.publicKeys]),
            signerQb64s: Object.freeze(
                manager.signers.map((signer) => signer.qb64)
            ),
        });
        this.#saltySignerCache.delete(aid.prefix);
        this.#saltySignerCache.set(aid.prefix, entry);
        if (this.#saltySignerCache.size > MAX_CACHED_SIGNER_SETS) {
            const oldestPrefix = this.#saltySignerCache.keys().next().value;
            if (oldestPrefix !== undefined) {
                this.#saltySignerCache.delete(oldestPrefix);
            }
        }

        return manager;
    }

    private validateSaltyObservation(aid: HabState): {
        establishmentSequence: number;
        establishmentDigest: string;
        publicKeys: readonly string[];
    } {
        if (typeof aid.prefix !== 'string' || aid.prefix.length === 0) {
            throw new Error(
                'Salty signer cache requires a non-empty identifier prefix.'
            );
        }
        if (aid.state.i !== aid.prefix) {
            throw new Error(
                `Salty signer cache prefix ${aid.prefix} does not match key state identifier ${aid.state.i}.`
            );
        }

        const sequence = aid.state.ee.s;
        if (typeof sequence !== 'string' || !/^[0-9a-fA-F]+$/.test(sequence)) {
            throw new Error(
                `Salty signer cache requires a hexadecimal establishment sequence for ${aid.prefix}.`
            );
        }
        const establishmentSequence = Number.parseInt(sequence, 16);
        if (
            !Number.isSafeInteger(establishmentSequence) ||
            establishmentSequence < 0
        ) {
            throw new Error(
                `Salty signer cache establishment sequence is out of range for ${aid.prefix}.`
            );
        }

        const establishmentDigest = aid.state.ee.d;
        if (
            typeof establishmentDigest !== 'string' ||
            establishmentDigest.length === 0
        ) {
            throw new Error(
                `Salty signer cache requires an establishment digest for ${aid.prefix}.`
            );
        }
        if (
            !Array.isArray(aid.state.k) ||
            !aid.state.k.every((key) => typeof key === 'string')
        ) {
            throw new Error(
                `Salty signer cache requires ordered public keys for ${aid.prefix}.`
            );
        }

        return {
            establishmentSequence,
            establishmentDigest,
            publicKeys: aid.state.k,
        };
    }
}

function arraysEqual(
    left: readonly string[],
    right: readonly string[]
): boolean {
    return (
        left.length === right.length &&
        left.every((value, index) => value === right[index])
    );
}

export class SaltyIdentifierManager implements IdentifierManager {
    private aeid: string | undefined;
    private encrypter: Encrypter | undefined;
    private decrypter: Decrypter | undefined;
    private salter!: Salter;
    private pidx!: number;
    private kidx!: number;
    private tier!: Tier;
    private transferable!: boolean;
    private acceptedTransferable!: boolean;
    private stem: string | undefined;
    private code!: string;
    private count!: number;
    private icodes: string[] | undefined;
    private ncode!: string;
    private ncount!: number;
    private ncodes: string[] | undefined;
    private dcode: string | undefined;
    private sxlt: string | undefined;
    private bran: string | undefined;
    private creator: SaltyCreator | undefined;
    public algo!: Algos;
    public signers!: Signer[];

    constructor(
        salter: Salter,
        pidx: number,
        kidx: number = 0,
        tier = Tier.low,
        transferable = false,
        stem: string | undefined = undefined,
        code = MtrDex.Ed25519_Seed,
        count = 1,
        icodes: string[] | undefined = undefined,
        ncode = MtrDex.Ed25519_Seed,
        ncount = 1,
        ncodes: string[] | undefined = undefined,
        dcode = MtrDex.Blake3_256,
        bran: string | undefined = undefined,
        sxlt: string | undefined = undefined
    ) {
        this.initialize(salter, {
            pidx,
            kidx,
            tier,
            transferable,
            stem,
            code,
            count,
            icodes,
            ncode,
            ncount,
            ncodes,
            dcode,
            bran,
            sxlt,
        });
    }

    /**
     * Recreate a manager for an accepted salty state.
     *
     * Supplying a signer snapshot avoids salt recovery and key derivation.
     * The returned manager owns fresh signer objects and copied keeper arrays.
     * @internal
     */
    static fromState(
        salter: Salter,
        state: SaltyKeyState,
        snapshot?: SaltySignerSnapshot
    ): SaltyIdentifierManager {
        const manager = Object.create(
            SaltyIdentifierManager.prototype
        ) as SaltyIdentifierManager;
        manager.initialize(
            salter,
            {
                pidx: state.pidx,
                kidx: state.kidx,
                tier: state.tier,
                transferable: state.transferable,
                stem: state.stem,
                code: MtrDex.Ed25519_Seed,
                count: state.icodes?.length ?? 1,
                icodes: state.icodes,
                ncode: MtrDex.Ed25519_Seed,
                ncount: state.ncodes?.length ?? 1,
                ncodes: state.ncodes,
                dcode: state.dcode,
                bran: undefined,
                sxlt: state.sxlt,
            },
            snapshot
        );
        return manager;
    }

    private initialize(
        salter: Salter,
        state: SaltyManagerInitialization,
        snapshot?: SaltySignerSnapshot
    ): void {
        this.salter = salter;
        this.pidx = state.pidx;
        this.kidx = state.kidx;
        this.tier = state.tier;
        this.transferable = state.transferable;
        this.acceptedTransferable = state.transferable;
        this.stem = state.stem ?? 'signify:aid';
        this.code = state.code;
        this.count = state.count;
        this.icodes =
            state.icodes === undefined
                ? new Array<string>(state.count).fill(state.code)
                : [...state.icodes];
        this.ncode = state.ncode;
        this.ncount = state.ncount;
        this.ncodes =
            state.ncodes === undefined
                ? new Array<string>(state.ncount).fill(state.ncode)
                : [...state.ncodes];
        this.dcode = state.dcode;
        this.bran =
            state.bran === undefined
                ? undefined
                : MtrDex.Salt_128 + 'A' + state.bran.slice(0, 21);
        this.sxlt = state.sxlt;
        this.aeid = undefined;
        this.encrypter = undefined;
        this.decrypter = undefined;
        this.creator = undefined;
        this.algo = Algos.salty;

        if (snapshot === undefined) {
            const creator = this.initializeCreator();
            this.signers = creator.create(
                this.icodes,
                this.ncount,
                this.ncode,
                this.transferable,
                this.pidx,
                0,
                this.kidx,
                false
            ).signers;
        } else {
            this.signers = this.recreateSigners(snapshot);
        }
    }

    private recreateSigners(snapshot: SaltySignerSnapshot): Signer[] {
        if (snapshot.publicKeys.length !== snapshot.signerQb64s.length) {
            throw new Error(
                'Signer snapshot key and seed counts do not match.'
            );
        }

        return snapshot.signerQb64s.map((signerQb64, index) => {
            const publicKey = snapshot.publicKeys[index];
            const verfer = new Verfer({ qb64: publicKey });
            if (verfer.transferable !== this.transferable) {
                throw new Error(
                    `Signer snapshot transferability does not match salty state for key ${index}.`
                );
            }

            const signer = new Signer({
                qb64: signerQb64,
                transferable: verfer.transferable,
            });
            if (signer.verfer.qb64 !== publicKey) {
                throw new Error(
                    `Signer snapshot does not reproduce public key ${index}.`
                );
            }
            return signer;
        });
    }

    private initializeCreator(): SaltyCreator {
        if (this.creator !== undefined) {
            return this.creator;
        }

        // The controller salter protects the accepted AID salt. Recover it
        // with the accepted state's transferability before an operation can
        // mutate its local candidate fields.
        const signer = this.salter.signer(
            this.code,
            this.acceptedTransferable,
            undefined,
            this.tier
        );
        this.aeid = signer.verfer.qb64;
        this.encrypter = new Encrypter({}, b(this.aeid));
        this.decrypter = new Decrypter({}, signer.qb64b);

        if (this.bran !== undefined) {
            this.creator = new SaltyCreator(this.bran, this.tier, this.stem);
            this.sxlt = this.encrypter.encrypt(b(this.creator.salt)).qb64;
        } else if (this.sxlt === undefined) {
            this.creator = new SaltyCreator(undefined, this.tier, this.stem);
            this.sxlt = this.encrypter.encrypt(b(this.creator.salt)).qb64;
        } else {
            const cipher = new Cipher({ qb64: this.sxlt });
            this.creator = new SaltyCreator(
                this.decrypter.decrypt(null, cipher).qb64,
                this.tier,
                this.stem
            );
        }

        return this.creator;
    }

    params(): SaltyManagerParams {
        return {
            sxlt: this.sxlt,
            pidx: this.pidx,
            kidx: this.kidx,
            stem: this.stem,
            tier: this.tier,
            icodes: this.icodes === undefined ? undefined : [...this.icodes],
            ncodes: this.ncodes === undefined ? undefined : [...this.ncodes],
            dcode: this.dcode,
            transferable: this.transferable,
        };
    }

    async incept(transferable: boolean): Promise<IdentifierManagerResult> {
        const creator = this.initializeCreator();
        this.transferable = transferable;
        this.kidx = 0;

        const signers = creator.create(
            this.icodes,
            this.count,
            this.code,
            this.transferable,
            this.pidx,
            0,
            this.kidx,
            false
        );
        this.signers = signers.signers;
        const verfers = signers.signers.map((signer) => signer.verfer.qb64);

        const nsigners = creator.create(
            this.ncodes,
            this.ncount,
            this.ncode,
            this.transferable,
            this.pidx,
            0,
            this.icodes?.length,
            false
        );
        const digers = nsigners.signers.map(
            (nsigner) =>
                new Diger({ code: this.dcode }, nsigner.verfer.qb64b).qb64
        );

        return [verfers, digers];
    }

    async rotate(
        ncodes: string[],
        transferable: boolean
    ): Promise<[string[], string[]]> {
        const creator = this.initializeCreator();
        this.ncodes = ncodes;
        this.transferable = transferable;
        const signers = creator.create(
            this.ncodes,
            this.ncount,
            this.ncode,
            this.transferable,
            this.pidx,
            0,
            this.kidx + this.icodes!.length,
            false
        );
        this.signers = signers.signers;
        const verfers = signers.signers.map((signer) => signer.verfer.qb64);

        this.kidx = this.kidx! + this.icodes!.length;
        const nsigners = creator.create(
            this.ncodes,
            this.ncount,
            this.ncode,
            this.transferable,
            this.pidx,
            0,
            this.kidx + this.icodes!.length,
            false
        );
        const digers = nsigners.signers.map(
            (nsigner) =>
                new Diger({ code: this.dcode }, nsigner.verfer.qb64b).qb64
        );

        return [verfers, digers];
    }

    async sign(
        ser: Uint8Array,
        indexed = true,
        indices: number[] | undefined = undefined,
        ondices: Ondex[] | undefined = undefined,
        _rotated?: boolean
    ): Promise<SignResult> {
        if (indexed) {
            const sigers = [];
            let i = 0;
            for (const [j, signer] of this.signers.entries()) {
                if (
                    indices &&
                    indices.length > 0 &&
                    indices.length === this.signers.length
                ) {
                    i = indices[j]; // default indexing behavior of pulling index order from signer order
                    if (!Number.isInteger(i) || i < 0) {
                        throw new Error(
                            `Invalid signing index = ${i}, not whole number.`
                        );
                    }
                } else {
                    i = j;
                }
                let o: Ondex = 0;
                // if ondices are specified then the count and order should match the indices list
                // even if a given ondex is "undefined" which means to ignore the ondex (dual indexed sig)
                // for that given index.
                if (ondices && ondices.length > 0) {
                    o = ondices[j];
                    if (o !== undefined && (!Number.isInteger(o) || o < 0)) {
                        throw new Error(
                            `Invalid ondex = ${o}, not whole number.`
                        );
                    }
                } else {
                    o = i;
                }
                sigers.push(
                    signer.sign(ser, i, o === undefined ? true : false, o)
                );
            }
            return sigers.map((siger) => siger.qb64);
        } else {
            const cigars = [];
            for (const signer of this.signers) {
                cigars.push(signer.sign(ser));
            }
            return cigars.map((cigar) => cigar.qb64);
        }
    }
}

export class RandyIdentifierManager implements IdentifierManager {
    private salter: Salter;
    private code: string;
    private count: number;
    private icodes: string[] | undefined;
    private transferable: boolean;
    private ncount: number;
    private ncodes: string[] | undefined;
    private ncode: string;
    private dcode: string | undefined;
    private prxs: string[] | undefined;
    private nxts: string[] | undefined;
    private aeid: string;
    private encrypter: Encrypter;
    private decrypter: Decrypter;
    private creator: RandyCreator;
    public algo: Algos = Algos.randy;
    public signers: Signer[];

    constructor(
        salter: Salter,
        code = MtrDex.Ed25519_Seed,
        count = 1,
        icodes: string[] | undefined = undefined,
        transferable = false,
        ncode = MtrDex.Ed25519_Seed,
        ncount = 1,
        ncodes: string[],
        dcode = MtrDex.Blake3_256,
        prxs: string[] | undefined = undefined,
        nxts: string[] | undefined = undefined
    ) {
        this.salter = salter;
        this.icodes =
            icodes == undefined ? new Array<string>(count).fill(code) : icodes;
        this.ncodes =
            ncodes == undefined
                ? new Array<string>(ncount).fill(ncode)
                : ncodes;

        this.code = code;
        this.ncode = ncode;
        this.count = count;
        this.ncount = ncount;

        const signer = this.salter.signer(code, transferable);
        this.aeid = signer.verfer.qb64;

        this.encrypter = new Encrypter({}, b(this.aeid));
        this.decrypter = new Decrypter({}, signer.qb64b);

        this.nxts = nxts ?? [];
        this.prxs = prxs ?? [];
        this.transferable = transferable;

        this.icodes = icodes;
        this.ncodes = ncodes;
        this.dcode = dcode;

        this.creator = new RandyCreator();

        this.signers = this.prxs.map((prx) =>
            this.decrypter.decrypt(
                new Cipher({ qb64: prx }).qb64b,
                undefined,
                this.transferable
            )
        );
    }

    params(): RandyManagerParams {
        return {
            nxts: this.nxts,
            prxs: this.prxs,
            transferable: this.transferable,
        };
    }

    async incept(transferable: boolean): Promise<IdentifierManagerResult> {
        this.transferable = transferable;

        const signers = this.creator.create(
            this.icodes,
            this.count,
            this.code,
            this.transferable
        );
        this.prxs = signers.signers.map(
            (signer) => this.encrypter.encrypt(undefined, signer).qb64
        );

        const verfers = signers.signers.map((signer) => signer.verfer.qb64);

        const nsigners = this.creator.create(
            this.ncodes,
            this.ncount,
            this.ncode,
            this.transferable
        );

        this.nxts = nsigners.signers.map(
            (signer) => this.encrypter.encrypt(undefined, signer).qb64
        );

        const digers = nsigners.signers.map(
            (nsigner) =>
                new Diger({ code: this.dcode }, nsigner.verfer.qb64b).qb64
        );

        return [verfers, digers];
    }

    async rotate(
        ncodes: string[],
        transferable: boolean
    ): Promise<IdentifierManagerResult> {
        this.ncodes = ncodes;
        this.transferable = transferable;
        this.prxs = this.nxts;

        const signers = this.nxts!.map((nxt) =>
            this.decrypter.decrypt(
                undefined,
                new Cipher({ qb64: nxt }),
                this.transferable
            )
        );
        const verfers = signers.map((signer) => signer.verfer.qb64);
        const nsigners = this.creator.create(
            this.ncodes,
            this.ncount,
            this.ncode,
            this.transferable
        );

        this.nxts = nsigners.signers.map(
            (signer) => this.encrypter.encrypt(undefined, signer).qb64
        );

        const digers = nsigners.signers.map(
            (nsigner) =>
                new Diger({ code: this.dcode }, nsigner.verfer.qb64b).qb64
        );

        return [verfers, digers];
    }

    async sign(
        ser: Uint8Array,
        indexed = true,
        indices: number[] | undefined = undefined,
        ondices: Ondex[] | undefined = undefined,
        _rotated?: boolean
    ): Promise<SignResult> {
        const signers = this.prxs!.map((prx) =>
            this.decrypter.decrypt(
                new Cipher({ qb64: prx }).qb64b,
                undefined,
                this.transferable
            )
        );

        if (indexed) {
            const sigers = [];
            let i = 0;
            for (const [j, signer] of signers.entries()) {
                if (indices != undefined) {
                    i = indices![j];
                    if (typeof i != 'number' || i < 0) {
                        throw new Error(
                            `Invalid signing index = ${i}, not whole number.`
                        );
                    }
                } else {
                    i = j;
                }
                let o: number | undefined = 0;
                if (ondices != undefined) {
                    o = ondices![j];
                    if (o !== undefined && (!Number.isInteger(o) || o < 0)) {
                        throw new Error(
                            `Invalid ondex = ${o}, not whole number.`
                        );
                    }
                } else {
                    o = i;
                }
                sigers.push(
                    signer.sign(ser, i, o === undefined ? true : false, o)
                );
            }
            return sigers.map((siger) => siger.qb64);
        } else {
            const cigars = [];
            for (const [, signer] of signers.entries()) {
                cigars.push(signer.sign(ser));
            }
            return cigars.map((cigar) => cigar.qb64);
        }
    }
}

// ondex = other index in KERI's dual indexing scheme of
//   - Index: signing key index (csi - current signing index)
//   - Ondex: rotation key index (pni - prior next index)
type Ondex = number | undefined;

/**
 * Identifier manager for group identifiers.
 *
 * A group identifier does not have its own private signing keys. Instead, this
 * manager maps group event signing indexes onto the local member AID (`mhab`)
 * and delegates actual signing to that member's key manager.
 *
 * The central invariant is that indexed rotation signatures carry two
 * positions:
 *
 * - `index` points to the signer's current key in the event's current key list
 *   (`k`), which SignifyTS derives from `states`.
 * - `ondex` points to the prior establishment event's next digest list (`n`),
 *   proving that the current key was a precommitted key.
 *
 * `rstates` are the proposed next digest source for the new event. They are not
 * the signer authorization set for the event being signed.
 */
export class GroupIdentifierManager implements IdentifierManager {
    /** Factory used to recover the local member keeper that performs signing. */
    private manager: IdentifierManagerFactory;

    /** Local member AID whose private key signs on behalf of the group. */
    private mhab: HabState;

    /**
     * Current group signing public keys for the event being built. During
     * rotation these come from `states[*].k[0]` and define signature `index`.
     */
    private gkeys: string[] = [];

    /**
     * Proposed next digest list for the event being built. During rotation
     * these come from `rstates[*].n[0]`, are returned from `rotate()`, and are
     * serialized as `group.ndigs`.
     */
    private gdigs: string[] = [];

    /**
     * Prior next digest list from the current group establishment event. For
     * rotations, this is the authorization commitment set used to derive
     * `ondex`; it must remain separate from proposed next digests in `gdigs`.
     */
    private gpndigs: string[] = [];

    public algo: Algos = Algos.group;

    /**
     * Retained for the `IdentifierManager` interface. Group signing delegates
     * to the local member AID keeper instead of storing signers here.
     */
    public signers: Signer[];

    /**
     * Creates a manager for either a new group event or an existing group AID.
     *
     * `states` and `rstates` are app-level key state records used when creating
     * a new group event. `keys` and `ndigs` are persisted group manager params
     * used when loading an existing group. For an existing group, `ndigs` is
     * expected to be the current establishment event's next digest list.
     *
     * During group inception there is no separate prior establishment event, so
     * `gpndigs` starts as the same digest list as `gdigs`. During rotation,
     * `gdigs` changes to the proposed next digests, while `gpndigs` stays
     * fixed for `ondex` derivation.
     */
    constructor(
        manager: IdentifierManagerFactory,
        mhab: HabState,
        states: KeyState[] | undefined = undefined,
        rstates: KeyState[] | undefined = undefined,
        keys: string[] = [],
        ndigs: string[] = []
    ) {
        this.manager = manager;
        if (states != undefined) {
            keys = states.map((state) => state['k'][0]);
        }

        if (rstates != undefined) {
            ndigs = rstates.map((state) => state['n'][0]);
        }

        this.gkeys = states?.map((state) => state['k'][0]) ?? keys;
        this.gdigs = rstates?.map((state) => state['n'][0]) ?? ndigs;
        this.gpndigs = this.gdigs;
        this.mhab = mhab;
        this.signers = [];
    }

    /**
     * Returns the inception key material for the group event.
     *
     * Inception has no prior group establishment event. The current keys and
     * proposed next digests are therefore returned directly from the manager's
     * configured `states` and `rstates`.
     */
    async incept(): Promise<IdentifierManagerResult> {
        return [this.gkeys, this.gdigs];
    }

    /**
     * Performs a multisig rotation.
     *
     * `states` supplies the current group signing keys for the event being
     * signed. `rstates` supplies the proposed next key digests to put in the
     * new event. The prior next digests used for rotation `ondex` lookup stay
     * unchanged until KERIA accepts the new establishment event and returns an
     * updated group state.
     *
     * @param _ncodes
     * @param _transferable
     * @param states
     * @param rstates
     */
    async rotate(
        _ncodes: string[],
        _transferable: boolean,
        states: KeyState[],
        rstates: KeyState[]
    ): Promise<IdentifierManagerResult> {
        this.gkeys = states.map((state) => state['k'][0]);
        this.gdigs = rstates.map((state) => state['n'][0]);
        return [this.gkeys, this.gdigs];
    }

    /**
     * Signs for the group by delegating to the local member keeper.
     */
    async sign(
        ser: Uint8Array,
        indexed: boolean = true,
        _indices: number[] | undefined = undefined,
        _ondices: Ondex[] | undefined = undefined,
        rotated = false
    ): Promise<SignResult> {
        if (!this.mhab.state) {
            throw new Error(`No state in mhab`);
        }

        const key = this.mhab['state']['k'][0];
        // The event's current key list authorizes the signature's `index`.
        const csi = this.gkeys!.indexOf(key); // csi = current signing index (from current rotation event)
        if (csi < 0) {
            throw new Error(
                `Group signing key ${key} is not present in current group signing keys.`
            );
        }

        let pni: number | undefined; // prior next index exposed as signature `ondex`

        if (rotated) {
            // Rotation call sites must explicitly request prior-next exposure,
            // dual indexed signatures with both an index (csi) and an ondex (pni)
            pni = this.priorNextIndexForKey(key);
        } else {
            // Inception and non-rotation signatures satisfy only the current
            // signing threshold. The event's `n` field is a precommitment for a
            // future rotation, not an `ondex` source.
            pni = undefined;
        }

        if (pni !== undefined && pni < 0) {
            throw new Error(
                `Group signing key ${key} cannot derive ondex from prior next digest list.`
            );
        }

        // Delegate the actual signature to the local member AID keeper while
        // supplying group-level index and ondex positions.
        const mkeeper = this.manager.get(this.mhab);

        return await mkeeper.sign(ser, indexed, [csi], [pni]);
    }

    /**
     * Finds the prior next digest position that precommitted the current key.
     *
     * This mirrors KERIpy's exposed-prior-next behavior: for each prior next
     * digest, hash the current verifier key using that digest's code and compare
     * the result to the digest at that position. A match means the signer has
     * exposed that precommitted key, and the matching position is the `ondex`.
     */
    private priorNextIndexForKey(key: string): number {
        const verfer = new Verfer({ qb64: key });

        for (const [index, ndig] of this.gpndigs.entries()) {
            const priorDiger = new Diger({ qb64: ndig });
            const keyDigest = new Diger({ code: priorDiger.code }, verfer.qb64b)
                .qb64;

            if (keyDigest === priorDiger.qb64) {
                return index;
            }
        }

        return -1;
    }

    params() {
        return {
            mhab: this.mhab,
            keys: this.gkeys,
            ndigs: this.gdigs,
        };
    }
}
