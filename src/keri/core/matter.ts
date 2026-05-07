import { EmptyMaterialError } from './kering.ts';

import { b64ToInt, concat, intToB64, readInt } from './core.ts';
import { b, d } from './core.ts';
import { decodeBase64Url, encodeBase64Url } from './base64.ts';

export class Codex {
    has(prop: string): boolean {
        const m = new Map(
            Array.from(Object.entries(this), (v) => [v[1], v[0]])
        );
        return m.has(prop);
    }
}

export class MatterCodex extends Codex {
    Ed25519_Seed: string = 'A'; // Ed25519 256 bit random seed for private key
    Ed25519N: string = 'B'; // Ed25519 verification key non-transferable, basic derivation.
    X25519: string = 'C'; // X25519 public encryption key, converted from Ed25519 or Ed25519N.
    Ed25519: string = 'D'; // Ed25519 verification key basic derivation
    Blake3_256: string = 'E'; // Blake3 256 bit digest self-addressing derivation.
    SHA3_256: string = 'H'; // SHA3 256 bit digest self-addressing derivation.
    SHA2_256: string = 'I'; // SHA2 256 bit digest self-addressing derivation.
    ECDSA_256k1_Seed: string = 'J'; // ECDSA secp256k1 256 bit random Seed for private key
    X25519_Private: string = 'O'; // X25519 private decryption key converted from Ed25519
    X25519_Cipher_Seed: string = 'P'; // X25519 124 char b64 Cipher of 44 char qb64 Seed
    ECDSA_256r1_Seed: string = 'Q'; // ECDSA secp256r1 256 bit random Seed for private key
    Salt_128: string = '0A'; // 128 bit random salt or 128 bit number (see Huge)
    Ed25519_Sig: string = '0B'; // Ed25519 signature.
    ECDSA_256k1_Sig: string = '0C'; // ECDSA secp256k1 signature.
    ECDSA_256r1_Sig: string = '0I'; // ECDSA secp256r1 signature.
    StrB64_L0: string = '4A'; // String Base64 Only Lead Size 0
    StrB64_L1: string = '5A'; // String Base64 Only Lead Size 1
    StrB64_L2: string = '6A'; // String Base64 Only Lead Size 2
    ECDSA_256k1N: string = '1AAA'; // ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1: string = '1AAB'; // ECDSA public verification or encryption key, basic derivation
    X25519_Cipher_Salt: string = '1AAH'; // X25519 100 char b64 Cipher of 24 char qb64 Salt
    ECDSA_256r1N: string = '1AAI'; // ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1: string = '1AAJ'; // ECDSA secp256r1 verification or encryption key, basic derivation
    StrB64_Big_L0: string = '7AAA'; // String Base64 Only Big Lead Size 0
    StrB64_Big_L1: string = '8AAA'; // String Base64 Only Big Lead Size 1
    StrB64_Big_L2: string = '9AAA'; // String Base64 Only Big Lead Size 2
    X25519_Cipher_L0: string = '4C'; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    X25519_Cipher_L1: string = '5C'; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    X25519_Cipher_L2: string = '6C'; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    X25519_Cipher_Big_L0: string = '7AAC'; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    X25519_Cipher_Big_L1: string = '8AAC'; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    X25519_Cipher_Big_L2: string = '9AAC'; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
}

export const MtrDex = new MatterCodex();

export class NonTransCodex extends Codex {
    Ed25519N: string = 'B'; // Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N: string = '1AAA'; // ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N: string = '1AAC'; // Ed448 non-transferable prefix public signing verification key. Basic derivation.
    ECDSA_256r1N: string = '1AAI'; // ECDSA secp256r1 verification key non-transferable, basic derivation.
}

export const NonTransDex = new NonTransCodex();

export class DigiCodex extends Codex {
    Blake3_256: string = 'E'; // Blake3 256 bit digest self-addressing derivation.
    Blake2b_256: string = 'F'; // Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256: string = 'G'; // Blake2s 256 bit digest self-addressing derivation.
    SHA3_256: string = 'H'; // SHA3 256 bit digest self-addressing derivation.
    SHA2_256: string = 'I'; // SHA2 256 bit digest self-addressing derivation.
    Blake3_512: string = '0D'; // Blake3 512 bit digest self-addressing derivation.
    Blake2b_512: string = '0E'; // Blake2b 512 bit digest self-addressing derivation.
    SHA3_512: string = '0F'; // SHA3 512 bit digest self-addressing derivation.
    SHA2_512: string = '0G'; // SHA2 512 bit digest self-addressing derivation.
}

export const DigiDex = new DigiCodex();

export class NumCodex extends Codex {
    Short: string = 'M'; // Short 2 byte b2 number
    Long: string = '0H'; // Long 4 byte b2 number
    Big: string = 'N'; // Big 8 byte b2 number
    Huge: string = '0A'; // Huge 16 byte b2 number (same as Salt_128)
}

export const NumDex = new NumCodex();

export class BexCodex extends Codex {
    StrB64_L0: string = '4A'; // String Base64 Only Leader Size 0
    StrB64_L1: string = '5A'; // String Base64 Only Leader Size 1
    StrB64_L2: string = '6A'; // String Base64 Only Leader Size 2
    StrB64_Big_L0: string = '7AAA'; // String Base64 Only Big Leader Size 0
    StrB64_Big_L1: string = '8AAA'; // String Base64 Only Big Leader Size 1
    StrB64_Big_L2: string = '9AAA'; // String Base64 Only Big Leader Size 2
}

export const BexDex = new BexCodex();

class SmallVarRawSizeCodex extends Codex {
    Lead0: string = '4'; // First Selector Character for all ls == 0 codes
    Lead1: string = '5'; // First Selector Character for all ls == 1 codes
    Lead2: string = '6'; // First Selector Character for all ls == 2 codes
}

export const SmallVrzDex = new SmallVarRawSizeCodex();

class LargeVarRawSizeCodex extends Codex {
    Lead0_Big: string = '7'; // First Selector Character for all ls == 0 codes
    Lead1_Big: string = '8'; // First Selector Character for all ls == 1 codes
    Lead2_Big: string = '9'; // First Selector Character for all ls == 2 codes
}

export const LargeVrzDex = new LargeVarRawSizeCodex();

export class Sizage {
    public hs: number;
    public ss: number;
    public ls?: number;
    public fs?: number;

    constructor(hs: number, ss: number, fs?: number, ls?: number) {
        this.hs = hs;
        this.ss = ss;
        this.fs = fs;
        this.ls = ls!;
    }
}

export interface MatterArgs {
    raw?: Uint8Array | undefined;
    code?: string;
    qb64b?: Uint8Array | undefined;
    qb64?: string;
    qb2?: Uint8Array | undefined;
    rize?: number;
}

export class Matter {
    static Sizes = new Map(
        Object.entries({
            A: new Sizage(1, 0, 44, 0),
            B: new Sizage(1, 0, 44, 0),
            C: new Sizage(1, 0, 44, 0),
            D: new Sizage(1, 0, 44, 0),
            E: new Sizage(1, 0, 44, 0),
            F: new Sizage(1, 0, 44, 0),
            G: new Sizage(1, 0, 44, 0),
            H: new Sizage(1, 0, 44, 0),
            I: new Sizage(1, 0, 44, 0),
            J: new Sizage(1, 0, 44, 0),
            K: new Sizage(1, 0, 76, 0),
            L: new Sizage(1, 0, 76, 0),
            M: new Sizage(1, 0, 4, 0),
            N: new Sizage(1, 0, 12, 0),
            O: new Sizage(1, 0, 44, 0),
            P: new Sizage(1, 0, 124, 0),
            Q: new Sizage(1, 0, 44, 0),
            '0A': new Sizage(2, 0, 24, 0),
            '0B': new Sizage(2, 0, 88, 0),
            '0C': new Sizage(2, 0, 88, 0),
            '0D': new Sizage(2, 0, 88, 0),
            '0E': new Sizage(2, 0, 88, 0),
            '0F': new Sizage(2, 0, 88, 0),
            '0G': new Sizage(2, 0, 88, 0),
            '0H': new Sizage(2, 0, 8, 0),
            '0I': new Sizage(2, 0, 88, 0),
            '1AAA': new Sizage(4, 0, 48, 0),
            '1AAB': new Sizage(4, 0, 48, 0),
            '1AAC': new Sizage(4, 0, 80, 0),
            '1AAD': new Sizage(4, 0, 80, 0),
            '1AAE': new Sizage(4, 0, 56, 0),
            '1AAF': new Sizage(4, 0, 8, 0),
            '1AAG': new Sizage(4, 0, 36, 0),
            '1AAH': new Sizage(4, 0, 100, 0),
            '1AAI': new Sizage(4, 0, 48, 0),
            '1AAJ': new Sizage(4, 0, 48, 0),
            '2AAA': new Sizage(4, 0, 8, 1),
            '3AAA': new Sizage(4, 0, 8, 2),
            '4A': new Sizage(2, 2, undefined, 0),
            '5A': new Sizage(2, 2, undefined, 1),
            '6A': new Sizage(2, 2, undefined, 2),
            '7AAA': new Sizage(4, 4, undefined, 0),
            '8AAA': new Sizage(4, 4, undefined, 1),
            '9AAA': new Sizage(4, 4, undefined, 2),
            '4B': new Sizage(2, 2, undefined, 0),
            '5B': new Sizage(2, 2, undefined, 1),
            '6B': new Sizage(2, 2, undefined, 2),
            '7AAB': new Sizage(4, 4, undefined, 0),
            '8AAB': new Sizage(4, 4, undefined, 1),
            '9AAB': new Sizage(4, 4, undefined, 2),
            '4C': new Sizage(2, 2, undefined, 0),
            '5C': new Sizage(2, 2, undefined, 1),
            '6C': new Sizage(2, 2, undefined, 2),
            '7AAC': new Sizage(4, 4, undefined, 0),
            '8AAC': new Sizage(4, 4, undefined, 1),
            '9AAC': new Sizage(4, 4, undefined, 2),
        })
    );

    static Hards = new Map<string, number>([
        ['A', 1],
        ['B', 1],
        ['C', 1],
        ['D', 1],
        ['E', 1],
        ['F', 1],
        ['G', 1],
        ['H', 1],
        ['I', 1],
        ['J', 1],
        ['K', 1],
        ['L', 1],
        ['M', 1],
        ['N', 1],
        ['O', 1],
        ['P', 1],
        ['Q', 1],
        ['R', 1],
        ['S', 1],
        ['T', 1],
        ['U', 1],
        ['V', 1],
        ['W', 1],
        ['X', 1],
        ['Y', 1],
        ['Z', 1],
        ['a', 1],
        ['b', 1],
        ['c', 1],
        ['d', 1],
        ['e', 1],
        ['f', 1],
        ['g', 1],
        ['h', 1],
        ['i', 1],
        ['j', 1],
        ['k', 1],
        ['l', 1],
        ['m', 1],
        ['n', 1],
        ['o', 1],
        ['p', 1],
        ['q', 1],
        ['r', 1],
        ['s', 1],
        ['t', 1],
        ['u', 1],
        ['v', 1],
        ['w', 1],
        ['x', 1],
        ['y', 1],
        ['z', 1],
        ['0', 2],
        ['1', 4],
        ['2', 4],
        ['3', 4],
        ['4', 2],
        ['5', 2],
        ['6', 2],
        ['7', 4],
        ['8', 4],
        ['9', 4],
    ]);

    private _code: string = '';
    private _size: number = -1;
    private _raw: Uint8Array = new Uint8Array(0);

    constructor({
        raw,
        code = MtrDex.Ed25519N,
        qb64b,
        qb64,
        qb2,
        rize,
    }: MatterArgs) {
        let size = -1;
        if (raw != undefined) {
            if (code.length == 0) {
                throw new Error(
                    'Improper initialization need either (raw and code) or qb64b or qb64 or qb2.'
                );
            }

            if (SmallVrzDex.has(code[0]) || LargeVrzDex.has(code[0])) {
                if (rize !== undefined) {
                    if (rize < 0)
                        throw new Error(
                            `missing var raw size for code=${code}`
                        );
                } else {
                    rize = raw.length;
                }

                const ls = (3 - (rize % 3)) % 3; // calc actual lead (pad) size
                size = Math.floor((rize + ls) / 3); // calculate value of size in triplets
                if (SmallVrzDex.has(code[0])) {
                    if (size <= 64 ** 2 - 1) {
                        const hs = 2;
                        const s = Object.values(SmallVrzDex)[ls];
                        code = `${s}${code.substring(1, hs)}`;
                    } else if (size <= 64 ** 4 - 1) {
                        const hs = 4;
                        const s = Object.values(LargeVrzDex)[ls];
                        code = `${s}${'AAAA'.substring(0, hs - 2)}${code[1]}`;
                    } else {
                        throw new Error(
                            `Unsupported raw size for code=${code}`
                        );
                    }
                } else {
                    if (size <= 64 ** 4 - 1) {
                        const hs = 4;
                        const s = Object.values(LargeVrzDex)[ls];
                        code = `${s}${code.substring(1, hs)}`;
                    } else {
                        throw new Error(
                            `Unsupported raw size for code=${code}`
                        );
                    }
                }
            } else {
                const sizage = Matter.Sizes.get(code);
                if (sizage!.fs === undefined) {
                    // invalid
                    throw new Error(`Unsupported variable size code=${code}`);
                }

                rize = Matter._rawSize(code);
            }
            raw = raw.slice(0, rize); // copy only exact size from raw stream
            if (raw.length != rize) {
                // forbids shorter
                throw new Error(
                    `Not enougth raw bytes for code=${code} expected ${rize} got ${raw.length}.`
                );
            }

            this._code = code; // hard value part of code
            this._size = size; // soft value part of code in int
            this._raw = raw; // crypto ops require bytes not bytearray
        } else if (qb64 !== undefined) {
            this._exfil(qb64);
        } else if (qb64b !== undefined) {
            const qb64 = d(qb64b);
            this._exfil(qb64);
        } else if (qb2 !== undefined) {
            this._bexfil(qb2);
        } else {
            throw new EmptyMaterialError('EmptyMaterialError');
        }
    }

    get code(): string {
        return this._code;
    }

    get size() {
        return this._size;
    }

    get raw(): Uint8Array {
        return this._raw;
    }

    get qb64() {
        return this._infil();
    }

    get qb64b() {
        return b(this.qb64);
    }

    get transferable(): boolean {
        return !NonTransDex.has(this.code);
    }

    get digestive(): boolean {
        return DigiDex.has(this.code);
    }

    static _rawSize(code: string) {
        const sizage = this.Sizes.get(code); // get sizes
        const cs = sizage!.hs + sizage!.ss; // both hard + soft code size
        if (sizage!.fs === undefined) {
            throw Error(`Non-fixed raw size code ${code}.`);
        }

        return Math.floor(((sizage!.fs! - cs) * 3) / 4) - sizage!.ls!;
    }

    static _leadSize(code: string) {
        const sizage = this.Sizes.get(code);
        return sizage!.ls;
    }

    get both() {
        const sizage = Matter.Sizes.get(this.code);
        return `${this.code}${intToB64(this.size, sizage!.ss)}`;
    }

    private _infil() {
        const code = this.code;
        const both = this.both;
        const size = this.size;
        const raw = this.raw;
        const rawSize = raw.length;
        const sizage = Matter.Sizes.get(code);
        const hardSoftSize = sizage!.hs + sizage!.ss;
        const leadSize = sizage!.ls!;
        // Matter.Sizes tests are expected to ensure valid code table entries.

        if (sizage!.fs === undefined) {
            // Variable-size entries can fix the lead size and code alignment,
            // but not the raw size. At runtime, lead + raw must be 24-bit
            // aligned so the qualified Base64 has no trailing pad chars.
            if ((leadSize + rawSize) % 3 || hardSoftSize % 4) {
                throw new Error(
                    `Invalid full code=${both} with variable raw size=${rawSize}.`
                );
            }
            if (size < 0 || size > 64 ** sizage!.ss - 1) {
                throw new Error(`Invalid size=${size} for code=${code}.`);
            }

            // With lead + raw aligned, encode lead zero bytes plus raw directly.
            // The lead bytes are not material; they preserve CESR alignment.
            const lead = new Uint8Array(leadSize);
            const full = both + encodeBase64Url(concat(lead, raw));

            if (full.length % 4) {
                throw new Error(
                    `Invalid full size given code=${both} with raw size=${rawSize}.`
                );
            }
            return full;
        } else {
            // For fixed-size codes, the net prepad must equal the code-size
            // remainder so code + converted padded raw has the declared size.
            const prepadSize = (3 - ((rawSize + leadSize) % 3)) % 3;
            if (prepadSize !== hardSoftSize % 4) {
                throw new Error(
                    `Invalid full code=${both} with fixed raw size=${rawSize}.`
                );
            }

            // Prepad raw so the full primitive is midpadded: encode
            // prepad + lead + raw, then skip the prepad chars after conversion.
            // This keeps the primitive fullSize while requiring zero midpad bits.
            const lead = new Uint8Array(prepadSize + leadSize);
            const full =
                both + encodeBase64Url(concat(lead, raw)).slice(prepadSize);

            if (full.length % 4 || full.length !== sizage!.fs) {
                throw new Error(
                    `Invalid full size given code=${both} with raw size=${rawSize}.`
                );
            }
            return full;
        }
    }

    private _exfil(qb64: string) {
        if (qb64.length == 0) {
            throw new Error('Empty Material');
        }

        const first = qb64[0];
        if (!Array.from(Matter.Hards.keys()).includes(first)) {
            throw new Error(`Unexpected code ${first}`);
        }

        const hs = Matter.Hards.get(first);
        if (qb64.length < hs!) {
            throw new Error(`Shortage Error`);
        }

        const hard = qb64.slice(0, hs);
        if (!Array.from(Matter.Sizes.keys()).includes(hard)) {
            throw new Error(`Unsupported code ${hard}`);
        }

        const sizage = Matter.Sizes.get(hard);
        const cs = sizage!.hs + sizage!.ss;
        // Matter.Sizes and Matter.Hards tests are expected to keep these
        // entries well formed. Variable codes use soft chars for size.
        let size = -1;
        let fullSize: number;
        if (sizage!.fs === undefined) {
            const soft = qb64.slice(sizage!.hs, cs);
            // The soft part stores the variable material size in Base64 triplets.
            size = b64ToInt(soft);
            fullSize = cs + size * 4;
        } else {
            size = sizage!.fs!;
            fullSize = sizage!.fs!;
        }

        if (qb64.length < fullSize) {
            throw new Error(`Need ${fullSize - qb64.length} more chars.`);
        }

        qb64 = qb64.slice(0, fullSize);
        // Check for non-zeroed pad bits and/or lead bytes. The net prepad is
        // cs % 4 and is limited by table invariants to 0, 1, or 2 bytes.
        const prepadSize = cs % 4;
        // Prepending prepad 'A' chars reverses _infil's midpad slicing and
        // lets decode recover prepad + lead + raw bytes for validation.
        const base = new Array(prepadSize + 1).join('A') + qb64.slice(cs);
        const paw = Uint8Array.from(decodeBase64Url(base));
        const leadSize = prepadSize + sizage!.ls!;
        // All recovered prepad and lead bytes must be zero before stripping.
        const pi = readInt(paw.subarray(0, leadSize));
        if (pi != 0) {
            throw new Error(`Nonzero midpad bytes = 0x${pi.toString(16)}`);
        }
        const raw = paw.subarray(leadSize);
        const rawSize = Math.floor(((qb64.length - cs) * 3) / 4) - sizage!.ls!;
        if (raw.length !== rawSize) {
            throw new Error(`Improperly qualified material = ${qb64}`);
        }

        this._code = hard; // hard only
        this._size = size;
        this._raw = Uint8Array.from(raw); // ensure bytes so immutable and for crypto ops
    }

    private _bexfil(qb2: Uint8Array) {
        throw new Error(`qb2 not yet supported: ${qb2}`);
    }
}
