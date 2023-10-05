import {Dict, Ident, Serials, Version, Versionage} from "./core";
import {Diger} from "./diger";
import {MtrDex} from "./matter";
import {sizeify} from "./serder";
import {Saider} from "./saider";

const VERFULLSIZE = 17  // number of characters in full version string
const MINSNIFFSIZE = 12 + VERFULLSIZE

const VEREX = /(?<proto>[A-Z]{4})(?<major>[0-9a-f])(?<minor>[0-9a-f])(?<kind>[A-Z]{4})(?<size>[0-9a-f]{6})_/;

/**
 * Returns serialization kind, version and size from serialized event raw by investigating leading
 * bytes that contain version string
 * @param raw
 */
export function sniff(raw: Uint8Array):
    {proto: Ident, kind: Serials, version: Version, size: number} {
    if (raw.length < MINSNIFFSIZE) {
        throw new Error("Need more bytes.")
    }

    const rawString = new TextDecoder().decode(raw);
    const match = VEREX.exec(rawString);

    if (!match || match.groups === undefined || match.index > 12) {
        throw new Error(`Invalid version string in raw ${rawString}`)
    }

    const proto = match.groups["proto"];
    const major = parseInt(match.groups["major"], 16);
    const minor = parseInt(match.groups["minor"], 16);
    const  kind = match.groups["kind"];
    const size = parseInt(match.groups["size"], 16);

    const version = new Version(major, minor)

    const serialValues: string[] = Object.values(Serials);
    if (!serialValues.includes(kind)) {
        throw new Error(`Invalid serialization kind: ${kind}`)
    }
    const serialization: Serials = Serials[kind as keyof typeof Serials]

    const protoValues: string[] = Object.values(Ident);
    if (!protoValues.includes(proto)) {
        throw new Error(`Invalid protocol type: ${proto}`)
    }
    const protocol: Ident = Ident[proto as keyof typeof Ident]
    return {proto: protocol, kind: serialization, version, size}
}

/**
 * utility function to handle deserialization by kind
 * @param raw
 * @param size
 * @param kind
 * @returns ked (object): deserialized
 */
function loads(raw: Uint8Array, size?: number, kind: Serials = Serials.JSON): any  {
    const rawData = raw.slice(0, size);
    let ked = {};
    switch (kind) {
        case Serials.JSON:
            try {
                ked = JSON.parse(new TextDecoder().decode(rawData));
                break;
            } catch (error) {
                throw new Error(`Error deserializing JSON: ${rawData}`)
            }
        default:
            throw new Error(`Invalid deserialization kind: ${kind}`);
    }
    return ked;
}

/**
 * Sadder is self addressed data (SAD) serializer-deserializer class
 *
 * Instance creation of a Sadder does not verifiy it .said property it merely extracts it.
 * In order to ensure Sadder instance has a verified .said then must call
 *   .saider.verify(sad=self.ked)
 *
 * Note:
 *   loads and jumps of json use str whereas cbor and msgpack use bytes
 */
export class Sadder {

    protected _raw?: Uint8Array;
    protected _ked?: Dict<any> = {};
    protected _kind: Serials = Serials.JSON;
    protected _size: number = 0;
    protected _version: Version = Versionage;
    protected _proto: Ident = Ident.KERI;
    protected _diger?: Diger;
    protected readonly _code: string;
    protected _saider?: Saider;

    constructor(raw?: Uint8Array, ked?: Dict<any>, sad?: Dict<any>, kind: Serials=Serials.JSON,
                code: string=MtrDex.Blake3_256) {
        this._code = code;
        if (raw) {
            this.raw = raw;
        } else if (ked) {
            this._kind = kind
            this.ked = ked
        } else if (sad) {
            this._clone(sad)
        } else {
            throw new Error("Improper initialization. Need raw, ked, or sad.")
        }
        this._kind = kind;
    }

    set raw(raw: Uint8Array) {
        let {ked, proto, kind, version, size} = this._inhale(raw)
        this._raw = raw.slice(0, size)
        this._ked = ked
        this._proto = proto
        this._kind = kind
        this._version = version
        this._size = size
        this._saider = new Saider({qb64: ked["d"]})
    }

    set ked(ked: Dict<any>) {
        let [raw, ident, kind, kd, version] = this._exhale(ked, this._kind)
        let size = raw.length
        this._raw = new TextEncoder().encode(raw)
        this._proto = ident
        this._ked = kd
        this._kind = kind
        this._size = size
        this._version = version
    }

    get raw(): Uint8Array {
        return this._raw || new Uint8Array();
    }

    get ked(): Dict<any> {
        return this._ked ? this._ked : {}
    }

    get saider(): Saider {
        const ked = this._ked ? this._ked : {}
        //@ts-ignore
        const [saider, sad] = Saider.saidify(ked)
        return saider
    }

    private _exhale(ked: Dict<any>, kind: Serials): [string, Ident, Serials, Dict<any>, Version] {
        return sizeify(ked, kind)
    }

    private _inhale(raw: Uint8Array) {
        let {proto, kind, version, size} = sniff(raw)
        if (version !== Versionage) {
            throw new Error(`Unsupported version ${version.major}.${version.minor}, 
            expected ${Versionage}`)
        }
        if(raw.length < size) {
            throw new Error("Need more bytes.");
        }
        const ked = loads(raw, size, kind)
        return {ked, proto, kind, version, size}
    }

    private _clone(sad: Dict<any>) {
        this._raw = sad.raw
        this._ked = sad.ked
        this._size = sad.size
        this._version = sad.version
        this._proto = sad.proto
        this._saider = sad.saider
    }

}

export class Creder extends Sadder {
    constructor(raw?: Uint8Array, ked?: Dict<any>, sad?: Dict<any>, kind: Serials=Serials.JSON,
                code: string=MtrDex.Blake3_256) {
        super(raw, ked, sad, kind, code)
        if (this._proto !== Ident.ACDC) {
            throw new Error(`Invalid protocol ${this._proto}, must be ${Ident.ACDC}`)
        }
    }
    static fromKed(ked: any): Creder {
        return new Creder(undefined, ked)
    }
}
