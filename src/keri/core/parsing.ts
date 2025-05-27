import { Serder } from "./serder";
import { d, deversify } from "./core";
import { Siger } from "./siger";
import { Cigar } from "./cigar";
import { Counter, CtrDex_1_0 } from "./counter";
import { Indexer } from "./indexer";
import { Matter } from "./matter";

/**
 * Cold start stream tritet codex.
 *
 * List of types (codex) of cold stream start tritets - the first three bits of the first byte of the stream.
 * The values are in octal notation.
 *
 * Reference: ToIP CESR spec section 10.5.1 "Performant resynchronization with unique start bits"
 * https://trustoverip.github.io/tswg-cesr-specification/#performant-resynchronization-with-unique-start-bits
 *
 * @type {{Free: number, CtB64: number, OpB64: number, JSON: number, MGPK1: number, CBOR: number, MGPK2: number, CtOpB2: number}}
 */
let ColdDex = {
    /**
     * Not taken, yet planned for annotated CESR
     * Binary 000, full binary value 00000000
     */
    Free: 0o0,
    /**
     * CountCode Base64URLSafe starting character ('-') tritet, position 62 or 0x3E.
     * Tritet bits 001, full binary 00101101, hex 0x2D
     * Tritet is first three bits of the '-' character, ASCII/UTF-8 45.
     */
    CtB64: 0o1,
    /**
     * OpCode Base64URLSafe starting character ('_'), position 63 or 0x3F.
     * Tritet bits 010, full binary 01011111, hex 0x5F
     * Tritet is first three bits of the '_' character, ASCII/UTF-8 character 95.
     */
    OpB64: 0o2,
    /**
     * JSON Map starting character ('{') tritet.
     * Tritet bits 011, full binary value 01111011, hex 0x7B
     * Tritet is first three bits of the '{' character, ASCII/UTF-8 character 123.
     */
    JSON: 0o3,
    /**
     * MessagePack Fixed Map Event Start tritet
     * Binary 100, full binary ?
     */
    MGPK1: 0o4,
    /**
     * CBOR Map Event Start
     * Binary 101, full binary ?
     */
    CBOR: 0o5,
    /**
     * MessagePack Big 16 or 32 Map Event Start
     * Binary 110, full binary ?
     */
    MGPK2: 0o6,
    /**
     * Base2 (binary) CountCode or OpCode starting character tritet
     * Binary 111, full binary ?
     */
    CtOpB2: 0o7,
}

/**
 * Stream cold start status
 */
export enum Cold {
    msg = 'msg',
    txt = 'txt',
    bny = 'bny',
}

export enum BodyType {
    S='S',
    KERI= 'KERI',
    ACDC= 'ACDC'
}

/**
 * The main body of a CESR message that is either a KERI or ACDC event. Attachments come after.
 */
export class CESRBody {
    private _bytes: Buffer; // raw bytes that will compose Serder
    private _bodyType: BodyType; // Whether SerderKERI or SerderACDC; all Serder for now

    constructor (bytes: Buffer, bodyType: BodyType = BodyType.S) {
        this._bytes = bytes;
        this._bodyType = bodyType;
    }
    get bodyType() {
        return this._bodyType;
    }
    get bytes() {
        return this._bytes;
    }
    get size() {
        return this._bytes.length;
    }
}

/**
 * The various cryptographic primitives that can be included in a CESR message.
 */
export enum PrimType {
    Bexter,
    Cigar,
    Cipher,
    Counter,
    Dater,
    Decrypter,
    Diger,
    Encrypter,
    Number,
    Pather, // if the Pather is in a CESRAtcGroup and
    PathedMaterialQuadlets,
    Prefixer,
    Saider,
    Salter,
    Seqner,
    Signer,
    Siger,
    Verfer,
}

export class CESRPrim {
    private _bytes: Buffer;
    private _primitive: PrimType;
    constructor(bytes: Buffer, primitive: PrimType) {
        this._bytes = bytes;
        this._primitive = primitive;
    }
    get bytes() {
        return this._bytes;
    }
    get primitive() {
        return this._primitive;
    }
}

/**
 * Union type for a CESR Tuple that allows single items, arrays of items, or a group.
 */
declare type CESRTupleType = (CESRPrim | CESRPrim[] | CESRTuple | CESRTuple[] | CESRAtcGroup)

export class CESRTuple {
    private _items: CESRTupleType[] = []
    constructor(tuple: CESRTupleType[]) {
        this._items = tuple;
    }
    get items() {
        return this._items;
    }
}

/**
 * A single CESR attachment corresponding to one cryptographic primitive.
 */
export class CESRAtcGroup {
    private _code: string; // derivation code
    private _counter: CESRPrim;
    private _path?: CESRPrim; // path for pathed groups
    private _items: CESRPrim[] | CESRTuple[] = []; // list or tuple of cryptographic primitives
    /**
     *
     * @param code
     * @param items Primitives that are part of this group
     * @param counter Count code for this group
     * @param path Pather primitive for groups that have paths
     */
    constructor(
      code: string,
      items: CESRPrim[] | CESRTuple[],
      counter: CESRPrim,
      path?: CESRPrim
    ) {
        this._code = code;
        this._counter = counter;
        this._items = items;
        this._path = path;
    }
    get code() {
        return this._code;
    }
    get counter() {
        return this._counter;
    }
    get items() {
        return this._items;
    }
    get path() {
        return this._path;
    }
}

/**
 * An ordered sequence of CESR attachments that comes after a CESRBody.
 */
export class CESRAttachments {
    private _groups: CESRAtcGroup[];

    /**
     * A CESR attachment stream is a list of CESR groups and their cryptographic primitives.
     * @param atcGroup
     */
    constructor(atcGroup: CESRAtcGroup[]) {
        this._groups = atcGroup;
    }

    /**
     * Groups of attachments. Each group has a count code and a list of cryptographic primitives
     */
    get groups() {
        return this._groups;
    }

    /**
     * Adds an attachment group to the list of groups.
     * @param atcGroup
     */
    add(atcGroup: CESRAtcGroup) {
        this._groups.push(atcGroup);
    }
}

/**
 * A complete CESR message that includes a body and attachments.
 */
export class CESRMessage {
    private _body: CESRBody;
    private _attachments: CESRAttachments;

    constructor(body: CESRBody, attachments: CESRAttachments) {
        this._body = body;
        this._attachments = attachments;
    }

    get body() {
        return this._body;
    }

    get atc() {
        return this._attachments;
    }
}

/**
 * CESR stream primitive parser. Turns a stream of bytes into a collection of CESRMessage objects.
 * These objects can then be converted into cryptographic primitives with Hydrator.
 */
export class Parser {
    constructor() {}

    *msgParsator(
        ims: Buffer,
        framed = false,
        pipeline = false
    ): Generator<CESRMessage | null, void, unknown> {
        if (ims.length === 0) return;
        let cold = this.sniff(ims);
        if ([Cold.txt, Cold.bny].includes(cold)) {
            throw new Error(`Cold start error: expecting message counter tritet, got ${cold}`)
        }
        while (true) {
            if (ims.length === 0) return;
            const body = this.reap(ims);
            ims = ims.subarray(body.size);
            const sigers: Siger[] = []; // attached indexed controller signatures
            const wigers: Siger[] = []; // attached indexed witness signatures
            const cigars: Cigar[] = []; // non-transferable receipt couples
            const trqs: any = []; // transferable receipt (vrc) quadruples - (prefixer, seqner, diger, siger)
            const tsgs: any = []; // transferable indexed sig groups - (i, s, d) plus list of sigs
            const ssgs: any = []; // signer seal sig groups - identifier prefix plus list of sigs
            const frcs: any = []; // first seen replay couples - (seqner, dater)
            const sscs: any = []; // source seal couples (delegator or issuer) - (seqner, diger) for delegating or issuing event
            const ssts: any = []; // source seal triples (issuer or issuance TEL evt) - (seqner, diger) for delegating or issuing event
            const sadtsgs: any = []; // SAD path sig groups from transferable identifiers - (path, i, s, d) plus list of sigs
            const sadcigs: any = []; // SAD path sig groups from non-transferable identifiers - path plus list of non-trans sigs
            const pathed: any = []; // grouped attachments targetting a subpath
            let pipelined: boolean = false;

            cold = this.sniff(ims);
            if (cold === Cold.msg) {
                throw new Error(`Cold start error: expecting attachment or binary counter tritet, got ${cold}`)
            }
            // TODO support qb2 for binary attachments - rig ht now only qb64b
            let ctr: Counter;
            if (cold === Cold.txt) ctr = new Counter({qb64b: ims});
            else if (cold === Cold.bny) ctr = new Counter({qb2: ims});
            else throw new Error(`Attachment cold start error: expecting text or binary counter, got ${cold}`)
            ims = ims.subarray(Counter.Sizes.get(ctr.code)!.fs!);

            // strip off initial attachment count code
            if (ctr.code === CtrDex_1_0.AttachedMaterialQuadlets) { // pipeline ctr?
                pipelined = true
                // compute pipelined attached group size (pags) based on txt or bny
                const pags = cold === Cold.txt ? ctr.count * 4 : ctr.count * 3
                if (ims.length < pags) throw new Error(`Insufficient bytes to parse pipelined attachments.`)

                // pipelined attachments
                const pims = ims.subarray(0, pags)
                ims = ims.subarray(pags);
                if (pipelined) {
                    // TODO parse pipelined attachments
                    return
                }
                ctr = new Counter({qb64b: ims});
            }

            // process attachments
            const attachments = new CESRAttachments([]);
            let group: CESRAtcGroup;
            switch (ctr.code) {
                case CtrDex_1_0.ControllerIdxSigs:
                    [ims, group] = AtcParser.ControllerIdxSigs(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.WitnessIdxSigs:
                    [ims, group] = AtcParser.WitnessIdxSigs(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.NonTransReceiptCouples:
                    [ims, group] = AtcParser.NonTransReceiptCouples(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.TransReceiptQuadruples:
                    [ims, group] = AtcParser.TransReceiptQuadruples(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.TransIdxSigGroups:
                    [ims, group] = AtcParser.TransIdxSigGroups(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.TransLastIdxSigGroups:
                    [ims, group] = AtcParser.TransLastIdxSigGroups(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.FirstSeenReplayCouples:
                    [ims, group] = AtcParser.FirstSeenReplayCouples(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.SealSourceCouples:
                    [ims, group] = AtcParser.SealSourceCouples(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.SealSourceTriples:
                    [ims, group] = AtcParser.SealSourceTriples(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.RootSadPathSigGroups:
                    [ims, group] = AtcParser.SadPathSigGroup(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.SadPathSigGroup:
                    [ims, group] = AtcParser.SadPathSig(ims, ctr);
                    attachments.add(group);
                    break;
                case CtrDex_1_0.PathedMaterialGroup:
                    [ims, group] = AtcParser.PathedMaterialQuadlets(ims, ctr, cold);
                    attachments.add(group);
                    break;
                default:
                    throw new Error(`Unknown attachment counter code ${ctr.code}`)
            }

            yield new CESRMessage(body, attachments);
        }
    }

    packGroup(group: CESRAtcGroup): Buffer {
        // TODO handle pathed groups
        let stream = Buffer.from([]);
        stream = Buffer.concat([stream, group.counter.bytes]);

        for (const item of group.items) {
            if (item instanceof CESRPrim) {
                stream = Buffer.concat([stream, item.bytes]);
            }
            else if (item instanceof CESRTuple) {
                stream = Buffer.concat([stream, this.packTuple(item)]);
            }
        }
        return stream;
    }

    packTuple(tuple: CESRTuple): Buffer  {
        let stream = Buffer.from([]);
        const items: CESRTupleType[] = tuple.items;
        if (items.length === 0) return stream;
        if (items.length === 1 && items[0] instanceof CESRPrim) {
            return Buffer.concat([stream, items[0].bytes]);
        }
        for (const item of items) {
            if (item instanceof CESRPrim) {
                stream = Buffer.concat([stream, item.bytes]);
            } else if (item instanceof CESRTuple) {
                stream = Buffer.concat([stream, this.packTuple(item)]);
            } else if (Array.isArray(item)) { // CESRPrim[] or CESRTuple[]
                for(const subItem of item) {
                    if (subItem instanceof CESRPrim) {
                        stream = Buffer.concat([stream, subItem.bytes]);
                    }
                    else if (subItem instanceof CESRTuple) {
                        stream = Buffer.concat([stream, this.packTuple(subItem)]);
                    }
                    else {
                        throw new Error(`Parsing Error: Unknown item type ${typeof subItem}`)
                    }
                }
            }
            else if (item instanceof CESRAtcGroup) {
                stream = Buffer.concat([stream, this.packGroup(item)]);
            }
            else {
                throw new Error(`Parsing Error: Unknown item type ${typeof item}`)
            }
        }
        return stream;
    }

    pack(msg: CESRMessage): Buffer {
        // TODO handle pathed group
        let stream = Buffer.from([]);
        stream = Buffer.concat([stream, msg.body.bytes]); // body
        for (const group of msg.atc.groups) { // attachments
            stream = Buffer.concat([stream, group.counter.bytes])
            for (const item of group.items) {
                if (item instanceof CESRPrim) {
                    stream = Buffer.concat([stream, item.bytes])
                }
                else if (item instanceof CESRTuple) {
                    stream = Buffer.concat([stream, this.packTuple(item)]);
                }
            }
        }
        return stream;
    }

    sniff(ims: Buffer): Cold {
        if (ims.length === 0) throw new Error('Empty stream');
        const tritet = ims[0] >> 5;
        if ([ColdDex.JSON, ColdDex. MGPK1, ColdDex.CBOR, ColdDex.MGPK2].includes(tritet)) {
            return Cold.msg;
        }
        if ([ColdDex.CtB64, ColdDex.OpB64].includes(tritet)) {
            return Cold.txt;
        }
        if ([ColdDex.CtOpB2].includes(tritet)) {
            return Cold.bny;
        }
        throw new Error(`Unknown cold start tritet ${tritet}`);
    }

    reap(ims: Buffer): CESRBody {
        if (ims.length < Serder.InhaleSize) {
            throw new Error(`Insufficient bytes to parse message.`);
        }
        const [proto, kind, version, size] = deversify(d(ims.subarray(0, Serder.InhaleSize)));
        // TODO add CESR 2 version string compatibility
        let sizeNum = parseInt(size, 16); // assumes CESR v1 so size is hex str
        return new CESRBody(ims.subarray(0, sizeNum));
    }

}

/**
 * Parses the various types of attachments that can be included with a CESR message.
 * All functions take the incoming stream and strip the existing attachment from the returned stream.
 */
class AtcParser {
    static ControllerIdxSigs(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const items: CESRPrim[] = [];
        for (let i = 0; i < ctr.count; i++) {
            const size = Indexer.sniffSize(ims);
            // extract the controller signature
            const siger = new CESRPrim(ims.subarray(0, size), PrimType.Siger)
            ims = ims.subarray(size);

            items.push(siger);
        }
        const group = new CESRAtcGroup(ctr.code, items,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    static WitnessIdxSigs(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const items: CESRPrim[] = [];
        for (let i = 0; i < ctr.count; i++) {
            const size = Indexer.sniffSize(ims);
            // extract the witness signature
            const siger = new CESRPrim(ims.subarray(0, size), PrimType.Siger)
            ims = ims.subarray(size);

            items.push(siger);
        }
        const group =new CESRAtcGroup(ctr.code, items,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    static NonTransReceiptCouples(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            // extract the couple (verfer, cigar)
            let size = Matter.sniffSize(ims);
            const verfer = new CESRPrim(ims.subarray(0, size), PrimType.Verfer)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const cigar = new CESRPrim(ims.subarray(0, size), PrimType.Cigar)
            ims = ims.subarray(size);

            tuples.push(new CESRTuple([verfer, cigar]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    /**
     * Extract attached trans receipt vrc quadruple
     * spre+ssnu+sdig+sig
     * @param ims
     * @param ctr
     * @constructor
     */
    static TransReceiptQuadruples(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const prefixer = new CESRPrim(ims.subarray(0, size), PrimType.Prefixer)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const seqner = new CESRPrim(ims.subarray(0, size), PrimType.Seqner)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const saider = new CESRPrim(ims.subarray(0, size), PrimType.Saider)
            ims = ims.subarray(size);

            size = Indexer.sniffSize(ims);
            const siger = new CESRPrim(ims.subarray(0, size), PrimType.Siger)
            ims = ims.subarray(size);

            tuples.push(new CESRTuple([prefixer, seqner, saider, siger]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
            new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    /**
     * Extract attaced trans indexed sig groups each made of
     * triple pre+snu+dig plus indexed sig group
     * pre is pre of signer (endorser) of msg
     * snu is sn of signer's est evt when signed
     * dig is dig of signer's est event when signed
     * followed by counter for ControllerIdxSigs with attached
     * indexed sigs from trans signer (endorser).
     * @param ims
     * @param ctr
     * @constructor
     */
    static TransIdxSigGroups(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const prefixer = new CESRPrim(ims.subarray(0, size), PrimType.Prefixer)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const seqner = new CESRPrim(ims.subarray(0, size), PrimType.Seqner)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const saider = new CESRPrim(ims.subarray(0, size), PrimType.Saider)
            ims = ims.subarray(size);

            const sigers: CESRPrim[] = [];
            const sigCtr = new Counter({qb64b: ims});
            if (sigCtr.code !== CtrDex_1_0.ControllerIdxSigs) throw new Error(`Invalid group code. Expected ControllerIdxSigs (${CtrDex_1_0.ControllerIdxSigs}) got ${sigCtr.code}`);
            ims = ims.subarray(Counter.Sizes.get(sigCtr.code)!.fs!);
            for (let j = 0; j < sigCtr.count; j++) {
                size = Indexer.sniffSize(ims);
                const siger = new CESRPrim(ims.subarray(0, size), PrimType.Siger)
                sigers.push(siger);
                ims = ims.subarray(size);
            }
            // child group
            const sigGroup = new CESRAtcGroup(
                sigCtr.code,
                sigers,
                new CESRPrim(Buffer.from(sigCtr.qb64b), PrimType.Counter)
            );
            tuples.push(new CESRTuple([prefixer, seqner, saider, sigGroup]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
            new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    /**
     * Extract attached signer seal indexed sig groups each made of
     * identifier pre plus indexed sig group
     * pre is pre of signer (endorser) of msg
     * followed by counter for ControllerIdxSigs with attached
     * indexed sigs from trans signer (endorser).
     * @param ims
     * @param ctr
     * @constructor
     */
    static TransLastIdxSigGroups(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const prefixer = new CESRPrim(ims.subarray(0, size), PrimType.Prefixer)
            ims = ims.subarray(size);

            const sigers: CESRPrim[] = [];
            const sigCtr = new Counter({qb64b: ims});
            if (sigCtr.code !== CtrDex_1_0.ControllerIdxSigs) throw new Error(`Invalid group code. Expected ControllerIdxSigs (${CtrDex_1_0.ControllerIdxSigs}) got ${sigCtr.code}`);
            ims = ims.subarray(Counter.Sizes.get(sigCtr.code)!.fs!);
            for (let j = 0; j < sigCtr.count; j++) {
                size = Indexer.sniffSize(ims);
                const siger = new CESRPrim(ims.subarray(0, size), PrimType.Siger)
                sigers.push(siger);
                ims = ims.subarray(size);
            }
            const sigGroup = new CESRAtcGroup(sigCtr.code, sigers,
                new CESRPrim(Buffer.from(sigCtr.qb64b), PrimType.Counter)
            );
            tuples.push(new CESRTuple([prefixer, sigGroup]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter))
        return [ims, group]
    }

    /**
     * Extract attached first seen replay couples
     * snu+dtm
     * snu is fn (first seen ordinal) of event
     * dtm is dt of event
     * @param ims
     * @param ctr
     * @constructor
     */
    static FirstSeenReplayCouples(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const seqner = new CESRPrim(ims.subarray(0, size), PrimType.Seqner)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const dater = new CESRPrim(ims.subarray(0, size), PrimType.Dater)
            ims = ims.subarray(size);

            tuples.push(new CESRTuple([seqner, dater]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
            new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group]
    }

    /**
     * Extract attached first seen replay couples
     * snu+dig
     * snu is sequence number  of event
     * dig is digest of event
     * @param ims
     * @param ctr
     * @constructor
     */
    static SealSourceCouples(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const seqner = new CESRPrim(ims.subarray(0, size), PrimType.Seqner)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const saider = new CESRPrim(ims.subarray(0, size), PrimType.Saider)
            ims = ims.subarray(size);

            tuples.push(new CESRTuple([seqner, saider]));
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group]
    }

    /**
     * Extract attached anchoring source event information
     * pre+snu+dig
     * pre is prefix of event
     * snu is sequence number  of event
     * dig is digest of event
     * @param ims
     * @param ctr
     * @constructor
     */
    static SealSourceTriples(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        const tuples: CESRTuple[] = [];
        for (let i = 0; i < ctr.count; i++) {
            let size = Matter.sniffSize(ims);
            const prefixer = new CESRPrim(ims.subarray(0, size), PrimType.Prefixer)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const seqner = new CESRPrim(ims.subarray(0, size), PrimType.Seqner)
            ims = ims.subarray(size);

            size = Matter.sniffSize(ims);
            const saider = new CESRPrim(ims.subarray(0, size), PrimType.Saider)
            ims = ims.subarray(size);

            tuples.push(
                new CESRTuple([prefixer, seqner, saider])
            );
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group]
    }

    /**
     * Extract attached SAD path sig groups each made of a top level Pather, a counter for SadPathSig groups,
     * and then within each sad path group a Pather and another count code which may count groups of either
     * TransIdxSigGroups, ControllerIdxSigs, or NonTransReceiptCouples.
     * @param ims
     * @param ctr count of SAD path sig groups
     * @constructor
     */
    static SadPathSigGroup(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        let tuples: CESRTuple[] = [];
        // get Pather
        const size = Matter.sniffSize(ims);
        const rootPath = new CESRPrim(ims.subarray(0, size), PrimType.Pather);
        ims = ims.subarray(size);

        // get nested groups
        for (let i = 0; i < ctr.count; i++) {
            // get Counter of subgroups of a specific type
            const sigGroupCtr = new Counter({qb64b: ims});
            ims = ims.subarray(Counter.Sizes.get(sigGroupCtr.code)!.fs!);

            [ims, tuples] = AtcParser._sadPathSigGroup(ims, sigGroupCtr);
        }
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter),
          rootPath);
        return [ims, group]
    }

    /**
     * Extract SAD path sig groups
     * @param ims incoming message stream
     * @param ctr count of subgroups within this sig group
     */
    static _sadPathSigGroup(ims: Buffer, ctr: Counter): [Buffer, CESRTuple[]] {
      if (ctr.code !== CtrDex_1_0.SadPathSigGroup)
          throw new Error(`Expected SadPathSig counter, got ${ctr.code}`);

      // get subpath
      const size = Matter.sniffSize(ims);
      const subpath = new CESRPrim(ims.subarray(0, size), PrimType.Pather);
      ims = ims.subarray(size);

      // get sig group counter
      const sctr = new Counter({qb64b: ims});
      ims = ims.subarray(Counter.Sizes.get(sctr.code)!.fs!);

      // pull items from each group and return an array of tuples
      let group: CESRAtcGroup;
      const tuples: CESRTuple[] = [];
      let tuple: CESRTuple;
      switch (sctr.code) {
          case CtrDex_1_0.TransIdxSigGroups:
              [ims, group] = AtcParser.TransIdxSigGroups(ims, sctr);
              // TODO add each inner group to the outer group, maybe return a CESRGroup
              group.items.forEach((gTuple) => {
                  // todo do type check of gTuple to ensure it is a CESRTuple
                  // tuple = sctr.code, (subpath, prefixer, seqner, saider, isigers)
                  tuple = new CESRTuple([
                    new CESRPrim(Buffer.from(sctr.qb64b), PrimType.Counter),
                    new CESRTuple([subpath, ...((gTuple as CESRTuple).items)])
                  ]);
                  tuples.push(tuple)
              });
              break;
          case CtrDex_1_0.ControllerIdxSigs:
              [ims, group] = AtcParser.ControllerIdxSigs(ims, sctr);
              // tuple = sctr.code, (subpath, isigers)
              tuple = new CESRTuple([
                  new CESRPrim(Buffer.from(sctr.qb64b), PrimType.Counter),
                  new CESRTuple([subpath, group.items])
              ])
              tuples.push(tuple)
              break;
          case CtrDex_1_0.NonTransReceiptCouples:
              [ims, group] = AtcParser.NonTransReceiptCouples(ims, sctr);
              group.items.forEach((gTuple) => {
                // tuple = sctr.code, (subpath, cigar)
                // in this case it is sctr.code, (subpath, verfer, cigar) because the two are not yet combined
                // TODO note for parsing: remember to combine the verfer to cigar.verfer
                tuple = new CESRTuple([
                    new CESRPrim(Buffer.from(sctr.qb64b), PrimType.Counter),
                    new CESRTuple([subpath, ...((gTuple as CESRTuple).items)])
                ])
                tuples.push(tuple);
              });
              break;
          default:
              throw new Error(`Wrong count code = ${sctr.code} in SAD path sig group`)
      }
      return [ims, tuples];
    }

    static SadPathSig(ims: Buffer, ctr: Counter): [Buffer, CESRAtcGroup] {
        let tuples: CESRTuple[] = [];
        [ims, tuples] = AtcParser._sadPathSigGroup(ims, ctr);
        const group = new CESRAtcGroup(ctr.code, tuples,
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }

    static PathedMaterialQuadlets(ims: Buffer, ctr: Counter, cold: Cold): [Buffer, CESRAtcGroup] {
        // compute pipelined attached group size based on txt or bny
        const pags = cold === Cold.txt ? ctr.count  * 4 : ctr.count * 3;
        if (ims.length < pags)
            throw new Error(`Not enough bytes to parse pathed material quadlets. Got ${ims.length} need ${pags}`);
        const pims = ims.subarray(0, pags);
        ims = ims.subarray(pags);
        const prim = new CESRPrim(pims, PrimType.PathedMaterialQuadlets)

        const group = new CESRAtcGroup(ctr.code, [prim],
          new CESRPrim(Buffer.from(ctr.qb64b), PrimType.Counter));
        return [ims, group];
    }
}



class Hydrator {
    constructor() {

    }

    hydrate(cesrMessage: CESRMessage) {

    }
}
