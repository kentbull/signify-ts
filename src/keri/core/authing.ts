import libsodium from 'libsodium-wrappers-sumo';
import { Signer } from './signer.ts';
import { Verfer } from './verfer.ts';
import {
    desiginput,
    HEADER_SIG,
    HEADER_SIG_DESTINATION,
    HEADER_SIG_INPUT,
    HEADER_SIG_SENDER,
    HEADER_SIG_TIME,
    normalize,
    siginput,
} from './httping.ts';
import { Signage, signature, designature } from '../end/ending.ts';
import { Cigar } from './cigar.ts';
import { Siger } from './siger.ts';
import { Diger } from './diger.ts';
import { MtrDex } from './matter.ts';
import { b } from './core.ts';

const HTTP_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const RESPONSE_STATUS_LINE = /^HTTP\/1\.[01] ([0-9]{3})(?: (.*))?$/;
const HEADER_SEPARATOR = new Uint8Array([13, 10, 13, 10]);

function contentLengthEquals(value: string, length: number): boolean {
    return (
        /^\d+$/.test(value) &&
        value.replace(/^0+(?=\d)/, '') === length.toString()
    );
}

export abstract class Authenticator {
    protected verfer: Verfer;
    protected readonly csig: Signer;

    constructor(csig: Signer, verfer: Verfer) {
        this.csig = csig;
        this.verfer = verfer;
    }

    abstract prepare(
        request: Request,
        local: string,
        remote: string
    ): Promise<Request>;
    abstract verify(
        request: Request,
        response: Response,
        local: string,
        remote: string
    ): Promise<Response>;
}

export class SignedHeaderAuthenticator extends Authenticator {
    static DefaultFields = [
        '@method',
        '@path',
        'signify-resource',
        HEADER_SIG_TIME.toLowerCase(),
    ];

    async prepare(
        request: Request,
        _local: string,
        _remote: string
    ): Promise<Request> {
        const headers = request.headers;
        const signedHeaders = this.sign(
            request.headers,
            request.method,
            new URL(request.url).pathname
        );

        signedHeaders.forEach((value, key) => {
            headers.set(key, value);
        });

        return request;
    }

    async verify(
        request: Request,
        response: Response,
        _local: string,
        remote: string
    ): Promise<Response> {
        if (response.status === 401) {
            throw new Error(
                `HTTP ${request.method} ${new URL(request.url).pathname} - ${response.status} ${response.statusText}`
            );
        }

        if (remote !== response.headers.get(HEADER_SIG_SENDER)) {
            throw new Error('message from a different remote agent');
        }

        if (
            !this.verifyHeaders(
                response.headers,
                request.method,
                new URL(request.url).pathname
            )
        ) {
            throw new Error('response verification failed');
        }

        return response;
    }

    private verifyHeaders(
        headers: Headers,
        method: string,
        path: string
    ): boolean {
        const siginput = headers.get(HEADER_SIG_INPUT);
        if (siginput == null) {
            return false;
        }
        const signature = headers.get(HEADER_SIG);
        if (signature == null) {
            return false;
        }
        let inputs = desiginput(siginput);
        inputs = inputs.filter((input) => input.name == 'signify');
        if (inputs.length == 0) {
            return false;
        }
        inputs.forEach((input) => {
            const items = new Array<string>();
            input.fields!.forEach((field: string) => {
                if (field.startsWith('@')) {
                    if (field == '@method') {
                        items.push(`"${field}": ${method}`);
                    } else if (field == '@path') {
                        items.push(`"${field}": ${path}`);
                    }
                } else {
                    if (headers.has(field)) {
                        const value = normalize(headers.get(field) as string);
                        items.push(`"${field}": ${value}`);
                    }
                }
            });
            const values = new Array<string>();
            values.push(`(${input.fields!.join(' ')})`);
            values.push(`created=${input.created}`);
            if (input.expires != undefined) {
                values.push(`expires=${input.expires}`);
            }
            if (input.nonce != undefined) {
                values.push(`nonce=${input.nonce}`);
            }
            if (input.keyid != undefined) {
                values.push(`keyid=${input.keyid}`);
            }
            if (input.context != undefined) {
                values.push(`context=${input.context}`);
            }
            if (input.alg != undefined) {
                values.push(`alg=${input.alg}`);
            }
            const params = values.join(';');
            items.push(`"@signature-params: ${params}"`);
            const ser = items.join('\n');
            const signage = designature(signature!);
            const markers = signage[0].markers as Map<string, Siger | Cigar>;
            const cig = markers.get(input.name);
            if (!cig || !this.verfer.verify(cig.raw, ser)) {
                throw new Error(`Signature for ${input.keyid} invalid.`);
            }
        });

        return true;
    }

    private sign(headers: Headers, method: string, path: string): Headers {
        const [header, sig] = siginput(this.csig, {
            name: 'signify',
            method,
            path,
            headers,
            fields: SignedHeaderAuthenticator.DefaultFields,
            alg: 'ed25519',
            keyid: this.csig.verfer.qb64,
        });

        header.forEach((value, key) => {
            headers.append(key, value);
        });

        const markers = new Map<string, Siger | Cigar>();
        markers.set('signify', sig);
        const signage = new Signage(markers, false);
        const signed = signature([signage]);
        signed.forEach((value, key) => {
            headers.append(key, value);
        });

        return headers;
    }
}

export class EssrAuthenticator extends Authenticator {
    private readonly cx25519Pub: Uint8Array;
    private readonly cx25519Priv: Uint8Array;

    private readonly vx25519Pub: Uint8Array;

    constructor(csig: Signer, verfer: Verfer) {
        super(csig, verfer);
        const sigkey = new Uint8Array(
            this.csig.raw.length + this.csig.verfer.raw.length
        );
        sigkey.set(this.csig.raw);
        sigkey.set(this.csig.verfer.raw, this.csig.raw.length);
        this.cx25519Priv =
            libsodium.crypto_sign_ed25519_sk_to_curve25519(sigkey);
        this.cx25519Pub = libsodium.crypto_scalarmult_base(this.cx25519Priv);

        this.vx25519Pub = libsodium.crypto_sign_ed25519_pk_to_curve25519(
            this.verfer.raw
        );
    }

    async prepare(
        request: Request,
        local: string,
        remote: string
    ): Promise<Request> {
        const dt = new Date().toISOString().replace('Z', '000+00:00');

        const headers = new Headers();
        headers.set(HEADER_SIG_SENDER, local);
        headers.set(HEADER_SIG_DESTINATION, remote);
        headers.set(HEADER_SIG_TIME, dt);
        headers.set('Content-Type', 'application/octet-stream');

        const requestBytes = await EssrAuthenticator.serializeRequest(request);
        const raw = libsodium.crypto_box_seal(
            requestBytes,
            this.vx25519Pub
        ) as Uint8Array<ArrayBuffer>;

        const diger = new Diger({ code: MtrDex.Blake3_256 }, raw);
        const payload = {
            src: local,
            dest: remote,
            d: diger.qb64,
            dt,
        };

        const sig = this.csig.sign(b(JSON.stringify(payload)));
        const markers = new Map<string, Siger | Cigar>();
        markers.set('signify', sig);
        const signage = new Signage(markers, false);
        const signed = signature([signage]);

        signed.forEach((value, key) => {
            headers.append(key, value);
        });

        return new Request(new URL(request.url).origin + '/', {
            method: 'POST',
            body: raw,
            headers,
        });
    }

    async verify(
        request: Request,
        response: Response,
        local: string,
        remote: string
    ): Promise<Response> {
        if (response.status === 401) {
            throw new Error(
                `HTTP ${request.method} ${new URL(request.url).pathname} - ${response.status} ${response.statusText}`
            );
        }

        return await this.unwrap(response, remote, local, request.method);
    }

    /**
     * Serialize the finite request as KERIA's ESSR-specific HTTP envelope.
     *
     * The HTTP head is ASCII and the body is appended as exact bytes. This is
     * not a general HTTP serializer and deliberately rejects transfer coding.
     */
    static async serializeRequest(request: Request): Promise<Uint8Array> {
        const body =
            request.body === null
                ? new Uint8Array()
                : new Uint8Array(await request.arrayBuffer());
        const headers: string[] = [];
        let contentLength: string | null = null;

        request.headers.forEach((value, name) => {
            const lowerName = name.toLowerCase();
            if (lowerName === 'transfer-encoding') {
                throw new Error(
                    'Failed to serialize ESSR request - Transfer-Encoding is unsupported'
                );
            }
            if (lowerName === 'content-length') {
                contentLength = value;
                return;
            }
            headers.push(`${name}: ${value}`);
        });

        if (contentLength !== null) {
            if (!contentLengthEquals(contentLength, body.byteLength)) {
                throw new Error(
                    'Failed to serialize ESSR request - Content-Length does not match the body'
                );
            }
        }
        headers.push(`content-length: ${body.byteLength}`);

        const head = `${request.method} ${request.url} HTTP/1.1\r\n${headers.join('\r\n')}\r\n\r\n`;
        const headBytes = this.encodeAsciiHead(head, 'request');
        const serialized = new Uint8Array(
            headBytes.byteLength + body.byteLength
        );
        serialized.set(headBytes);
        serialized.set(body, headBytes.byteLength);
        return serialized;
    }

    private async unwrap(
        wrapper: Response,
        sender: string,
        receiver: string,
        requestMethod: string
    ): Promise<Response> {
        const signature = wrapper.headers.get(HEADER_SIG);
        if (!signature) {
            throw new Error('Signature is missing from ESSR payload');
        }

        if (wrapper.headers.get(HEADER_SIG_SENDER) !== sender) {
            throw new Error('Message from a different remote agent');
        }

        if (wrapper.headers.get(HEADER_SIG_DESTINATION) !== receiver) {
            throw new Error(
                'Invalid ESSR payload, missing or incorrect destination prefix'
            );
        }

        const dt = wrapper.headers.get(HEADER_SIG_TIME);
        if (!dt) {
            throw new Error('Timestamp is missing from ESSR payload');
        }

        const ciphertext = new Uint8Array(await wrapper.arrayBuffer());
        const diger = new Diger({ code: MtrDex.Blake3_256 }, ciphertext);

        const payload = {
            src: sender,
            dest: receiver,
            d: diger.qb64,
            dt,
        };

        const signages = designature(signature);
        const markers = signages[0].markers as Map<string, Siger | Cigar>;
        const cig = markers.get('signify');
        if (!cig) {
            throw new Error(
                'Invalid signature format - missing "signify" marker'
            );
        }

        const verified = this.verfer.verify(
            cig.raw,
            b(JSON.stringify(payload))
        );
        if (!verified) {
            throw new Error('Invalid signature');
        }

        const response = EssrAuthenticator.deserializeResponse(
            this.decrypt(ciphertext),
            requestMethod
        );

        if (response.headers.get(HEADER_SIG_SENDER) !== sender) {
            throw new Error(
                'Invalid ESSR payload, missing or incorrect encrypted sender'
            );
        }

        return response;
    }

    // KERIA seals the response to the client key it has in the controller's KEL
    private decrypt(ciphertext: Uint8Array): Uint8Array {
        try {
            return libsodium.crypto_box_seal_open(
                ciphertext,
                this.cx25519Pub,
                this.cx25519Priv
            );
        } catch (e) {
            throw new Error(
                'Failed to decrypt ESSR response - sealed to a different client key',
                { cause: e }
            );
        }
    }

    /** Parse KERIA's finite ESSR response envelope without decoding its body. */
    static deserializeResponse(
        httpBytes: Uint8Array,
        requestMethod?: string
    ): Response {
        const separator = this.findHeaderSeparator(httpBytes);
        if (separator === -1) {
            throw new Error(
                'Failed to deserialize ESSR response - missing CRLFCRLF separator'
            );
        }

        const head = this.decodeAsciiHead(
            httpBytes.subarray(0, separator),
            'response'
        );
        const [statusLine, ...headerLines] = head.split('\r\n');
        const statusMatch = RESPONSE_STATUS_LINE.exec(statusLine);
        if (statusMatch === null) {
            throw new Error(
                'Failed to deserialize ESSR response - invalid status line'
            );
        }

        const status = Number(statusMatch[1]);
        if (status < 200 || status > 599) {
            throw new Error(
                'Failed to deserialize ESSR response - unsupported status code'
            );
        }
        const statusText = statusMatch[2] ?? '';
        if (
            [...statusText].some(
                (character) =>
                    character.charCodeAt(0) < 32 ||
                    character.charCodeAt(0) === 127
            )
        ) {
            throw new Error(
                'Failed to deserialize ESSR response - invalid status text'
            );
        }

        const body = httpBytes.slice(separator + HEADER_SEPARATOR.byteLength);
        const headers = new Headers();
        const contentLengths: string[] = [];
        for (const line of headerLines) {
            const i = line.indexOf(':');
            const name = line.slice(0, i);
            if (i < 1 || !HTTP_TOKEN.test(name)) {
                throw new Error(
                    'Failed to deserialize ESSR response - invalid header field'
                );
            }
            const value = line.slice(i + 1).trim();
            if (
                [...value].some(
                    (character) =>
                        (character.charCodeAt(0) < 32 && character !== '\t') ||
                        character.charCodeAt(0) === 127
                )
            ) {
                throw new Error(
                    'Failed to deserialize ESSR response - invalid header value'
                );
            }

            const lowerName = name.toLowerCase();
            if (lowerName === 'transfer-encoding') {
                throw new Error(
                    'Failed to deserialize ESSR response - Transfer-Encoding is unsupported'
                );
            }
            if (lowerName === 'content-length') {
                contentLengths.push(value);
            }
            headers.append(name, value);
        }

        if (
            contentLengths.length > 1 ||
            (contentLengths.length === 1 && !/^\d+$/.test(contentLengths[0]))
        ) {
            throw new Error(
                'Failed to deserialize ESSR response - invalid Content-Length'
            );
        }

        const method = requestMethod?.toUpperCase();
        const bodyless = method === 'HEAD' || [204, 205, 304].includes(status);
        if (bodyless && body.byteLength !== 0) {
            throw new Error(
                'Failed to deserialize ESSR response - body is forbidden for this response'
            );
        }

        if (contentLengths.length === 1) {
            if (status === 204) {
                throw new Error(
                    'Failed to deserialize ESSR response - Content-Length is forbidden for 204'
                );
            }
            if (status === 205 && !contentLengthEquals(contentLengths[0], 0)) {
                throw new Error(
                    'Failed to deserialize ESSR response - 205 Content-Length must be zero'
                );
            }
            if (
                method !== 'HEAD' &&
                status !== 304 &&
                !contentLengthEquals(contentLengths[0], body.byteLength)
            ) {
                throw new Error(
                    'Failed to deserialize ESSR response - Content-Length does not match the body'
                );
            }
        }

        return new Response(bodyless || body.byteLength === 0 ? null : body, {
            status,
            statusText,
            headers,
        });
    }

    private static encodeAsciiHead(
        head: string,
        messageType: string
    ): Uint8Array {
        for (let i = 0; i < head.length; i++) {
            if (head.charCodeAt(i) > 127) {
                throw new Error(
                    `Failed to serialize ESSR ${messageType} - head must be ASCII`
                );
            }
        }
        return new TextEncoder().encode(head);
    }

    private static decodeAsciiHead(
        head: Uint8Array,
        messageType: string
    ): string {
        if (head.some((value) => value > 127)) {
            throw new Error(
                `Failed to deserialize ESSR ${messageType} - head must be ASCII`
            );
        }
        return new TextDecoder().decode(head);
    }

    private static findHeaderSeparator(message: Uint8Array): number {
        const lastStart = message.byteLength - HEADER_SEPARATOR.byteLength;
        for (let i = 0; i <= lastStart; i++) {
            if (
                HEADER_SEPARATOR.every(
                    (value, offset) => message[i + offset] === value
                )
            ) {
                return i;
            }
        }
        return -1;
    }
}
