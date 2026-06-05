import type { IdentifierDwsResult } from './aiding.ts';
import type { SignifyClient } from './clienting.ts';
import type { CreateRegistryArgs, CredentialData } from './credentialing.ts';

export interface DidWebsRegistrySetup {
    name: string;
    registryId: string | null;
    ready: boolean;
    createArgs: CreateRegistryArgs;
}

export interface DidWebsDesignatedAliasSetup {
    schema: string;
    credentialSaid: string | null;
    ready: boolean;
    issueArgs: CredentialData | null;
}

export interface DidWebsSetupInfo {
    name: string;
    aid: string;
    did: string;
    dws: string | null;
    didJsonUrl: string;
    keriCesrUrl: string;
    ready: boolean;
    registry: DidWebsRegistrySetup;
    designatedAlias: DidWebsDesignatedAliasSetup;
}

/**
 * Thin did:webs state client.
 *
 * KERIA owns readiness projection. SignifyTS exposes typed access to that
 * projection so higher-level packages can orchestrate edge-signed registry and
 * designated-alias ACDC setup.
 */
export class DidWebs {
    client: SignifyClient;

    constructor(client: SignifyClient) {
        this.client = client;
    }

    async setup(name: string): Promise<DidWebsSetupInfo> {
        const res = await this.client.fetch(
            `/identifiers/${encodeURIComponent(name)}/dws/setup`,
            'GET',
            null
        );
        return await res.json();
    }

    async readiness(name: string): Promise<IdentifierDwsResult> {
        return await this.client.identifiers().dws(name);
    }
}
