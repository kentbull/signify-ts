import { strict as assert } from 'node:assert';
import {
    Algos,
    CredentialData,
    HabState,
    KeyState,
    Serder,
    SignifyClient,
    Siger,
    assertMultisigIcp,
    b,
    d,
    messagize,
    randomNonce,
    rotate,
} from 'signify-ts';
import { test } from 'vitest';
import {
    createTimestamp,
    getIssuedCredential,
    getOrCreateAID,
    getOrCreateClient,
    getOrCreateContact,
    getStates,
    resolveOobi,
    waitAndMarkNotification,
    waitOperation,
} from './utils/test-util.ts';
import {
    createRegistryMultisig,
    issueCredentialMultisig,
} from './utils/multisig-utils.ts';
import { resolveEnvironment } from './utils/resolve-env.ts';
import { retry } from './utils/retry.ts';

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const multisigAddTest =
    process.env.SIGNIFY_TS_MULTISIG_ADD_SPIKE === '1' ? test : test.skip;

interface PreparedSync {
    manifest: {
        d: string;
        gid: string;
        target: string;
        smids: string[];
    };
    signable: string;
    operation: string;
}

function message(
    serder: Serder,
    signatures: string[],
    seal?: [string, { i: string; s: string; d: string }]
): Uint8Array {
    const sigers = signatures.map((qb64) => new Siger({ qb64 }));
    return messagize(serder, sigers, seal);
}

async function putCesr(agentUrl: string, destination: string, raw: Uint8Array) {
    const response = await fetch(`${agentUrl.replace(/\/$/, '')}/`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/octet-stream',
            'CESR-DESTINATION': destination,
        },
        body: raw,
        // Node's fetch accepts Uint8Array even though the DOM type omits it.
        duplex: 'half',
    } as RequestInit);
    if (!response.ok) {
        throw new Error(
            `CESR PUT failed with ${response.status}: ${await response.text()}`
        );
    }
    assert.equal(response.status, 204);
}

async function waitForState(
    client: SignifyClient,
    prefix: string,
    said: string
) {
    return retry(
        async () => {
            const [state] = await client.keyStates().get(prefix);
            assert.equal(state.d, said);
            return state;
        },
        { timeout: 60_000, minSleep: 100, maxSleep: 500 }
    );
}

async function createPrecommittedGroup(
    clientA: SignifyClient,
    memberAName: string,
    clientB: SignifyClient,
    memberBName: string,
    memberC: HabState,
    groupName: string
) {
    const memberA = await clientA.identifiers().get(memberAName);
    const memberB = await clientB.identifiers().get(memberBName);
    const smids = [memberA.prefix, memberB.prefix];
    const rmids = [...smids, memberC.prefix];

    const resultA = await clientA.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: memberA,
        isith: 2,
        nsith: 3,
        toad: 0,
        wits: [],
        states: await getStates(clientA, smids),
        rstates: await getStates(clientA, rmids),
    });
    const operationA = await resultA.op();
    const inceptionAttachmentA = d(
        message(resultA.serder, resultA.sigs)
    ).substring(resultA.serder.size);
    await clientA
        .exchanges()
        .send(
            memberAName,
            'multisig',
            memberA,
            '/multisig/icp',
            { gid: resultA.serder.pre, smids, rmids },
            { icp: [resultA.serder, inceptionAttachmentA] },
            [memberB.prefix]
        );

    const requestSaid = await waitAndMarkNotification(
        clientB,
        '/multisig/icp',
        { timeout: 30_000 }
    );
    const [request] = await clientB.groups().getRequest(requestSaid);
    const proposal = assertMultisigIcp(request).exn;
    const inception = proposal.e.icp;
    const resultB = await clientB.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: memberB,
        isith: inception.kt,
        nsith: inception.nt,
        toad: parseInt(inception.bt),
        wits: inception.b,
        states: await getStates(clientB, proposal.a.smids),
        rstates: await getStates(clientB, proposal.a.rmids ?? proposal.a.smids),
    });
    const operationB = await resultB.op();
    assert.equal(resultB.serder.raw, resultA.serder.raw);
    const inceptionAttachmentB = d(
        message(resultB.serder, resultB.sigs)
    ).substring(resultB.serder.size);
    await clientB
        .exchanges()
        .send(
            memberBName,
            'multisig',
            memberB,
            '/multisig/icp',
            { gid: resultB.serder.pre, smids, rmids },
            { icp: [resultB.serder, inceptionAttachmentB] },
            [memberA.prefix]
        );

    await Promise.all([
        waitOperation(clientA, operationA, AbortSignal.timeout(60_000)),
        waitOperation(clientB, operationB, AbortSignal.timeout(60_000)),
    ]);
    const groupA = await clientA.identifiers().get(groupName);
    const groupB = await clientB.identifiers().get(groupName);
    assert.equal(groupA.prefix, groupB.prefix);
    return { groupA, groupB, smids, rmids };
}

async function publishEndpoint(
    clientA: SignifyClient,
    memberAName: string,
    clientB: SignifyClient,
    memberBName: string,
    groupName: string,
    agentUrl: string
) {
    const memberA = await clientA.identifiers().get(memberAName);
    const memberB = await clientB.identifiers().get(memberBName);
    const groupA = await clientA.identifiers().get(groupName);
    const stamp = groupA.state.dt;
    const seal: [string, { i: string; s: string; d: string }] = [
        'SealEvent',
        {
            i: groupA.prefix,
            s: groupA.state.ee.s,
            d: groupA.state.ee.d,
        },
    ];

    const resultA = await clientA
        .identifiers()
        .addEndRole(groupName, 'controller', memberA.prefix, stamp);
    const operationA = await resultA.op();
    const attachmentA = d(
        message(resultA.serder, resultA.sigs, seal)
    ).substring(resultA.serder.size);
    await clientA
        .exchanges()
        .send(
            memberAName,
            'multisig',
            memberA,
            '/multisig/rpy',
            { gid: groupA.prefix },
            { rpy: [resultA.serder, attachmentA] },
            [memberB.prefix]
        );

    await waitAndMarkNotification(clientB, '/multisig/rpy', {
        timeout: 30_000,
    });
    const resultB = await clientB
        .identifiers()
        .addEndRole(groupName, 'controller', memberA.prefix, stamp);
    const operationB = await resultB.op();
    assert.equal(resultB.serder.raw, resultA.serder.raw);
    const attachmentB = d(
        message(resultB.serder, resultB.sigs, seal)
    ).substring(resultB.serder.size);
    await clientB
        .exchanges()
        .send(
            memberBName,
            'multisig',
            memberB,
            '/multisig/rpy',
            { gid: groupA.prefix },
            { rpy: [resultB.serder, attachmentB] },
            [memberA.prefix]
        );
    await Promise.all([
        waitOperation(clientA, operationA, AbortSignal.timeout(60_000)),
        waitOperation(clientB, operationB, AbortSignal.timeout(60_000)),
    ]);

    const location = await clientA.identifiers().addLocScheme(memberAName, {
        url: agentUrl,
        eid: memberA.prefix,
        scheme: 'http',
        stamp,
    });
    await waitOperation(
        clientA,
        await location.op(),
        AbortSignal.timeout(60_000)
    );
    const memberSeal: [string, { i: string; s: string; d: string }] = [
        'SealEvent',
        {
            i: memberA.prefix,
            s: memberA.state.ee.s,
            d: memberA.state.ee.d,
        },
    ];
    await putCesr(
        agentUrl,
        memberB.prefix,
        message(location.serder, location.sigs, memberSeal)
    );
    await retry(
        async () => {
            const response = await clientB.fetch(
                `/locschemes/${memberA.prefix}`,
                'GET',
                null
            );
            const locations = (await response.json()) as {
                scheme: string;
            }[];
            assert(locations.some((item) => item.scheme === 'http'));
        },
        { timeout: 60_000, minSleep: 100, maxSleep: 500 }
    );
}

async function prepare(
    client: SignifyClient,
    groupName: string,
    body: Record<string, unknown>
): Promise<PreparedSync> {
    const response = await client.fetch(
        `/identifiers/${groupName}/multisig/add`,
        'POST',
        body
    );
    if (!response.ok) {
        throw new Error(
            `multisig add preparation failed with ${response.status}: ${await response.text()}`
        );
    }
    assert.equal(response.status, 202);
    return (await response.json()) as PreparedSync;
}

async function waitForSync(
    client: SignifyClient,
    operation: string,
    expectedStatus: string
) {
    return retry(
        async () => {
            const result = await client.operations().get(operation);
            const metadata = result.metadata as { status?: string } | undefined;
            assert.equal(metadata?.status, expectedStatus);
            return result;
        },
        { timeout: 90_000, minSleep: 100, maxSleep: 500 }
    );
}

multisigAddTest(
    'adds one precommitted member through the bounded live sync',
    { timeout: 240_000 },
    async () => {
        const agentUrl = process.env.SIGNIFY_TS_KERIA_AGENT_URL;
        if (!agentUrl) {
            throw new Error('SIGNIFY_TS_KERIA_AGENT_URL is required');
        }
        const suffix = Date.now().toString(36);
        const names = {
            memberA: `sync-a-${suffix}`,
            memberB: `sync-b-${suffix}`,
            memberC: `sync-c-${suffix}`,
            holder: `sync-h-${suffix}`,
            group: `sync-group-${suffix}`,
            registry: `sync-registry-${suffix}`,
        };
        const [clientA, clientB, clientC, clientH] = await Promise.all([
            getOrCreateClient(),
            getOrCreateClient(),
            getOrCreateClient(),
            getOrCreateClient(),
        ]);
        const [memberA, memberB, memberC, holder] = await Promise.all([
            getOrCreateAID(clientA, names.memberA, { toad: 0, wits: [] }),
            getOrCreateAID(clientB, names.memberB, { toad: 0, wits: [] }),
            getOrCreateAID(clientC, names.memberC, { toad: 0, wits: [] }),
            getOrCreateAID(clientH, names.holder, { toad: 0, wits: [] }),
        ]);

        const participants = [
            [clientA, names.memberA] as const,
            [clientB, names.memberB] as const,
            [clientC, names.memberC] as const,
            [clientH, names.holder] as const,
        ];
        const oobis = await Promise.all(
            participants.map(async ([client, name]) => {
                const result = await client.oobis().get(name, 'agent');
                return result.oobis[0];
            })
        );
        await Promise.all(
            participants.flatMap(([client], destination) =>
                participants
                    .map(([, name], source) =>
                        source === destination
                            ? undefined
                            : getOrCreateContact(client, name, oobis[source])
                    )
                    .filter(
                        (operation): operation is Promise<string> =>
                            operation !== undefined
                    )
            )
        );

        const { groupA, groupB, smids, rmids } = await createPrecommittedGroup(
            clientA,
            names.memberA,
            clientB,
            names.memberB,
            memberC,
            names.group
        );
        await publishEndpoint(
            clientA,
            names.memberA,
            clientB,
            names.memberB,
            names.group,
            agentUrl
        );

        const schemaUrl = `${resolveEnvironment().vleiServerUrl}/oobi/${QVI_SCHEMA_SAID}`;
        await Promise.all([
            resolveOobi(clientA, schemaUrl, 'schema'),
            resolveOobi(clientB, schemaUrl, 'schema'),
        ]);

        const nonce = randomNonce();
        const registryOperationA = await createRegistryMultisig(
            clientA,
            memberA,
            [memberB],
            groupA,
            names.registry,
            nonce,
            true
        );
        const registryOperationB = await createRegistryMultisig(
            clientB,
            memberB,
            [memberA],
            groupB,
            names.registry,
            nonce
        );
        await Promise.all([
            waitOperation(
                clientA,
                registryOperationA,
                AbortSignal.timeout(60_000)
            ),
            waitOperation(
                clientB,
                registryOperationB,
                AbortSignal.timeout(60_000)
            ),
        ]);
        const [registryA, registryB] = await retry(
            async () => {
                const [registriesA, registriesB] = await Promise.all([
                    clientA.registries().list(names.group),
                    clientB.registries().list(names.group),
                ]);
                assert.equal(registriesA.length, 1);
                assert.equal(registriesB.length, 1);
                assert.equal(registriesA[0].regk, registriesB[0].regk);
                return [registriesA[0], registriesB[0]];
            },
            { timeout: 60_000, minSleep: 100, maxSleep: 500 }
        );
        assert.equal(registryA.regk, registryB.regk);

        const credentialData: CredentialData = {
            i: groupA.prefix,
            ri: registryA.regk,
            s: QVI_SCHEMA_SAID,
            a: {
                i: holder.prefix,
                dt: createTimestamp(),
                LEI: '5493001KJTIIGC8Y1R17',
            },
        };
        const credentialOperationA = await issueCredentialMultisig(
            clientA,
            memberA,
            [memberB],
            names.group,
            credentialData,
            true
        );
        const credentialOperationB = await issueCredentialMultisig(
            clientB,
            memberB,
            [memberA],
            names.group,
            credentialData
        );
        await Promise.all([
            waitOperation(
                clientA,
                credentialOperationA,
                AbortSignal.timeout(60_000)
            ),
            waitOperation(
                clientB,
                credentialOperationB,
                AbortSignal.timeout(60_000)
            ),
        ]);
        const [credentialA, credentialB] = await retry(
            async () => {
                const [issuedA, issuedB] = await Promise.all([
                    getIssuedCredential(
                        clientA,
                        groupA,
                        holder,
                        QVI_SCHEMA_SAID
                    ),
                    getIssuedCredential(
                        clientB,
                        groupB,
                        holder,
                        QVI_SCHEMA_SAID
                    ),
                ]);
                assert(issuedA);
                assert(issuedB);
                assert.equal(issuedA.sad.d, issuedB.sad.d);
                return [issuedA, issuedB];
            },
            { timeout: 60_000, minSleep: 100, maxSleep: 500 }
        );
        assert.equal(credentialA.sad.d, credentialB.sad.d);
        assert.deepEqual(await clientC.keyStates().get(groupA.prefix), []);
        await assert.rejects(() =>
            clientC.credentials().get(credentialA.sad.d)
        );

        const rotateMember = async (client: SignifyClient, name: string) => {
            const result = await client.identifiers().rotate(name, { toad: 0 });
            await waitOperation(
                client,
                await result.op(),
                AbortSignal.timeout(60_000)
            );
            return {
                state: await client.identifiers().get(name),
                serder: result.serder,
                sigs: result.sigs,
            };
        };
        const [rotatedA, rotatedB, rotatedC] = await Promise.all([
            rotateMember(clientA, names.memberA),
            rotateMember(clientB, names.memberB),
            rotateMember(clientC, names.memberC),
        ]);
        await Promise.all([
            putCesr(
                agentUrl,
                rotatedB.state.prefix,
                message(rotatedA.serder, rotatedA.sigs)
            ),
            putCesr(
                agentUrl,
                rotatedA.state.prefix,
                message(rotatedB.serder, rotatedB.sigs)
            ),
            putCesr(
                agentUrl,
                rotatedA.state.prefix,
                message(rotatedC.serder, rotatedC.sigs)
            ),
            putCesr(
                agentUrl,
                rotatedB.state.prefix,
                message(rotatedC.serder, rotatedC.sigs)
            ),
        ]);
        await Promise.all([
            waitForState(clientA, rotatedB.state.prefix, rotatedB.serder.said),
            waitForState(clientA, rotatedC.state.prefix, rotatedC.serder.said),
            waitForState(clientB, rotatedA.state.prefix, rotatedA.serder.said),
            waitForState(clientB, rotatedC.state.prefix, rotatedC.serder.said),
        ]);

        const statesA = (await getStates(clientA, rmids)) as KeyState[];
        const statesB = (await getStates(clientB, rmids)) as KeyState[];
        const establishmentState = (state: KeyState) => ({
            i: state.i,
            s: state.s,
            d: state.d,
            k: state.k,
            n: state.n,
        });
        assert.deepEqual(
            statesA.map(establishmentState),
            statesB.map(establishmentState)
        );
        const [currentGroupA, currentGroupB] = await Promise.all([
            clientA.identifiers().get(names.group),
            clientB.identifiers().get(names.group),
        ]);
        assert.equal(currentGroupA.state.d, currentGroupB.state.d);
        const addingRotation = rotate({
            pre: currentGroupA.prefix,
            keys: statesA.map((state) => state.k[0]),
            dig: currentGroupA.state.d,
            sn: parseInt(currentGroupA.state.s, 16) + 1,
            isith: 3,
            ndigs: statesA.map((state) => state.n[0]),
            nsith: 3,
            toad: 0,
            wits: [],
            cuts: [],
            adds: [],
        });
        const preparationBody = {
            rot: addingRotation.sad,
            target: rotatedC.state.prefix,
            smids: rmids,
            rmids,
            registry: registryA.regk,
            credential: credentialA.sad.d,
            schema: QVI_SCHEMA_SAID,
            endpoint: {
                cid: groupA.prefix,
                role: 'controller',
                eid: rotatedA.state.prefix,
            },
            location: {
                eid: rotatedA.state.prefix,
                scheme: 'http',
            },
        };
        const [preparedA, preparedB] = await Promise.all([
            prepare(clientA, names.group, preparationBody),
            prepare(clientB, names.group, preparationBody),
        ]);
        assert.equal(preparedA.signable, preparedB.signable);
        assert.deepEqual(preparedA.manifest.smids, rmids);
        assert.deepEqual(smids, rmids.slice(0, -1));

        const approvalBytes = new Uint8Array(
            Buffer.from(preparedA.signable, 'base64url')
        );
        const keeperA = clientA.manager!.get(groupA);
        const keeperB = clientB.manager!.get(groupB);
        const approvals = [
            (await keeperA.sign(approvalBytes))[0],
            (await keeperB.sign(approvalBytes))[0],
        ];
        const deliveryPayload = {
            op: 'deliver',
            gid: preparedA.manifest.gid,
            target: preparedA.manifest.target,
            manifest: preparedA.manifest.d,
            catalog: preparedA.signable,
            approvals,
        };
        const [delivery, deliverySigs, deliveryAttachment] = await clientC
            .exchanges()
            .createExchangeMessage(
                rotatedC.state,
                '/multisig/add',
                deliveryPayload,
                {},
                rotatedC.state.prefix
            );
        assert.equal(deliveryAttachment, '');
        const targetSeal: [string, { i: string; s: string; d: string }] = [
            'SealEvent',
            {
                i: rotatedC.state.prefix,
                s: rotatedC.state.state.ee.s,
                d: rotatedC.state.state.ee.d,
            },
        ];
        await putCesr(
            agentUrl,
            rotatedC.state.prefix,
            message(delivery, deliverySigs, targetSeal)
        );
        await waitForSync(clientC, preparedA.operation, 'state-verified');

        Object.assign(keeperA, { mhab: rotatedA.state });
        Object.assign(keeperB, { mhab: rotatedB.state });
        await keeperA.rotate([], true, statesA, statesA);
        await keeperB.rotate([], true, statesB, statesB);
        const groupSignatures = [
            (
                await keeperA.sign(
                    b(addingRotation.raw),
                    true,
                    undefined,
                    undefined,
                    true
                )
            )[0],
            (
                await keeperB.sign(
                    b(addingRotation.raw),
                    true,
                    undefined,
                    undefined,
                    true
                )
            )[0],
            (
                await clientC
                    .manager!.get(rotatedC.state)
                    .sign(b(addingRotation.raw), true, [2], [2])
            )[0],
        ];
        await putCesr(
            agentUrl,
            rotatedC.state.prefix,
            message(addingRotation, groupSignatures)
        );
        const syncOperation = await waitForSync(
            clientC,
            preparedA.operation,
            'core-converged'
        );
        assert.equal(syncOperation.done, false);

        const [groupStateC] = await clientC.keyStates().get(groupA.prefix);
        const credentialC = await clientC.credentials().get(credentialA.sad.d);
        const credentialStateC = await clientC
            .credentials()
            .state(registryA.regk, credentialA.sad.d);
        const schemaC = await clientC.schemas().get(QVI_SCHEMA_SAID);
        const endRolesC = await clientC
            .oobis()
            .endroles(groupA.prefix, 'controller');
        const locationResponse = await clientC.fetch(
            `/locschemes/${rotatedA.state.prefix}`,
            'GET',
            null
        );
        const locationsC = (await locationResponse.json()) as {
            scheme: string;
        }[];

        assert.equal(groupStateC.d, addingRotation.said);
        assert.equal(credentialC.sad.d, credentialA.sad.d);
        assert.equal(credentialStateC.et, 'iss');
        assert.equal(schemaC.$id, QVI_SCHEMA_SAID);
        assert(endRolesC.some((role) => role.eid === rotatedA.state.prefix));
        assert(locationsC.some((location) => location.scheme === 'http'));
    }
);
