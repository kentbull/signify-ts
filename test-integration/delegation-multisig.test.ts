import { assert, test } from 'vitest';
import signify from 'signify-ts';
import {
    assertNotifications,
    assertOperations,
    createAID,
    createTimestamp,
    assertNoNotifications,
    getOrCreateClient,
    markAndRemoveNotification,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util.ts';
import {
    acceptMultisigIncept,
    addEndRoleMultisig,
    delegateMultisig,
    startMultisigIncept,
} from './utils/multisig-utils.ts';
import { step } from './utils/test-step.ts';

const delegatorGroupName = 'delegator_group';
const delegateeGroupName = 'delegatee_group';
const delegator1Name = 'delegator1';
const delegator2Name = 'delegator2';
const delegatee1Name = 'delegatee1';
const delegatee2Name = 'delegatee2';

function groupAgentOobi(
    memberOobi: string,
    groupPrefix: string,
    agentPrefix: string
): string {
    const oobi = new URL(memberOobi);
    oobi.pathname = `/oobi/${groupPrefix}/agent/${agentPrefix}`;
    oobi.search = '';
    oobi.hash = '';
    return oobi.toString();
}

const keriaInstances = [
    {
        url: 'http://127.0.0.1:3901',
        bootUrl: 'http://127.0.0.1:3903',
    },
    {
        url: 'http://127.0.0.1:4901',
        bootUrl: 'http://127.0.0.1:4903',
    },
    {
        url: 'http://127.0.0.1:5901',
        bootUrl: 'http://127.0.0.1:5903',
    },
    {
        url: 'http://127.0.0.1:6901',
        bootUrl: 'http://127.0.0.1:6903',
    },
] as const;

test('delegation-multisig', async () => {
    await signify.ready();
    // Use one controller per KERIA instance until Agency routing supports
    // multiple local members of the same multisig group.
    const [
        delegator1Client,
        delegator2Client,
        delegatee1Client,
        delegatee2Client,
    ] = await step('Creating single sig clients', async () => {
        return await Promise.all([
            getOrCreateClient(undefined, [], keriaInstances[0]),
            getOrCreateClient(undefined, [], keriaInstances[1]),
            getOrCreateClient(undefined, [], keriaInstances[2]),
            getOrCreateClient(undefined, [], keriaInstances[3]),
        ]);
    });

    // Create delegator and delegatee identifiers clients
    const [delegator1Aid, delegator2Aid, delegatee1Aid, delegatee2Aid] =
        await step('Creating single sig aids', async () => {
            return await Promise.all([
                createAID(delegator1Client, delegator1Name),
                createAID(delegator2Client, delegator2Name),
                createAID(delegatee1Client, delegatee1Name),
                createAID(delegatee2Client, delegatee2Name),
            ]);
        });

    // Exchange OOBIs
    const [delegator1Oobi, delegator2Oobi, delegatee1Oobi, delegatee2Oobi] =
        await step('Getting OOBIs before resolving...', async () => {
            return await Promise.all([
                await delegator1Client.oobis().get(delegator1Name, 'agent'),
                await delegator2Client.oobis().get(delegator2Name, 'agent'),
                await delegatee1Client.oobis().get(delegatee1Name, 'agent'),
                await delegatee2Client.oobis().get(delegatee2Name, 'agent'),
            ]);
        });

    await step('Resolving OOBIs', async () => {
        await Promise.all([
            (async () => {
                await resolveOobi(
                    delegator1Client,
                    delegator2Oobi.oobis[0],
                    delegator2Name
                );
                await resolveOobi(
                    delegator1Client,
                    delegatee1Oobi.oobis[0],
                    delegatee1Name
                );
                await resolveOobi(
                    delegator1Client,
                    delegatee2Oobi.oobis[0],
                    delegatee2Name
                );
            })(),
            (async () => {
                await resolveOobi(
                    delegator2Client,
                    delegator1Oobi.oobis[0],
                    delegator1Name
                );
                await resolveOobi(
                    delegator2Client,
                    delegatee1Oobi.oobis[0],
                    delegatee1Name
                );
                await resolveOobi(
                    delegator2Client,
                    delegatee2Oobi.oobis[0],
                    delegatee2Name
                );
            })(),
            (async () => {
                await resolveOobi(
                    delegatee1Client,
                    delegatee2Oobi.oobis[0],
                    delegatee2Name
                );
            })(),
            (async () => {
                await resolveOobi(
                    delegatee2Client,
                    delegatee1Oobi.oobis[0],
                    delegatee1Name
                );
            })(),
        ]);
    });
    console.log(
        `${delegator1Name}(${delegator1Aid.prefix}) and ${delegatee1Name}(${delegatee1Aid.prefix}) resolved ${delegator2Name}(${delegator2Aid.prefix}) and ${delegatee2Name}(${delegatee2Aid.prefix}) OOBIs and vice versa`
    );

    // First member start the creation of a multisig identifier
    // Create a multisig AID for the GEDA.
    // Skip if a GEDA AID has already been incepted.
    const otor1 = await step(
        `${delegator1Name}(${delegator1Aid.prefix}) initiated delegator multisig, waiting for ${delegator2Name}(${delegator2Aid.prefix}) to join...`,
        async () => {
            return await startMultisigIncept(delegator1Client, {
                groupName: delegatorGroupName,
                localMemberName: delegator1Aid.name,
                participants: [delegator1Aid.prefix, delegator2Aid.prefix],
                isith: 2,
                nsith: 2,
                toad: 2,
                wits: [
                    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
                    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
                    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
                ],
            });
        }
    );

    const [ntor] = await waitForNotifications(
        delegator2Client,
        '/multisig/icp',
        {
            maxSleep: 10000,
            minSleep: 1000,
            maxRetries: undefined,
            timeout: 30000,
        }
    );
    await markAndRemoveNotification(delegator2Client, ntor);
    assert(ntor.a.d);
    const otor2 = await acceptMultisigIncept(delegator2Client, {
        localMemberName: delegator2Aid.name,
        groupName: delegatorGroupName,
        msgSaid: ntor.a.d,
    });

    const torpre = otor1.name.split('.')[1];
    await Promise.all([
        waitOperation(delegator1Client, otor1),
        waitOperation(delegator2Client, otor2),
    ]);

    const adelegatorGroupName1 = await delegator1Client
        .identifiers()
        .get(delegatorGroupName);
    const adelegatorGroupName2 = await delegator2Client
        .identifiers()
        .get(delegatorGroupName);

    assert.equal(adelegatorGroupName1.prefix, adelegatorGroupName2.prefix);
    assert.equal(adelegatorGroupName1.name, adelegatorGroupName2.name);
    const adelegatorGroupName = adelegatorGroupName1;

    // Resolve one group OOBI through each member's KERIA instance.
    const delegatorGroupOobis = await step(
        `Add delegator end roles for ${delegatorGroupName}(${adelegatorGroupName.prefix})`,
        async () => {
            const timestamp = createTimestamp();
            const opList1 = await addEndRoleMultisig(
                delegator1Client,
                delegatorGroupName,
                delegator1Aid,
                [delegator2Aid],
                adelegatorGroupName,
                timestamp,
                true
            );
            const opList2 = await addEndRoleMultisig(
                delegator2Client,
                delegatorGroupName,
                delegator2Aid,
                [delegator1Aid],
                adelegatorGroupName,
                timestamp
            );

            await Promise.all(
                opList1.map((op) => waitOperation(delegator1Client, op))
            );
            await Promise.all(
                opList2.map((op) => waitOperation(delegator2Client, op))
            );

            await assertNoNotifications(delegator1Client, '/multisig/rpy');
            await assertNoNotifications(delegator2Client, '/multisig/rpy');

            const oobis = [
                groupAgentOobi(
                    delegator1Oobi.oobis[0],
                    adelegatorGroupName.prefix,
                    delegator1Client.agent!.pre
                ),
                groupAgentOobi(
                    delegator2Oobi.oobis[0],
                    adelegatorGroupName.prefix,
                    delegator2Client.agent!.pre
                ),
            ];
            assert.equal(new Set(oobis).size, 2);

            return oobis;
        }
    );

    await Promise.all(
        [delegatee1Client, delegatee2Client].map(async (client) => {
            for (const oobi of delegatorGroupOobis) {
                await resolveOobi(client, oobi, adelegatorGroupName.name);
            }
        })
    );

    const opDelegatee1 = await step(
        `${delegatee1Name}(${delegatee1Aid.prefix}) initiated delegatee multisig, waiting for ${delegatee2Name}(${delegatee2Aid.prefix}) to join...`,
        async () => {
            return await startMultisigIncept(delegatee1Client, {
                groupName: delegateeGroupName,
                localMemberName: delegatee1Aid.name,
                participants: [delegatee1Aid.prefix, delegatee2Aid.prefix],
                isith: 2,
                nsith: 2,
                toad: 2,
                delpre: torpre,
                wits: [
                    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
                    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
                    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
                ],
            });
        }
    );

    // Second member of delegatee check notifications and join the multisig
    const [ntee] = await waitForNotifications(
        delegatee2Client,
        '/multisig/icp'
    );
    await markAndRemoveNotification(delegatee2Client, ntee);
    assert(ntee.a.d);

    const opDelegatee2 = await acceptMultisigIncept(delegatee2Client, {
        localMemberName: delegatee2Aid.name,
        groupName: delegateeGroupName,
        msgSaid: ntee.a.d,
    });

    console.log(`${delegatee2Name} joined multisig, waiting for delegator...`);

    const agtee1 = await delegatee1Client.identifiers().get(delegateeGroupName);
    const agtee2 = await delegatee2Client.identifiers().get(delegateeGroupName);

    assert.equal(agtee1.prefix, agtee2.prefix);
    assert.equal(agtee1.name, agtee2.name);

    const teepre = opDelegatee1.name.split('.')[1];
    assert.equal(opDelegatee2.name.split('.')[1], teepre);
    console.log('Delegatee prefix:', teepre);

    await step('delegators receive delegation requests', async () => {
        const notificationOptions = {
            minCount: 1,
            maxSleep: 10000,
            minSleep: 1000,
            maxRetries: undefined,
            timeout: 60000,
        };
        const [requests1, requests2] = await Promise.all([
            waitForNotifications(
                delegator1Client,
                '/delegate/request',
                notificationOptions
            ),
            waitForNotifications(
                delegator2Client,
                '/delegate/request',
                notificationOptions
            ),
        ]);
        // KERIpy elects the group member at signing index 0 to perform
        // delegation and witness messaging.
        const expectedSource = delegatee1Client.agent!.pre;

        for (const requests of [requests1, requests2]) {
            assert.equal(requests.length, 1);

            for (const request of requests) {
                assert.equal(request.a.src, expectedSource);
                assert.equal(request.a.delpre, torpre);
                assert.deepEqual(request.a.aids, []);
                assert(request.a.ked);
                assert.equal(request.a.ked.t, 'dip');
                assert.equal(request.a.ked.i, teepre);
                assert.equal(request.a.ked.s, '0');
                assert.equal(request.a.ked.d, teepre);
                assert.equal(request.a.ked.di, torpre);
            }
        }

        await Promise.all([
            ...requests1.map((request) =>
                markAndRemoveNotification(delegator1Client, request)
            ),
            ...requests2.map((request) =>
                markAndRemoveNotification(delegator2Client, request)
            ),
        ]);
    });

    await step('delegator anchors/approves delegation', async () => {
        // GEDA anchors delegation with an interaction event.
        const anchor = {
            i: teepre,
            s: '0',
            d: teepre,
        };
        const delApprOp1 = await delegateMultisig(
            delegator1Client,
            delegator1Aid,
            [delegator2Aid],
            adelegatorGroupName,
            anchor,
            true
        );
        const delApprOp2 = await delegateMultisig(
            delegator2Client,
            delegator2Aid,
            [delegator1Aid],
            adelegatorGroupName,
            anchor
        );
        const [dresult1, dresult2] = await Promise.all([
            waitOperation(delegator1Client, delApprOp1),
            waitOperation(delegator2Client, delApprOp2),
        ]);

        assert.equal(dresult1.response, dresult2.response);

        await assertNoNotifications(delegator1Client, '/multisig/ixn');
        await assertNoNotifications(delegator2Client, '/multisig/ixn');
    });

    const queryOp1 = await delegator1Client
        .keyStates()
        .query(adelegatorGroupName.prefix, '1');
    const queryOp2 = await delegator2Client
        .keyStates()
        .query(adelegatorGroupName.prefix, '1');

    const kstor1 = await waitOperation(delegator1Client, queryOp1);
    const kstor2 = await waitOperation(delegator2Client, queryOp2);

    // QARs query the GEDA's key state
    const ksteetor1 = await delegatee1Client
        .keyStates()
        .query(adelegatorGroupName.prefix, '1');
    const ksteetor2 = await delegatee2Client
        .keyStates()
        .query(adelegatorGroupName.prefix, '1');
    const teeTor1 = await waitOperation(delegatee1Client, ksteetor1);
    const teeTor2 = await waitOperation(delegatee2Client, ksteetor2);

    const teeDone1 = await waitOperation(delegatee1Client, opDelegatee1);
    const teeDone2 = await waitOperation(delegatee2Client, opDelegatee2);
    console.log('Delegated multisig created!');

    const agtee = await delegatee1Client.identifiers().get(delegateeGroupName);
    assert.equal(agtee.prefix, teepre);

    await assertOperations(
        delegator1Client,
        delegator2Client,
        delegatee1Client,
        delegatee2Client
    );
    await assertNotifications(
        delegator1Client,
        delegator2Client,
        delegatee1Client,
        delegatee2Client
    );
}, 600000);
