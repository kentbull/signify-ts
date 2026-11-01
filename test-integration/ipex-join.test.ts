import assert from 'assert';
import { randomUUID } from 'node:crypto';
import signify, { d, messagize, Siger } from 'signify-ts';
import { test } from 'vitest';
import {
    createTimestamp,
    getOrCreateClients,
    getOrCreateIdentifier,
    resolveOobi,
    waitAndMarkNotification,
    waitOperation,
} from './utils/test-util.ts';
import {
    createTwoMemberGroup,
    exposeMultisigAgentOobi,
} from './utils/multisig-utils.ts';

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';

function alias(name: string): string {
    return `${name}-${randomUUID().slice(0, 8)}`;
}

test('ipex join approves a peer-originated multisig apply proposal', async () => {
    await signify.ready();
    const [senderClientA, senderClientB, recipientClient] =
        await getOrCreateClients(3);

    const memberAName = alias('sender-a');
    const memberBName = alias('sender-b');
    const groupName = alias('sender-group');
    const recipientName = alias('recipient');

    const { memberBPrefix, groupA } = await createTwoMemberGroup(
        senderClientA,
        memberAName,
        senderClientB,
        memberBName,
        groupName
    );

    const [recipientPrefix, recipientOobi] = await getOrCreateIdentifier(
        recipientClient,
        recipientName
    );
    await Promise.all([
        resolveOobi(senderClientA, recipientOobi, recipientName),
        resolveOobi(senderClientB, recipientOobi, recipientName),
    ]);
    const groupOobi = await exposeMultisigAgentOobi(
        senderClientA,
        memberAName,
        senderClientB,
        memberBName,
        groupName
    );
    await resolveOobi(recipientClient, groupOobi, groupName);

    const [apply, sigs, end] = await senderClientA.ipex().apply({
        senderName: groupName,
        schemaSaid: QVI_SCHEMA_SAID,
        attributes: { LEI: '5493001KJTIIGC8Y1R17' },
        recipient: recipientPrefix,
        datetime: createTimestamp(),
    });
    const operationA = await senderClientA
        .ipex()
        .submitApply(groupName, apply, sigs, [recipientPrefix]);

    const memberA = await senderClientA.identifiers().get(memberAName);
    const seal = [
        'SealEvent',
        {
            i: groupA.prefix,
            s: groupA.state.ee.s,
            d: groupA.state.ee.d,
        },
    ];
    const sigers = sigs.map((sig) => new Siger({ qb64: sig }));
    const ims = d(messagize(apply, sigers, seal));
    const atc = ims.substring(apply.size) + end;
    await senderClientA
        .exchanges()
        .send(
            memberAName,
            'multisig',
            memberA,
            '/multisig/exn',
            { gid: groupA.prefix },
            { exn: [apply, atc] },
            [memberBPrefix]
        );

    const joinProposalSaid = await waitAndMarkNotification(
        senderClientB,
        '/multisig/exn'
    );
    assert(joinProposalSaid, 'multisig IPEX proposal SAID missing');
    const storedProposal = await senderClientB
        .exchanges()
        .get(joinProposalSaid);
    const embedded = storedProposal.exn.e.exn as { r: string; d: string };
    assert.equal(embedded.r, '/ipex/apply');
    assert.equal(embedded.d, apply.said);

    const operationB = await senderClientB
        .ipex()
        .join(groupName, joinProposalSaid);
    await Promise.all([
        waitOperation(senderClientA, operationA),
        waitOperation(senderClientB, operationB),
    ]);

    const recipientApplySaid = await waitAndMarkNotification(
        recipientClient,
        '/exn/ipex/apply',
        { said: apply.said }
    );
    assert.equal(recipientApplySaid, apply.said);
    const recipientExchange = await recipientClient.exchanges().get(apply.said);
    assert.equal(recipientExchange.exn.d, apply.said);
});
