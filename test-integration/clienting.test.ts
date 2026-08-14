import { randomPasscode, ready, SignifyClient, Tier } from 'signify-ts';
import { assert, expect, test } from 'vitest';
import { resolveEnvironment } from './utils/resolve-env.ts';

test('boot and connect honor cancellation signals', async () => {
    await ready();
    const environment = resolveEnvironment();
    const bran = randomPasscode();
    const client = new SignifyClient(
        environment.url,
        bran,
        Tier.low,
        environment.bootUrl
    );

    const bootCancellation = new Error('cancel boot');
    await expect(
        client.boot({
            signal: AbortSignal.abort(bootCancellation),
        })
    ).rejects.toBe(bootCancellation);

    const boot = await client.boot({
        signal: AbortSignal.timeout(5_000),
    });
    assert.equal(boot.status, 202);

    const connectCancellation = new Error('cancel connect');
    await expect(
        client.connect({
            signal: AbortSignal.abort(connectCancellation),
        })
    ).rejects.toBe(connectCancellation);

    await client.connect({
        signal: AbortSignal.timeout(5_000),
    });
    assert(client.agent);

    const reconnectingClient = new SignifyClient(
        environment.url,
        bran,
        Tier.low,
        environment.bootUrl
    );
    await reconnectingClient.connect({
        signal: AbortSignal.timeout(5_000),
    });
    assert.equal(reconnectingClient.agent?.pre, client.agent.pre);
});
