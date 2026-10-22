"""Bound the proxy outside the unchanged Guest/CLI command deadlines."""
import asyncio
import time

GUEST_COMMAND_SECONDS = 300
GUEST_KILL_GRACE_SECONDS = 5
CLI_COMMAND_SECONDS = 330
PROXY_CONNECTION_SECONDS = 360


def validate_budgets():
    if not (GUEST_COMMAND_SECONDS + GUEST_KILL_GRACE_SECONDS < CLI_COMMAND_SECONDS < PROXY_CONNECTION_SECONDS):
        raise ValueError('Guest exit delivery must fit within CLI and proxy budgets')


async def relay(reader, writer, peer_reader, peer_writer, *, timeout=PROXY_CONNECTION_SECONDS, observe=None):
    """Relay bytes unchanged, retaining bounded lifetime and cancellation.

    Observations contain counts and a reason, never HTTP headers, API keys,
    command text or response content. They are diagnostics, not workload metrics.
    """
    if not isinstance(timeout, (float, int)) or timeout <= 0:
        raise ValueError('Positive bounded proxy lifetime required')
    started = time.monotonic()
    counts = [0, 0]
    reason, error_type = 'eof', None

    async def pump(source, destination, index):
        while True:
            data = await source.read(65536)
            if not data:
                if destination.can_write_eof():
                    destination.write_eof()
                return
            destination.write(data)
            counts[index] += len(data)
            await destination.drain()

    tasks = [asyncio.create_task(pump(reader, peer_writer, 0)),
             asyncio.create_task(pump(peer_reader, writer, 1))]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout)
    except asyncio.TimeoutError:
        reason = 'proxy_deadline'
    except asyncio.CancelledError:
        reason = 'cancelled'
        raise
    except (OSError, ConnectionError) as error:
        reason, error_type = 'io_error', type(error).__name__
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        peer_writer.close()
        if observe is not None:
            try:
                observe({'reason': reason, 'errorType': error_type, 'durationSeconds': time.monotonic() - started,
                         'clientToServerBytes': counts[0], 'serverToClientBytes': counts[1],
                         'proxyDeadlineSeconds': timeout, 'payloadLogged': False})
            except OSError:
                # Failure of a diagnostic sink must not alter command delivery.
                pass


validate_budgets()
