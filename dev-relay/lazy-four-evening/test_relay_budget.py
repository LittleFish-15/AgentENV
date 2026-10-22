import asyncio
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('relay_budget',Path(__file__).with_name('relay_budget.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Writer:
    def __init__(self):self.data=bytearray();self.closed=False;self.eof=False
    def write(self,data):self.data.extend(data)
    async def drain(self):await asyncio.sleep(0)
    def can_write_eof(self):return True
    def write_eof(self):self.eof=True
    def close(self):self.closed=True


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self,deadline,delay):
        client,server=asyncio.StreamReader(),asyncio.StreamReader()
        client.feed_data(b'GET fixture');client.feed_eof()
        out,to_server=Writer(),Writer();events=[]
        async def response():
            server.feed_data(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
            await asyncio.sleep(delay)
            server.feed_data(b'3\r\n124\r\n0\r\n\r\n');server.feed_eof()
        sender=asyncio.create_task(response())
        await m.relay(client,out,server,to_server,timeout=deadline,observe=events.append)
        await sender
        return out,to_server,events

    async def test_equal_budget_drops_exit_while_margin_delivers_it(self):
        old,_,events=await self.exchange(.02,.06)
        self.assertEqual(events[-1]['reason'],'proxy_deadline')
        self.assertNotIn(b'124',old.data)
        fixed,request,events=await self.exchange(.3,.06)
        self.assertIn(b'3\r\n124\r\n0\r\n\r\n',fixed.data)
        self.assertEqual(request.data,b'GET fixture')
        self.assertEqual(events[-1]['reason'],'eof')
        self.assertTrue(fixed.closed and request.closed)

    async def test_external_cancellation_closes_both_sides(self):
        client,server=asyncio.StreamReader(),asyncio.StreamReader()
        out,peer=Writer(),Writer();events=[]
        task=asyncio.create_task(m.relay(client,out,server,peer,timeout=1,observe=events.append))
        await asyncio.sleep(.01);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertTrue(out.closed and peer.closed)
        self.assertEqual(events[-1]['reason'],'cancelled')

    async def test_diagnostic_failure_does_not_change_payload(self):
        client,server=asyncio.StreamReader(),asyncio.StreamReader()
        client.feed_eof();server.feed_data(b'only-body');server.feed_eof()
        out,peer=Writer(),Writer()
        def bad(_):raise OSError('modeled full log device')
        await m.relay(client,out,server,peer,timeout=1,observe=bad)
        self.assertEqual(out.data,b'only-body')

    def test_guest_deadline_not_extended(self):
        self.assertEqual(m.GUEST_COMMAND_SECONDS,300)
        self.assertEqual(m.GUEST_KILL_GRACE_SECONDS,5)
        self.assertEqual(m.CLI_COMMAND_SECONDS,330)
        self.assertEqual(m.PROXY_CONNECTION_SECONDS,360)
        m.validate_budgets()


if __name__=='__main__':unittest.main()
