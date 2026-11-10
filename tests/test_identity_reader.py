import json
import subprocess
import unittest
from unittest.mock import patch
from chip_relay.identity_reader import read_identity, PROBE
from chip_relay.binding import BindingError


class IdentityReaderTests(unittest.TestCase):
    def payload(self):
        return dict(schema='relay-identity-reader-v1', pid=123,
                    identity=dict(uid=1000,start_time=55,executable='/fixture/chrome',args=[]),sockets=['567'])

    def test_fixed_unprivileged_owner_command(self):
        result = subprocess.CompletedProcess([],0,json.dumps(self.payload()).encode(),b'')
        with patch('chip_relay.identity_reader.subprocess.run',return_value=result) as run:
            self.assertEqual(read_identity(123,1000)['sockets'],['567'])
        args=run.call_args.args[0]
        self.assertEqual(args[:8],['/usr/bin/sudo','-n','-u','#1000','--','/usr/bin/python3','-I','-c'])
        self.assertEqual(args[8],PROBE)
        self.assertEqual(run.call_args.kwargs['timeout'],5)
        self.assertNotIn('chip_relay', PROBE)

    def test_spoofed_pid_uid_and_schema_rejected(self):
        for key,value in [('pid',124),('schema','fake')]:
            data=self.payload(); data[key]=value
            with patch('chip_relay.identity_reader.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(data).encode(),b'')), self.assertRaises(BindingError):
                read_identity(123,1000)
        data=self.payload(); data['identity']['uid']=1001
        with patch('chip_relay.identity_reader.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(data).encode(),b'')), self.assertRaises(BindingError):
            read_identity(123,1000)

    def test_timeout_and_output_limit(self):
        with patch('chip_relay.identity_reader.subprocess.run',side_effect=subprocess.TimeoutExpired('probe',5)), self.assertRaises(BindingError):
            read_identity(123,1000)
        with patch('chip_relay.identity_reader.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'x'*65537,b'')), self.assertRaises(BindingError):
            read_identity(123,1000)

    def test_root_and_injected_arguments_rejected_without_execution(self):
        for pid,uid in [(123,0),('123;id',1000),(True,1000),(123,'1000')]:
            with patch('chip_relay.identity_reader.subprocess.run') as run, self.assertRaises(BindingError):
                read_identity(pid,uid)
            run.assert_not_called()
