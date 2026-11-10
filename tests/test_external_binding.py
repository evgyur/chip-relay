from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chip_relay import binding


class ExternalBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root/'browser-profile'; self.profile.mkdir()
        self.exe = self.root/'chrome'; self.exe.touch()
        st = self.profile.stat()
        self.entry = {'lifecycle':'external','endpoint':'http://127.0.0.1:19999',
                      'uid':os.geteuid(),'pid':123,'start_time':55,'executable':str(self.exe),
                      'profile_path':str(self.profile),'profile_directory':'Default',
                      'profile_inode':st.st_ino,'profile_device':st.st_dev}
        self.data = {'schema':'relay-external-binding-v1','profiles':{'fixture':self.entry},'aliases':{'main':'fixture'}}
        self.file = self.root/'binding.json'; self.save()
        self.proc = self.root/'proc'; (self.proc/'123/fd').mkdir(parents=True)
        (self.proc/'123/fd/7').symlink_to('socket:[567]')
        (self.proc/'net').mkdir()
        (self.proc/'net/tcp').write_text('header\n0: 0100007F:4E1F 00000000:0000 0A 0 0 0 0 0 567\n')
        (self.proc/'net/tcp6').write_text('header\n')
        self.identity = {'uid':os.geteuid(),'start_time':55,'executable':str(self.exe),
                         'args':[str(self.exe),'--remote-debugging-port=19999','--user-data-dir='+str(self.profile)]}

    def save(self):
        self.file.write_text(json.dumps(self.data)); self.file.chmod(0o600)




    def test_opt_in_owner_reader_still_checks_identity_and_listener(self):
        entry={**self.entry,'identity_reader':'sudo-owner-python3-v1'}
        receipt={'identity':self.identity,'sockets':['567']}
        with patch('chip_relay.identity_reader.read_identity',return_value=receipt):
            self.assertTrue(binding.verify_binding(entry,self.proc)['verified'])
        for bad in ({'identity':self.identity,'sockets':['999']},
                    {'identity':{**self.identity,'start_time':56},'sockets':['567']}):
            with patch('chip_relay.identity_reader.read_identity',return_value=bad), self.assertRaises(binding.BindingError):
                binding.verify_binding(entry,self.proc)




    def test_read_unknown_missing_alias_and_registry(self):
        data=binding.read_bindings(self.file)
        self.assertEqual(binding.select_binding(data,'main')[0],'fixture')
        for name in (None,'unknown'):
            with self.assertRaises(binding.BindingError): binding.select_binding(data,name)
        with self.assertRaises(FileNotFoundError): binding.read_bindings(self.root/'missing')

    def test_gui_process_does_not_need_own_process_group(self):
        with patch.object(binding,'process_identity',return_value=self.identity):
            self.assertTrue(binding.verify_binding(self.entry,self.proc)['verified'])

    def test_wrong_owner_reused_pid_and_executable(self):
        for key,value in [('uid',99999),('start_time',56),('executable','/wrong')]:
            bad={**self.identity,key:value}
            with self.subTest(key=key), patch.object(binding,'process_identity',return_value=bad), self.assertRaises(binding.BindingError):
                binding.verify_binding(self.entry,self.proc)

    def test_wrong_profile_and_profile_directory(self):
        for arg in ('--user-data-dir=/other','--profile-directory=Other'):
            bad=copy.deepcopy(self.identity)
            if arg.startswith('--user-data-dir'): bad['args']=bad['args'][:2]+[arg]
            else: bad['args'].append(arg)
            with self.subTest(arg=arg), patch.object(binding,'process_identity',return_value=bad), self.assertRaises(binding.BindingError):
                binding.verify_binding(self.entry,self.proc)

    def test_listener_socket_owned_by_other_process(self):
        (self.proc/'123/fd/7').unlink()
        with patch.object(binding,'process_identity',return_value=self.identity), self.assertRaisesRegex(binding.BindingError,'listener_owner'):
            binding.verify_binding(self.entry,self.proc)

    def test_listener_wildcard_rejected(self):
        (self.proc/'net/tcp').write_text('header\n0: 00000000:4E1F 00000000:0000 0A 0 0 0 0 0 567\n')
        with self.assertRaises(binding.BindingError): binding.listener_inodes(19999,self.proc)

    def test_missing_receipt_fields(self):
        for key in ('uid','pid','start_time','executable','profile_path','profile_inode','profile_directory'):
            bad={k:v for k,v in self.entry.items() if k!=key}
            with self.subTest(key=key), self.assertRaises(binding.BindingError): binding.validate_entry(bad)

    def test_binding_permissions_and_symlinks(self):
        self.file.chmod(0o644)
        with self.assertRaises(binding.BindingError): binding.read_bindings(self.file)
        self.file.chmod(0o600)
        link=self.root/'link'; link.symlink_to(self.file)
        with self.assertRaises(binding.BindingError): binding.read_bindings(link)
        link.unlink(); link.symlink_to(self.profile)
        with self.assertRaises(binding.BindingError): binding.canonical_path(str(link))








    def test_proc_flat_cmdline_and_generation(self):
        root=self.proc/'123'
        (root/'stat').write_text('123 (chrome gui) '+' '.join(['S']+['0']*18+['55']+['0']*3))
        (root/'cmdline').write_bytes(('chrome --remote-debugging-port=19999 --user-data-dir="'+str(self.profile)+'"\0').encode())
        (root/'exe').symlink_to(self.exe)
        actual=binding.process_identity(123,self.proc)
        self.assertEqual(actual['start_time'],55)
        self.assertEqual(binding.flag(actual['args'],'--user-data-dir'),str(self.profile))


if __name__ == '__main__': unittest.main()
