from __future__ import annotations
import unittest
from unittest.mock import patch
from chip_relay.cdp_binding_probe import probe_cdp_binding

class Session:
    def __init__(self,page): self.page=page; self.callback=None; self.adds=0; self.detached=False
    def on(self,event,callback): self.callback=callback
    def send(self,method,args=None):
        if method=='Runtime.addBinding': self.page.exists=True; self.adds+=1
    def detach(self): self.detached=True

class Page:
    def __init__(self,persist=True,deliver=True):
        self.context=self; self.exists=False; self.persist=persist; self.deliver=deliver; self.session=Session(self)
    def goto(self,*args,**kw):
        if not self.persist: self.exists=False
    def reload(self,**kw): self.goto('reload')
    def new_cdp_session(self,page): return self.session
    def evaluate(self,expression,arg=None):
        if arg is None: return 'function' if self.exists else 'undefined'
        if self.deliver: self.session.callback({'name':'__relayCompatibilityBinding','payload':arg})
    def wait_for_timeout(self,ms): pass

class BindingProbeTests(unittest.TestCase):
    def probe(self,page): return probe_cdp_binding(page,'http://127.0.0.1:1234/clean','http://127.0.0.1:1234/init-script')
    def test_real_events_required_for_each_document(self):
        page=Page(); report=self.probe(page)
        self.assertEqual(report['status'],'passed'); self.assertEqual(page.session.adds,1)
        self.assertTrue(page.session.detached)
        self.assertTrue(all(s['function_available'] and s['event_received'] for s in report['stages']))
    def test_lost_binding_is_not_silently_reinstalled(self):
        page=Page(persist=False); report=self.probe(page)
        self.assertEqual(report['status'],'needs_attention'); self.assertEqual(page.session.adds,1)
        self.assertTrue(report['stages'][0]['event_received'])
        self.assertFalse(report['stages'][1]['function_available'])
        self.assertFalse(report['stages'][2]['event_received'])
        self.assertFalse(report['workaround_applied'])
    def test_function_without_delivery_is_not_a_pass(self):
        page=Page(deliver=False)
        with patch('chip_relay.cdp_binding_probe.time.monotonic',side_effect=range(100)):
            report=self.probe(page)
        self.assertEqual(report['status'],'needs_attention')
        self.assertTrue(all(s['function_available'] for s in report['stages']))
        self.assertFalse(any(s['event_received'] for s in report['stages']))
    def test_only_same_exact_local_fixture_allowed(self):
        for first,next_url in [('https://example.com/clean','http://127.0.0.1:1234/init-script'),
                               ('http://127.0.0.1:1234/clean','http://127.0.0.1:1235/init-script'),
                               ('http://u:p@127.0.0.1:1234/clean','http://127.0.0.1:1234/init-script')]:
            with self.assertRaises(ValueError): probe_cdp_binding(Page(),first,next_url)

if __name__=='__main__': unittest.main()
