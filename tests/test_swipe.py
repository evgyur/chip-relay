"""Offline swipe contract tests; real compositor proof is a separate fixture."""
import asyncio
import time
import unittest
from unittest.mock import patch

from chip_relay.binding import BindingError
from chip_relay.swipe import geometry, swipe
from chip_relay.humanize import HumanInput


class Session:
    def __init__(self):
        self.calls=[];self.detached=False;self.fail_move=False;self.stall_move=False
    async def send(self,method,payload):
        self.calls.append((method,payload))
        if payload['type']=='touchMove':
            if self.fail_move:raise RuntimeError('native dispatch failed')
            if self.stall_move:await asyncio.sleep(2)
        return {}
    async def detach(self):self.detached=True


class Page:
    def __init__(self):
        self.session=Session();self._impl_obj=self;self.context=self
        self.main_frame=object();self.events={};self.positions=0;self.safe=True
        self.origin='http://127.0.0.1:12345';self.closed=False;self.foreground=0
    def on(self,name,callback):self.events[name]=callback
    def remove_listener(self,name,callback):self.events.pop(name,None)
    def is_closed(self):return self.closed
    def _sync(self,work):return asyncio.run(work)
    async def new_cdp_session(self,page):assert page is self;return self.session
    async def bring_to_front(self):self.foreground+=1
    async def evaluate(self,expression,arg=None):
        if 'width:innerWidth' in expression:return dict(width=1280,height=900,origin=self.origin)
        if 'elementFromPoint' in expression:return self.safe
        self.positions+=1
        return dict(x=0,y=min(250,max(0,(self.positions-1)*50)),t=self.positions*50)


class Human:
    def __init__(self):
        self.page=Page();self.expected_origin=self.page.origin;self.actions=0;self.guards=0;self.block=False
    _timeout=staticmethod(HumanInput._timeout)
    _remaining=staticmethod(HumanInput._remaining)
    def _page_guard(self):
        self.guards+=1
        if self.block:raise BindingError('fixture account/origin mismatch')


class SwipeTests(unittest.TestCase):
    def test_geometry_all_directions(self):
        for direction in ['up','down','left','right']:
            x,y,ex,ey=geometry(1280,900,direction,240,None,None)
            self.assertAlmostEqual(abs(ex-x)+abs(ey-y),240)
            self.assertTrue(16<=min(x,ex) and max(x,ex)<=1264)
            self.assertTrue(16<=min(y,ey) and max(y,ey)<=884)
    def test_invalid_geometry(self):
        for args in [(1280,900,'diagonal',240,None,None),(1280,900,'up',float('nan'),None,None),(1280,900,'up',True,None,None),(300,200,'up',240,None,None),(1280,900,'up',240,500,30)]:
            with self.subTest(args=args),self.assertRaises(BindingError):geometry(*args)
    def test_native_sequence_and_readback(self):
        h=Human();r=swipe(h,timeout=3000)
        calls=h.page.session.calls
        self.assertEqual(calls[0][1]['type'],'touchStart')
        self.assertEqual(calls[-1][1]['type'],'touchEnd')
        self.assertTrue(all(method=='Input.dispatchTouchEvent' for method,_ in calls))
        self.assertEqual(sum(p['type']=='touchStart' for _,p in calls),1)
        self.assertGreaterEqual(sum(p['type']=='touchMove' for _,p in calls),6)
        self.assertTrue(r['settled']);self.assertTrue(r['inertia_observed'])
        self.assertTrue(h.page.session.detached);self.assertFalse(h.page.events)
        self.assertEqual(h.actions,1);self.assertEqual(h.guards,2)
    def test_stationary_release_mode_is_explicit(self):
        h=Human();r=swipe(h,inertia=False,timeout=3000)
        self.assertFalse(r['inertia_requested']);self.assertEqual(r['backend'],'cdp-native-touch')
    def test_guard_denial_never_dispatches(self):
        h=Human();h.block=True
        with self.assertRaises(BindingError):swipe(h)
        self.assertEqual(h.page.session.calls,[])
    def test_preflight_expiry_never_dispatches(self):
        h=Human()
        h._page_guard=lambda:time.sleep(.015)
        with self.assertRaises(Exception):swipe(h,timeout=1)
        self.assertEqual(h.page.session.calls,[])
    def test_invalid_inputs_never_dispatch(self):
        for params in [dict(distance=0),dict(speed=float('inf')),dict(speed=True),dict(inertia='yes'),dict(timeout=0),dict(direction='other'),dict(distance=600,speed=200)]:
            h=Human()
            with self.subTest(params=params),self.assertRaises(BindingError):swipe(h,**params)
            self.assertEqual(h.page.session.calls,[])
    def test_iframe_or_interactive_start_rejected(self):
        h=Human();h.page.safe=False
        with self.assertRaisesRegex(BindingError,'unsafe_start'):swipe(h)
        self.assertEqual(h.page.session.calls,[]);self.assertFalse(h.page.events)
    def test_origin_rechecked_before_dispatch(self):
        h=Human();h.page.origin='https://other.example'
        with self.assertRaisesRegex(BindingError,'origin_mismatch'):swipe(h)
        self.assertEqual(h.page.session.calls,[])
    def test_failure_cancels_without_retry_or_fallback(self):
        h=Human();h.page.session.fail_move=True
        with self.assertRaisesRegex(RuntimeError,'native dispatch failed'):swipe(h)
        types=[p['type'] for _,p in h.page.session.calls]
        self.assertEqual(types,['touchStart','touchMove','touchCancel'])
        self.assertEqual(h.actions,0);self.assertFalse(h.page.events)
    def test_timeout_cancels_within_original_budget(self):
        h=Human();h.page.session.stall_move=True
        start=time.monotonic()
        with self.assertRaises(Exception):swipe(h,timeout=300)
        self.assertLess(time.monotonic()-start,.5)
        self.assertEqual(sum(p['type']=='touchStart' for _,p in h.page.session.calls),1)
        self.assertEqual(h.page.session.calls[-1][1]['type'],'touchCancel')
        self.assertFalse(h.page.events)
    def test_main_frame_navigation_stops_further_input(self):
        h=Human();original=h.page.session.send
        async def send(method,payload):
            result=await original(method,payload)
            if payload['type']=='touchStart':h.page.events['framenavigated'](h.page.main_frame)
            return result
        h.page.session.send=send
        with self.assertRaisesRegex(BindingError,'page_changed'):swipe(h)
        self.assertEqual([p['type'] for _,p in h.page.session.calls],['touchStart'])
        self.assertFalse(h.page.events)
    def test_facade_exposes_swipe(self):
        h=Human()
        with patch('chip_relay.swipe.swipe',return_value={'sentinel':True}) as backend:
            self.assertEqual(HumanInput.swipe(h,direction='down',inertia=False),{'sentinel':True})
        self.assertEqual(backend.call_args.kwargs['direction'],'down')
        self.assertFalse(backend.call_args.kwargs['inertia'])


if __name__=='__main__':unittest.main()
