#!/usr/bin/env python3
"""Explicit disposable-only swipe acceptance. Never opens a production account.

Uses an existing executable, a new private temporary profile, exact PID/port
binding and real input/readback. Closes only its owned fixture/browser/listener.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright
from chip_relay.binding import BindingError,process_identity,verify_binding
from chip_relay.config import BOUND_CONFIG,load_config
from chip_relay.humanize import humanize_page

HTML=b'''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="fixture-account" content="swipe-fixture"><style>html{scroll-behavior:auto}body{margin:0;width:6000px;height:60000px;background:repeating-linear-gradient(#eef 0px,#dde 99px,#000 100px)}button{position:fixed;top:4px;left:4px}</style><button id="control">No gesture here</button><input type="password" style="position:fixed;top:40px;left:4px"><iframe style="position:fixed;top:180px;left:4px;width:160px;height:120px" srcdoc="frame"></iframe><script>
window.probe={events:[],samples:[]};for(const type of ['touchstart','touchend','touchcancel','pointerdown','pointerup'])addEventListener(type,e=>probe.events.push({type,t:performance.now(),x:scrollX,y:scrollY,trusted:e.isTrusted}),{passive:true});
function sample(t){probe.samples.push({t,x:scrollX,y:scrollY});if(probe.samples.length>1800)probe.samples.shift();requestAnimationFrame(sample)}requestAnimationFrame(sample);
</script>'''

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(HTML)


def run(executable: str) -> dict:
    exe=Path(executable).resolve(strict=True)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    origin='http://127.0.0.1:'+str(server.server_port)
    process=None
    try:
        with tempfile.TemporaryDirectory(prefix='relay-swipe-live-',dir=os.environ.get('TMPDIR')) as work:
            root=Path(work);profile=root/'profile';profile.mkdir(mode=0o700)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            endpoint='http://127.0.0.1:'+str(port)
            with (root/'browser.log').open('w') as log:
                process=subprocess.Popen([str(exe),'--headless=new','--no-sandbox','--disable-dev-shm-usage','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-sync','--remote-debugging-address=127.0.0.1','--remote-debugging-port='+str(port),'--user-data-dir='+str(profile),'about:blank'],stdout=log,stderr=log,start_new_session=True)
                deadline=time.monotonic()+30
                while True:
                    assert process.poll() is None and time.monotonic()<deadline,'fixture_start_failed'
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.5):break
                    except OSError:time.sleep(.1)
                identity=process_identity(process.pid);info=profile.stat()
                entry=dict(lifecycle='external',endpoint=endpoint,uid=os.geteuid(),pid=process.pid,start_time=identity['start_time'],executable=str(exe),profile_path=str(profile),profile_inode=info.st_ino,profile_device=info.st_dev,profile_directory='Default',capabilities={})
                assert verify_binding(entry)['verified']
                config=replace(load_config(),external_binding=entry,cdp_url=endpoint,profile='swipe-fixture',profile_dir=profile)
                token=BOUND_CONFIG.set(config)
                try:
                    with sync_playwright() as pw:
                        browser=pw.chromium.connect_over_cdp(endpoint)
                        page=browser.contexts[0].new_page();other=browser.contexts[0].new_page()
                        page.goto(origin+'/fixture',wait_until='load');other.goto(origin+'/other',wait_until='load')
                        other.evaluate('scrollTo(0,1200)');other_y=other.evaluate('scrollY')
                        fingerprint='({touch:navigator.maxTouchPoints,ua:navigator.userAgent,width:innerWidth,height:innerHeight})'
                        before_settings=page.evaluate(fingerprint);before_other=other.evaluate(fingerprint)
                        identity_check=lambda:page.locator('meta[name="fixture-account"]').get_attribute('content')=='swipe-fixture'
                        receipts=[]
                        with humanize_page(page,expected_origin=origin,expected_account='swipe-fixture',identity_check=identity_check,mode='off') as human:
                            for inertia in [True,False,True]:
                                page.evaluate('scrollTo(0,5000);probe.events=[];probe.samples=[]');page.wait_for_timeout(150)
                                result=human.swipe(direction='up',distance=240,speed=1200,inertia=inertia,timeout=6000)
                                page.wait_for_timeout(250)
                                data=page.evaluate('probe');ends=[e for e in data['events'] if e['type']=='touchend'];assert len(ends)==1
                                end=ends[0];samples=[s for s in data['samples'] if s['t']>end['t']+30]
                                extra=max(s['y'] for s in samples)-end['y']
                                assert all(e['trusted'] for e in data['events'])
                                assert len([e for e in data['events'] if e['type']=='touchstart'])==1
                                assert not any(e['type']=='touchcancel' for e in data['events'])
                                assert data['samples'][-1]['y']>5100 and result['settled']
                                tail=[s['y'] for s in data['samples'][-8:]];assert max(tail)-min(tail)<=1
                                if inertia:assert extra>3 and result['inertia_observed'],('native_inertia_not_observed',extra,result)
                                else:assert extra<=3 and not result['inertia_observed'],('stationary_release_did_not_stop',extra,result)
                                assert other.evaluate('scrollY')==other_y
                                receipts.append(dict(result,measured_after_touchend_px=extra,trusted_events=True,stopped=True,other_page_unchanged=True))
                            page.evaluate('scrollTo(0,5000);probe.events=[];probe.samples=[]')
                            human.swipe(direction='down',distance=180,speed=1000,timeout=6000)
                            assert page.evaluate('scrollY')<4900
                            for horizontal in ['left','right']:
                                page.evaluate('scrollTo(1000,5000);probe.events=[];probe.samples=[]');page.wait_for_timeout(150)
                                moved=human.swipe(direction=horizontal,distance=180,speed=1000,inertia=False,y=page.evaluate('innerHeight*.8'),timeout=6000)
                                delta=moved['document_scroll_after']['x']-moved['document_scroll_before']['x']
                                assert delta>100 if horizontal=='left' else delta < -100
                            for target_y in [20,50,230]:
                                calls_before=len(page.evaluate('probe.events'))
                                try:human.swipe(x=30,y=target_y,distance=100,direction='down');raise AssertionError('unsafe_target_not_blocked')
                                except BindingError as e:assert str(e)=='swipe_unsafe_start_target'
                                assert len(page.evaluate('probe.events'))==calls_before
                            assert page.evaluate(fingerprint)==before_settings
                            assert other.evaluate(fingerprint)==before_other
                            completed=human.actions
                        try:human.swipe();raise AssertionError('closed_facade_not_blocked')
                        except BindingError as e:assert str(e)=='humanize_scope_closed'
                        # A wrong account callback cannot start another gesture.
                        try:
                            with humanize_page(page,expected_origin=origin,expected_account='other-account',identity_check=lambda:page.locator('meta[name="fixture-account"]').get_attribute('content')=='other-account'):
                                raise AssertionError('identity_guard_not_blocked')
                        except BindingError as e:assert str(e)=='humanize_live_account_identity_required'
                        for opted_mode in ['default','careful']:
                            page.evaluate('scrollTo(0,5000)');page.wait_for_timeout(100)
                            with humanize_page(page,expected_origin=origin,expected_account='swipe-fixture',identity_check=identity_check,mode=opted_mode) as opted:
                                proof=opted.swipe(direction='up',distance=180,speed=1000,inertia=False,timeout=6000)
                                assert proof['settled'] and proof['document_scroll_after']['y']>5100
                                assert opted.actions==1
                        assert page.evaluate(fingerprint)==before_settings
                        assert other.evaluate('scrollY')==other_y
                        # Run through the real bound task child too, with task state
                        # confined to this disposable fixture directory.
                        from chip_relay.workspace import init_run
                        from chip_relay.playwright_runner import run_final_script
                        child_config=replace(config,base_dir=root/'task-state',runs_dir=root/'task-runs',recipes_dir=root/'recipes')
                        workspace=init_run(child_config,'Swipe disposable acceptance',run_id='swipe-fixture-acceptance')
                        child_source='''import json,os
from playwright.sync_api import sync_playwright
from chip_relay.config import load_config
from chip_relay.humanize import humanize_page
cfg=load_config()
with sync_playwright() as pw:
    browser=pw.chromium.connect_over_cdp(cfg.cdp_url)
    page=next(p for ctx in browser.contexts for p in ctx.pages if p.url==ORIGIN+'/fixture')
    page.evaluate('scrollTo(0,5000)')
    with humanize_page(page,expected_origin=ORIGIN,expected_account='swipe-fixture',identity_check=lambda:page.locator('meta[name="fixture-account"]').get_attribute('content')=='swipe-fixture') as human:
        receipt=human.swipe(direction='up',distance=180,speed=1000,inertia=False,timeout=6000)
        assert receipt['settled'] and receipt['document_scroll_after']['y']>5100
        assert human.report()['completed_actions']==1
    print(json.dumps({'bound_task_child_swipe':True}))
'''
                        child_source='ORIGIN='+repr(origin)+'\n'+child_source
                        (workspace.run_dir/'scripts/final.py').write_text(child_source)
                        child_result=run_final_script(workspace.run_dir,config=child_config,timeout=30)
                        assert child_result.status=='ran',child_result.as_dict()
                        result={'fixture_only':True,'browser_version':browser.version,'backend':'cdp-native-touch','runs':receipts,'completed_gestures':completed,'sdk_modes_verified':['off','default','careful'],'bound_task_child_swipe':True,'reverse_direction_verified':True,'horizontal_directions_verified':True,'secret_and_iframe_start_denied':True,'interactive_start_denied':True,'closed_scope_denied':True,'wrong_account_denied':True,'device_settings_unchanged':True,'production_bindings_untouched':True}
                        other.close();page.close()
                finally:BOUND_CONFIG.reset(token)
                return result
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
        server.shutdown();server.server_close()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--executable',required=True);parser.add_argument('--fixture-only',action='store_true',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    result=run(args.executable)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
