"""Offline fixtures only. Any socket attempt fails the test process."""
import ast
import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rehearsal as r

NETWORK_EVENTS = []
def audit(event, args):
    if event.startswith('socket.'):
        NETWORK_EVENTS.append(event)
        raise RuntimeError('OFFLINE_TEST_NETWORK_FORBIDDEN')
sys.addaudithook(audit)

def page(key, rows=None, more=False, cursor=None):
    return {key: [] if rows is None else rows,
            'pagination': {'hasNextPage': more, 'nextCursor': cursor}}

class Clock:
    def __init__(self): self.now = 0
    def mono(self): return self.now
    def sleep(self, seconds): self.now += seconds

class Tests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.calls = []
        self.env = dict(CONTROLLER_REPOSITORY='example/watchdog',
                        REVIEWED_REHEARSAL_COMMIT='a'*40, GITHUB_SHA='a'*40,
                        GITHUB_REPOSITORY='example/watchdog', GITHUB_REF='refs/heads/main',
                        GITHUB_EVENT_NAME='workflow_dispatch',
                        REHEARSAL_AUTHORIZATION=r.AUTHORIZATION)
    def transport(self, path, cursor, token, timeout):
        self.calls.append((path, cursor, timeout))
        return page(dict(r.CATEGORIES.values())[path])
    def test_context_valid_without_paid_policy(self): r.verify_context(self.env)
    def test_context_missing_each_field(self):
        for key in self.env:
            env = dict(self.env); env.pop(key)
            with self.subTest(key=key), self.assertRaises(r.Stop): r.verify_context(env)
    def test_context_wrong_each_field(self):
        for key in self.env:
            env = dict(self.env); env[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(r.Stop): r.verify_context(env)
    def test_no_production_lock_dependency(self):
        source = pathlib.Path(r.__file__).read_text()
        for name in ('policy-lock', 'POLICY_APPROVED', 'POLICY_RISK_ACCEPTED', 'terminate_trial', 'TRIAL_RUNPOD_TOKEN'):
            self.assertNotIn(name, source)
    def test_all_six(self):
        r.empty_inventory('dummy', 120, self.transport, self.clock.mono)
        self.assertEqual([x[0] for x in self.calls], [x[0] for x in r.CATEGORIES.values()])
    def test_every_category_stops_on_first_resource(self):
        for category, (target, key) in r.CATEGORIES.items():
            calls = []
            def transport(path, cursor, token, timeout):
                calls.append(path)
                return page(dict(r.CATEGORIES.values())[path], [{'private': 'do-not-log'}] if path == target else [])
            with self.subTest(category=category), self.assertRaises(r.Stop):
                r.empty_inventory('dummy', 120, transport, self.clock.mono)
            self.assertEqual(calls[-1], target)
    def test_pagination_complete(self):
        calls = []
        def transport(path, cursor, token, timeout):
            calls.append((path,cursor)); key = dict(r.CATEGORIES.values())[path]
            return page(key, more=cursor is None, cursor='next' if cursor is None else None)
        r.empty_inventory('dummy',120,transport,self.clock.mono)
        self.assertEqual(len(calls),12)
    def test_resource_on_later_page(self):
        def transport(path,cursor,token,timeout):
            return page('pods', rows=[{}] if cursor else [], more=cursor is None, cursor='next' if cursor is None else None)
        with self.assertRaises(r.Stop): r.empty_inventory('dummy',120,transport,self.clock.mono)
    def test_repeated_cursor(self):
        with self.assertRaises(r.Stop):
            r.empty_inventory('dummy',120,lambda *a:page('pods',more=True,cursor='same'),self.clock.mono)
    def test_malformed_inventory(self):
        for value in (None, [], {}, {'pods': None}, {'pods': [], 'pagination': {}}, page('pods',more=1), page('pods',cursor='unexpected'), page('pods',more=True,cursor='')):
            with self.subTest(value=value), self.assertRaises(r.Stop):
                r.empty_inventory('dummy',120,lambda *a:value,self.clock.mono)
    def test_page_limit(self):
        count = [0]
        def transport(*args):
            count[0] += 1
            return page('pods',more=True,cursor=str(count[0]))
        with self.assertRaises(r.Stop): r.empty_inventory('dummy',120,transport,self.clock.mono)
        self.assertEqual(count[0],100)
    def test_expired_budget_no_request(self):
        with self.assertRaises(r.Stop): r.empty_inventory('dummy',0,self.transport,self.clock.mono)
        self.assertEqual(self.calls,[])
    def test_late_response_rejected(self):
        def transport(*args): self.clock.now=121; return page('pods')
        with self.assertRaises(r.Stop): r.empty_inventory('dummy',120,transport,self.clock.mono)
    def test_ten_minutes_and_final_six(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out): r.observe('dummy',self.transport,self.clock.mono,self.clock.sleep)
        self.assertEqual(self.clock.now,600)
        events=[json.loads(line)['event'] for line in out.getvalue().splitlines()]
        self.assertEqual(events[0],'READY_EMPTY_ACCOUNT')
        self.assertEqual(events[-1],'EMPTY_OBSERVATION_COMPLETE')
        self.assertEqual([x[0] for x in self.calls[-6:]],[x[0] for x in r.CATEGORIES.values()])
        self.assertLessEqual(len(events),41)
    def test_new_resource_during_observation(self):
        def transport(path,cursor,token,timeout):
            return page(dict(r.CATEGORIES.values())[path], [{}] if self.clock.now>=15 else [])
        out=io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(r.Stop):
            r.observe('dummy',transport,self.clock.mono,self.clock.sleep)
        self.assertEqual(self.clock.now,15)
        self.assertNotIn('COMPLETE',out.getvalue())
    def test_final_inventory_failure_no_success(self):
        def transport(path,cursor,token,timeout):
            if self.clock.now>=600: raise r.Stop()
            return self.transport(path,cursor,token,timeout)
        out=io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(r.Stop):
            r.observe('dummy',transport,self.clock.mono,self.clock.sleep)
        self.assertNotIn('COMPLETE',out.getvalue())
    def test_transport_error_not_retried(self):
        count=[0]
        def transport(*args): count[0]+=1; raise r.Stop('private-provider-body')
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(r.Stop): r.observe('dummy',transport,self.clock.mono,self.clock.sleep)
        self.assertEqual(count[0],1)
    def test_strict_json(self):
        for raw in ('{"a":1,"a":2}','NaN','Infinity','broken'):
            with self.subTest(raw=raw),self.assertRaises(r.Stop): r.strict_json(raw)
    def test_bad_paths_never_open(self):
        for path in ('https://evil.invalid','/pods/id12345','/pods?cursor=x','/pods/../secrets','//evil.invalid'):
            with patch.object(r.urllib.request,'build_opener') as opener,self.subTest(path=path),self.assertRaises(r.Stop):
                r.get_collection(path,None,'dummy',15)
            opener.assert_not_called()
    def test_bad_tokens_never_open(self):
        for token in (None,'','a\nb','a b','x'*4097):
            with patch.object(r.urllib.request,'build_opener') as opener,self.subTest(token=token),self.assertRaises(r.Stop):
                r.get_collection('/pods',None,token,15)
            opener.assert_not_called()
    def test_only_get_request_and_fixed_origin(self):
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def read(self,n): return b'{"pods":[],"pagination":{"hasNextPage":false,"nextCursor":null}}'
        with patch.object(r.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value=Response()
            r.get_collection('/pods','https://evil.invalid','dummy',15)
            request=opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_method(),'GET')
            self.assertTrue(request.full_url.startswith(r.BASE+'/pods?cursor='))
            self.assertIsNone(request.data)
            self.assertIsInstance(opener.call_args.args[0],r.urllib.request.ProxyHandler)
            self.assertEqual(opener.call_args.args[0].proxies,{})
            self.assertIsInstance(opener.call_args.args[1],r.NoRedirect)
    def test_redirect_refused(self):
        self.assertIsNone(r.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.invalid'))
    def test_bad_transport_responses(self):
        class Response:
            def __init__(self,status,raw): self.status=status; self.raw=raw
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,n): return self.raw
        for status,raw in ((302,b'private'),(401,b'private'),(403,b'private'),(500,b'private'),(204,b''),(200,b'x'*1048577),(200,b'\xff'),(200,b'NaN'),(200,b'{"x":1,"x":2}')):
            with self.subTest(status=status,size=len(raw)),patch.object(r.urllib.request,'build_opener') as opener:
                opener.return_value.open.return_value=Response(status,raw)
                with self.assertRaises(r.Stop): r.get_collection('/pods',None,'dummy',15)
    def test_transport_exception_sanitised(self):
        with patch.object(r.urllib.request,'build_opener') as opener:
            opener.return_value.open.side_effect=Exception('PRIVATE_CANARY')
            with self.assertRaises(r.Stop) as caught: r.get_collection('/pods',None,'dummy',15)
            self.assertEqual(str(caught.exception),'')
    def test_bad_cursor_and_timeout(self):
        for cursor,timeout in (('',15),('x'*257,15),(123,15),(None,0),(None,16)):
            with self.subTest(cursor=cursor,timeout=timeout),self.assertRaises(r.Stop):
                r.get_collection('/pods',cursor,'dummy',timeout)
    def test_nonempty_first_page_never_follows_cursor(self):
        count=[0]
        def transport(*args): count[0]+=1; return page('pods',[{}],True,'next')
        with self.assertRaises(r.Stop): r.empty_inventory('dummy',120,transport,self.clock.mono)
        self.assertEqual(count[0],1)
    def test_error_output_sanitised(self):
        env=dict(self.env,REHEARSAL_RUNPOD_TOKEN='PRIVATE_CANARY')
        for error in (Exception('PRIVATE_CANARY'),KeyboardInterrupt(),SystemExit(3)):
            out=io.StringIO()
            with patch.object(sys,'argv',['rehearsal.py']),patch.object(r,'observe',side_effect=error),contextlib.redirect_stdout(out):
                self.assertEqual(r.main(env),1)
            self.assertEqual(out.getvalue(),'{"event": "STOP"}\n')
    def test_context_before_token_transport(self):
        with patch.object(sys,'argv',['rehearsal.py']),patch.object(r,'observe') as observe,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main({}),1)
        observe.assert_not_called()
    def test_missing_token(self):
        with patch.object(sys,'argv',['rehearsal.py']),patch.object(r,'observe') as observe,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main(self.env),1)
        observe.assert_not_called()
    def test_no_cli_overrides(self):
        with patch.object(sys,'argv',['rehearsal.py','watch']),patch.object(r,'observe') as observe,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main(self.env),1)
        observe.assert_not_called()
    def test_emit_allowlist(self):
        with self.assertRaises(r.Stop): r.emit('PRIVATE_CANARY')
    def test_no_mutation_or_execution_imports(self):
        tree=ast.parse(pathlib.Path(r.__file__).read_text())
        modules={alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names}
        self.assertNotIn('subprocess',modules)
        requests=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='Request']
        self.assertEqual(len(requests),1)
        self.assertEqual(next(k.value.value for k in requests[0].keywords if k.arg=='method'),'GET')
    def test_workflow_boundary(self):
        text=(pathlib.Path(r.__file__).parent/'.github/workflows/rehearsal.yml').read_text()
        self.assertEqual(text.count('secrets.'),1)
        for value in ('environment: watchdog-approval','timeout-minutes: 15','persist-credentials: false','REVIEWED_REHEARSAL_COMMIT','group: gpu-trial-watchdog','cancel-in-progress: false'):
            self.assertIn(value,text)
        for value in ('pull_request:','push:','schedule:','POLICY_','TRIAL_RUNPOD_TOKEN:'):
            self.assertNotIn(value,text)
    def test_no_socket_activity(self): self.assertEqual(NETWORK_EVENTS,[])

if __name__=='__main__':
    unittest.main(verbosity=2)
