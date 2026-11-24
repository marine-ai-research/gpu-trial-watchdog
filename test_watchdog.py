"""Offline tests only: fake transports, fake clocks and fictional policy."""
import sys,pathlib
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import copy,contextlib,datetime,hashlib,io,json,os,unittest,urllib.error
from unittest.mock import patch
import controller as c
import terminate_trial as t
import reconcile_resources as r
KEY='TEST_CREDENTIAL_DO_NOT_LOG'
def policy():return dict(approved=True,billing_mode='prepaid',auto_pay_disabled=True,risk_or_contract_approval=True,name='gpu-trial-000000000001',image='example.invalid/container@sha256:'+'0'*64,gpu_type='NVIDIA L40S',gpu_count=1,container_disk_gb=50,data_center_id='EU-TEST-1',quoted_hourly_usd=1.1,startup_sha256=c.startup_fingerprint(['/usr/bin/python3','-I','-B','-c'],['import time; time.sleep(6600)']))
def lock(p):return {'sha256':hashlib.sha256(c.canonical(p)).hexdigest()}
def pod():
 p=policy();return dict(id='pod_test123',name=p['name'],createdAt='2026-01-01T00:00:00Z',image=p['image'],cloud='SECURE',dataCenterId=p['data_center_id'],disk=50,ports=[],mounts={},gpu={'id':p['gpu_type'],'count':1},cost=1.1,globalNetworking={'enabled':False},entrypoint=['/usr/bin/python3','-I','-B','-c'],cmd=['import time; time.sleep(6600)'],runtime=None,args=json.dumps({'entrypoint':['/usr/bin/python3','-I','-B','-c'],'cmd':['import time; time.sleep(6600)']}))
NOW=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc).timestamp()
class Clock:
 def __init__(self):self.v=NOW
 def time(self):return self.v
 def mono(self):return self.v-NOW
 def sleep(self,n):self.v+=n
class Tests(unittest.TestCase):
 def test_policy_accepts_only_hash_locked(self):self.assertEqual(policy(),c.load_policy(json.dumps(policy()),lock(policy())))
 def test_unconfigured_lock_stops(self):
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(policy()),{'sha256':None})
 def test_changed_policy_stops(self):
  p=policy();p['name']='gpu-trial-000000000002'
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(p),lock(policy()))
 def test_all_required_approvals(self):
  for k in ['approved','auto_pay_disabled','risk_or_contract_approval']:
   p=policy();p[k]=False
   with self.subTest(k=k),self.assertRaises(t.Stop):c.load_policy(json.dumps(p),lock(p))
 def test_postpaid_rejected(self):
  p=policy();p['billing_mode']='postpaid'
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(p),lock(p))
 def test_invalid_policy_fields(self):
  for k,v in [('image','latest'),('gpu_count',2),('gpu_count',True),('container_disk_gb',51),('quoted_hourly_usd',float('inf')),('quoted_hourly_usd',True),('quoted_hourly_usd',3),('data_center_id',None),('name','bad name')]:
   p=policy();p[k]=v
   with self.subTest(k=k,v=repr(v)),self.assertRaises((t.Stop,ValueError)):c.load_policy(json.dumps(p),lock(p))
 def test_unknown_policy_field_rejected(self):
  p=policy();p['command']='arbitrary'
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(p),lock(p))
 def test_duplicate_json(self):
  with self.assertRaises(t.Stop):t.strict_json('{"a":1,"a":2}')
 def test_nonfinite_json(self):
  with self.assertRaises(t.Stop):t.strict_json('{"a":NaN}')
 def test_individual_environment_policy(self):
  p=policy();e={'POLICY_APPROVED':'true','POLICY_BILLING_MODE':'prepaid','POLICY_AUTO_PAY_DISABLED':'true','POLICY_RISK_ACCEPTED':'true','POLICY_NAME':p['name'],'POLICY_IMAGE':p['image'],'POLICY_DATA_CENTER':p['data_center_id'],'POLICY_GPU_TYPE':p['gpu_type'],'POLICY_MAX_HOURLY_USD':'1.1','POLICY_GPU_COUNT':'1','POLICY_CONTAINER_DISK_GB':'50','POLICY_STARTUP_SHA256':p['startup_sha256']}
  self.assertEqual(p,c.policy_from_environment(e,lock(p)))
  e['POLICY_APPROVED']='yes'
  with self.assertRaises(t.Stop):c.policy_from_environment(e,lock(p))
 def test_missing_environment_policy_stops(self):
  with self.assertRaises(t.Stop):c.policy_from_environment({},lock(policy()))
 def test_identity_and_expiry(self):
  receipt,valid=c.bind(policy(),pod(),NOW,NOW)
  self.assertTrue(valid);self.assertEqual(receipt['deadline_unix']-receipt['created_unix'],6300)
 def test_wrong_name_cannot_bind(self):
  p=pod();p['name']='unrelated'
  with self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_invalid_id_cannot_bind(self):
  p=pod();p['id']='../other'
  with self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_bad_creation_metadata(self):
  for value in ['not-a-date','2026-01-01T00:00:00','2026-01-01T00:00:01Z','2025-01-01T00:00:00Z']:
   p=pod();p['createdAt']=value
   with self.subTest(value=value),self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_initial_mismatch_never_creates_receipt(self):
  variants=[('ports',['22/tcp']),('image','changed'),('cloud','COMMUNITY'),('dataCenterId','EU-OTHER'),('mounts',{'persistent':{'size':1}}),('disk',49),('cost',2),('globalNetworking',{'enabled':True}),('gpu',{'id':'other','count':1})]
  for k,v in variants:
   p=pod();p[k]=v
   with self.subTest(k=k),self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_same_name_mismatch_never_deletes_in_watch(self):
  for field,value in [('ports',['22/tcp']),('image','changed'),('cloud','COMMUNITY'),('dataCenterId','EU-OTHER'),('gpu',{'id':'other','count':1}),('mounts',{'persistent':{'size':1}}),('cost',2),('disk',49),('globalNetworking',{'enabled':True})]:
   clock=Clock();phase={'lists':0};calls=[]
   def tx(method,path,token,**kw):
    calls.append((method,path))
    if method=='DELETE':self.fail('unauthorised DELETE')
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':phase['lists']+=1
    candidate=pod();candidate[field]=value
    return 200,{key:[candidate]if path=='/pods'and phase['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   with self.subTest(field=field),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
   self.assertFalse(any(method=='DELETE'for method,path in calls))
 def test_receipt_cannot_extend_deadline(self):
  receipt,_=c.bind(policy(),pod(),NOW,NOW);receipt['deadline_unix']+=1
  with self.assertRaises(t.Stop):t.validate_receipt(receipt,NOW)
 def test_receipt_no_persistent_volume(self):
  receipt,_=c.bind(policy(),pod(),NOW,NOW);receipt['persistent_disk_gb']=1
  with self.assertRaises(t.Stop):t.validate_receipt(receipt,NOW)
 def test_exact_delete_and_absence(self):
  clock=Clock();calls=[];receipt,_=c.bind(policy(),pod(),NOW,NOW)
  def transport(method,path,token,**kw):calls.append((method,path));return (204,None)if method=='DELETE'else(404,None)
  self.assertTrue(t.terminate(receipt,KEY,transport,clock.time,clock.sleep,clock.mono));self.assertEqual(calls,[('DELETE','/pods/pod_test123'),('GET','/pods/pod_test123')])
 def test_termination_bounded_failure(self):
  clock=Clock();calls=[];receipt,_=c.bind(policy(),pod(),NOW,NOW)
  def transport(*args,**kw):calls.append(args);raise RuntimeError(KEY)
  with self.assertRaises(t.Stop):t.terminate(receipt,KEY,transport,clock.time,clock.sleep,clock.mono)
  self.assertEqual(3,len(calls))
 def test_nonabsence_never_success(self):
  clock=Clock();receipt,_=c.bind(policy(),pod(),NOW,NOW)
  with self.assertRaises(t.Stop):t.terminate(receipt,KEY,lambda *a,**k:(200,{}),clock.time,clock.sleep,clock.mono)
 def test_transport_forbids_creation_and_other_origins(self):
  for method,path in [('POST','/pods'),('DELETE','/pods'),('GET','https://other.invalid'),('GET','//other.invalid'),('GET','/pods/../../else'),('GET','/account'),('GET','/pods/pod_test123?cursor=a')]:
   with self.subTest(method=method,path=path),self.assertRaises(t.Stop):t.request(method,path,KEY)
 def test_redirect_never_forwards_authorization(self):
  self.assertIsNone(t.NoRedirect().redirect_request(None,None,302,'',{},'https://other.invalid'))
 def test_network_exception_not_echoed(self):
  with patch.object(t.OPENER,'open',side_effect=RuntimeError(KEY+' private data')):
   with self.assertRaises(t.Stop)as cm:t.request('GET','/pods',KEY)
  self.assertNotIn(KEY,str(cm.exception));self.assertEqual('API_UNAVAILABLE',str(cm.exception))
 def test_http_error_body_not_echoed(self):
  error=urllib.error.HTTPError('https://api.runpod.io/v2/pods',403,KEY,{},io.BytesIO(KEY.encode()))
  with patch.object(t.OPENER,'open',side_effect=error):
   with self.assertRaises(t.Stop)as cm:t.request('GET','/pods',KEY)
  self.assertEqual('API_UNAVAILABLE',str(cm.exception))
 def test_pagination_complete(self):
  calls=[]
  def tx(method,path,token,**kw):calls.append(path);return(200,{'pods':[{}],'pagination':{'hasNextPage':len(calls)==1,'nextCursor':'next'if len(calls)==1 else None}})
  self.assertEqual(2,len(r.listing('/pods','pods',KEY,tx)));self.assertEqual(['/pods','/pods?cursor=next'],calls)
 def test_repeated_cursor_stops(self):
  with self.assertRaises(t.Stop):r.listing('/pods','pods',KEY,lambda *a,**k:(200,{'pods':[],'pagination':{'hasNextPage':True,'nextCursor':'repeat'}}))
 def test_missing_pagination_stops(self):
  with self.assertRaises(t.Stop):r.listing('/pods','pods',KEY,lambda *a,**k:(200,{'pods':[]}))
 def test_absent_cursor_does_not_prove_empty_inventory(self):
  with self.assertRaises(t.Stop):r.listing('/pods','pods',KEY,lambda *a,**k:(200,{'pods':[],'pagination':{'hasNextPage':False}}))
 def test_schema_mismatch_stops(self):
  with self.assertRaises(t.Stop):r.listing('/pods','pods',KEY,lambda *a,**k:(200,{'pods':'bad'}))
 def test_inventory_deadline(self):
  with self.assertRaises(t.Stop):r.listing('/pods','pods',KEY,lambda *a,**k:self.fail('network attempted'),mono=lambda:1,deadline=0)
 def test_full_empty_account_rehearsal(self):
  clock=Clock();calls=[]
  def tx(method,path,token,**kw):
   calls.append(method);key=dict(r.CATEGORIES.values())[path.split('?')[0]];return 200,{key:[],'pagination':{'hasNextPage':False,'nextCursor':None}}
  out=io.StringIO()
  with contextlib.redirect_stdout(out):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertNotIn('DELETE',calls);self.assertIn('NO_RESOURCE_CREATED',out.getvalue());self.assertNotIn(KEY,out.getvalue());self.assertLessEqual(clock.mono(),600)
 def test_watch_deadline_and_reconciliation(self):
  clock=Clock();calls=[];pod_lists=0
  def tx(method,path,token,**kw):
   nonlocal pod_lists
   calls.append((method,path,clock.mono()))
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':pod_lists+=1
    rows=[pod()]if path=='/pods'and pod_lists==2 else []
    return 200,{key:rows,'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':return 204,None
   if any(m=='DELETE'for m,_,_ in calls):return 404,None
   return 200,pod()
  out=io.StringIO()
  with contextlib.redirect_stdout(out):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  deletes=[v for v in calls if v[0]=='DELETE'];self.assertEqual(1,len(deletes));self.assertEqual(6300,deletes[0][2]);self.assertIn('TARGET_ABSENT',out.getvalue());self.assertNotIn('pod_test123',out.getvalue());self.assertNotIn(KEY,out.getvalue())
 def test_bound_api_failure_attempts_exact_cleanup(self):
  clock=Clock();phase={'lists':0,'deleted':False};calls=[]
  def tx(method,path,token,**kw):
   calls.append((method,path))
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':phase['lists']+=1
    return 200,{key:[pod()]if path=='/pods'and phase['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':phase['deleted']=True;return 204,None
   if phase['deleted']:return 404,None
   raise t.Stop('API_UNAVAILABLE')
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertIn(('DELETE','/pods/pod_test123'),calls)
 def test_policy_drift_terminates_early(self):
  clock=Clock();phase={'lists':0,'deleted':False};calls=[]
  def tx(method,path,token,**kw):
   calls.append((method,path,clock.mono()))
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':phase['lists']+=1
    return 200,{key:[pod()]if path=='/pods'and phase['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':phase['deleted']=True;return 204,None
   if phase['deleted']:return 404,None
   changed=pod();changed['ports']=['22/tcp'];return 200,changed
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertEqual(0,next(at for method,path,at in calls if method=='DELETE'))
 def test_interruption_after_binding_attempts_cleanup(self):
  clock=Clock();phase={'lists':0,'deleted':False}
  def tx(method,path,token,**kw):
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':phase['lists']+=1
    return 200,{key:[pod()]if path=='/pods'and phase['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':phase['deleted']=True;return 204,None
   if phase['deleted']:return 404,None
   raise KeyboardInterrupt()
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(KeyboardInterrupt):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertTrue(phase['deleted'])
 def test_unrelated_resource_is_count_only_and_never_deleted(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):c.emit('RECONCILIATION',dict(pods=1,queued=0,network_volumes=0,global_volumes=0,serverless=0,clusters=0))
  self.assertNotIn(KEY,out.getvalue());self.assertIn('"all_billable_resources_verified": false',out.getvalue())
 def test_backward_clock_cannot_prevent_exact_cleanup(self):
  clock=Clock();phase={'lists':0,'deleted':False,'skew':0}
  def wall():return clock.time()+phase['skew']
  def tx(method,path,token,**kw):
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':phase['lists']+=1
    return 200,{key:[pod()]if path=='/pods'and phase['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':phase['deleted']=True;return 204,None
   if phase['deleted']:return 404,None
   phase['skew']=-30;return 200,pod()
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,wall,clock.mono,clock.sleep)
  self.assertTrue(phase['deleted']);self.assertLess(clock.mono(),6300)
 def test_wrong_initial_account_never_deletes(self):
  def tx(method,path,token,**kw):
   key=dict(r.CATEGORIES.values())[path];return 200,{key:[{}]if path=='/pods'else[],'pagination':{'hasNextPage':False,'nextCursor':None}}
  with self.assertRaises(t.Stop):c.watch(policy(),KEY,tx)
 def test_final_error_output_sanitized(self):
  env={'CONTROLLER_REPOSITORY':'example/gpu-trial-watchdog','REVIEWED_CONTROLLER_COMMIT':'1'*40,'GITHUB_REPOSITORY':'example/gpu-trial-watchdog','GITHUB_SHA':'1'*40,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
  out=io.StringIO();err=io.StringIO()
  with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',['controller.py','watch']),patch.object(c,'policy_from_environment',side_effect=RuntimeError(KEY+' private-value')),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):result=c.main()
  self.assertEqual(1,result);self.assertEqual('{"event": "STOP"}\n',out.getvalue());self.assertEqual('',err.getvalue())
 def test_actual_isolated_entrypoint_without_credentials(self):
  import subprocess
  root=pathlib.Path(__file__).resolve().parent
  result=subprocess.run([sys.executable,'-I','-B',str(root/'controller.py'),'inventory'],env={},capture_output=True,text=True,timeout=10)
  self.assertEqual(1,result.returncode);self.assertEqual('{"event": "STOP"}\n',result.stdout);self.assertEqual('',result.stderr)
 def test_workflow_context(self):
  e={'CONTROLLER_REPOSITORY':'example/gpu-trial-watchdog','REVIEWED_CONTROLLER_COMMIT':'1'*40,'GITHUB_REPOSITORY':'example/gpu-trial-watchdog','GITHUB_SHA':'1'*40,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
  c.verify_context(e)
  for k,v in [('GITHUB_REPOSITORY','other/fork'),('GITHUB_SHA','2'*40),('GITHUB_REF','refs/heads/untrusted'),('GITHUB_EVENT_NAME','pull_request_target')]:
   changed=dict(e);changed[k]=v
   with self.subTest(k=k),self.assertRaises(t.Stop):c.verify_context(changed)
 def test_workflow_static_guards(self):
  root=pathlib.Path(__file__).resolve().parent
  for name in ['watchdog.yml','validate.yml']:
   text=(root/'.github/workflows'/name).read_text()
   self.assertIn("github.repository == vars.CONTROLLER_REPOSITORY",text);self.assertIn("github.sha == vars.REVIEWED_CONTROLLER_COMMIT",text);self.assertIn("github.ref == 'refs/heads/main'",text);self.assertNotIn('pull_request',text);self.assertNotIn('schedule:',text);self.assertNotIn('id-token:',text)
  watcher=(root/'.github/workflows/watchdog.yml').read_text();validator=(root/'.github/workflows/validate.yml').read_text()
  self.assertIn('environment: watchdog-approval',watcher);self.assertIn('cancel-in-progress: false',watcher);self.assertNotIn('secrets.',validator);self.assertNotIn('environment:',validator)
 def test_documentation_derived_response_fixtures(self):
  root=pathlib.Path(__file__).resolve().parent
  f=json.loads((root/'fixtures/api-shapes.json').read_text())
  self.assertEqual('Documentation-derived fictional responses; not captured from a live account',f['fixture_kind'])
  receipt,ok=c.bind(policy(),f['get_pod'],NOW,NOW);self.assertTrue(ok)
  def tx(method,path,token,**kw):
   key=dict(r.CATEGORIES.values())[path];return 200,f['empty_collections'][key]
  self.assertEqual(dict.fromkeys(r.CATEGORIES,0),r.inventory(KEY,tx))
 def test_missing_security_metadata_is_not_authorised(self):
  for field in ['image','ports','mounts','gpu','cloud','dataCenterId','disk','cost','globalNetworking']:
   p=pod();del p[field]
   with self.subTest(field=field),self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_empty_looking_mount_variants_abstain(self):
  for value in [None,{'persistent':None},{'network':[]},[],False]:
   p=pod();p['mounts']=value
   with self.subTest(value=value),self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_missing_or_changed_startup_never_authorises_delete(self):
  cases=[('args','/bin/sh -c other'),('args',None),('args','{"entrypoint":["/wrong"],"cmd":[]}'),('entrypoint',None),('cmd',None),('entrypoint',[]),('entrypoint','/usr/bin/python3'),('cmd','import time; time.sleep(6600)'),('entrypoint',['/bin/sh','-c']),('cmd',['import time;time.sleep(6600)']),('cmd',[]),('cmd',['import time; time.sleep(6600)','extra'])]
  for field,value in cases+ [('entrypoint','MISSING'),('cmd','MISSING'),('args','MISSING')]:
   clock=Clock();lists=[0];calls=[];out=io.StringIO()
   def tx(method,path,token,**kw):
    calls.append((method,path))
    if method=='DELETE':self.fail('startup mismatch granted DELETE')
    key=dict(r.CATEGORIES.values())[path]
    if path=='/pods':lists[0]+=1
    candidate=pod()
    if value=='MISSING':candidate.pop(field)
    else:candidate[field]=value
    return 200,{key:[candidate]if path=='/pods'and lists[0]==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
   with self.subTest(field=field,value=value),contextlib.redirect_stdout(out),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
   self.assertFalse(any(m=='DELETE'for m,p in calls));self.assertNotIn('TARGET_BOUND',out.getvalue())
 def test_postauthorisation_startup_creation_and_mapping_drift_cleans_original_id(self):
  for field,value in [('entrypoint',['/bin/sh']),('cmd',None),('cmd',['different']),('args','contradictory'),('createdAt','2026-01-01T00:00:01Z'),('runtime',{'ports':[{'private':22}]}),('id','pod_other123')]:
   clock=Clock();state={'lists':0,'deleted':False};calls=[]
   def tx(method,path,token,**kw):
    calls.append((method,path,clock.mono()))
    if path in dict(r.CATEGORIES.values()):
     key=dict(r.CATEGORIES.values())[path]
     if path=='/pods':state['lists']+=1
     return 200,{key:[pod()]if path=='/pods'and state['lists']==2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
    if method=='DELETE':state['deleted']=True;return 204,None
    if state['deleted']:return 404,None
    changed=pod();changed[field]=value;return 200,changed
   with self.subTest(field=field),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
   self.assertEqual([('DELETE','/pods/pod_test123')],[(m,p)for m,p,at in calls if m=='DELETE'])
 def test_startup_hash_is_exact_and_policy_locked(self):
  p=policy();changed=dict(p);changed['startup_sha256']='f'*64
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(changed),lock(p))
  self.assertNotEqual(c.startup_fingerprint(['/x'],[]),c.startup_fingerprint(['/x'],['']))
  for a,b in [(None,[]),([],[]),(['/x'],None),(['/x'],'text'),(['/x'],[True]),(['/x'],['\x00']),(['/x'],['a']*256)]:
   with self.subTest(a=a,b=b),self.assertRaises(t.Stop):c.startup_fingerprint(a,b)
 def test_missing_runtime_or_known_initial_mappings_rejected(self):
  for value in ['MISSING',{}, {'ports':None},{'ports':[{'private':22}]}]:
   p=pod()
   if value=='MISSING':del p['runtime']
   else:p['runtime']=value
   with self.subTest(value=value),self.assertRaises(t.Stop):c.bind(policy(),p,NOW,NOW)
 def test_log_only_whitelisted_shapes(self):
  with self.assertRaises(t.Stop):c.emit(KEY)
  with self.assertRaises(t.Stop):c.emit('RECONCILIATION',{'private':KEY})
if __name__=='__main__':unittest.main(verbosity=2)
