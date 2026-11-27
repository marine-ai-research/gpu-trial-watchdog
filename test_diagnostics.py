"""Offline synthetic fixtures and mocked transport only."""
import sys,pathlib
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import ast,copy,contextlib,io,json,unittest,hashlib
from unittest.mock import patch
import controller as c
import binding_diagnostics as d
from test_watchdog import policy,pod,NOW,Clock,KEY
import reconcile_resources as inv
# Frozen source from approved v4 commit 0c919b9fda48e37c822748c212b4585f2e0e0e60.
# Self-contained, source-hash anchored expectations; never read from the candidate.
BASELINE_V4_SHA256 = '0c63c57bd29aedd2ca5a17e00c024643d48174157c0a274f37938f2739b099a4'
BASELINE_V4_SOURCE = (
 '"""Finite, fixed-policy independent watchdog. No resource-creation API or shell."""\n'
 'import datetime,hashlib,json,math,os,pathlib,re,signal,sys,time\n'
 'sys.dont_write_bytecode=True\n'
 'sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))\n'
 'from terminate_trial import Stop,request,terminate,strict_json,ID\n'
 'from reconcile_resources import inventory,listing\n'
 'P=pathlib.Path(__file__).resolve().parent\n'
 'EXPIRY=105*60\n'
 "FIELDS={'approved','billing_mode','auto_pay_disabled','risk_or_contract_approval','name','image','gpu_type','gpu_count','container_disk_gb','data_center_ids','quoted_hourly_usd','startup_sha256'}\n"
 "EVENTS={'READY_EMPTY_ACCOUNT','NO_RESOURCE_CREATED','TARGET_BOUND','TARGET_ABSENT','RECONCILIATION','STOP','WATCHDOG_HEARTBEAT'}\n"
 'def emit(event,counts=None):\n'
 " if event not in EVENTS:raise Stop('LOG_POLICY')\n"
 " data={'event':event}\n"
 ' if counts is not None:\n'
 "  if set(counts)!={'pods','queued','network_volumes','global_volumes','serverless','clusters'}or any(type(v)is not int or not 0<=v<=10000 for v in counts.values()):raise Stop('LOG_POLICY')\n"
 '  data.update(counts=counts,all_billable_resources_verified=False)\n'
 ' print(json.dumps(data,sort_keys=True),flush=True)\n'
 "def canonical(p):return json.dumps(p,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()\n"
 'def startup_fingerprint(entrypoint,cmd):\n'
 ' # Exact exec-form arrays only: no shell parsing, whitespace folding or args fallback.\n'
 " if type(entrypoint)is not list or not entrypoint or type(cmd)is not list or len(entrypoint)+len(cmd)>256:raise Stop('STARTUP_SCHEMA')\n"
 " if any(type(v)is not str or len(v)>4096 or '\\x00'in v for v in entrypoint+cmd)or not entrypoint[0].strip():raise Stop('STARTUP_SCHEMA')\n"
 " return hashlib.sha256(canonical({'entrypoint':entrypoint,'cmd':cmd})).hexdigest()\n"
 'def startup_matches(p,pod):\n'
 ' try:\n'
 "  raw=pod['args']\n"
 '  if type(raw)is not str:return False\n'
 '  if raw:\n'
 '   decoded=strict_json(raw)\n'
 "   if type(decoded)is not dict or set(decoded)!={'entrypoint','cmd'}or decoded!={'entrypoint':pod['entrypoint'],'cmd':pod['cmd']}:return False\n"
 "  return startup_fingerprint(pod['entrypoint'],pod['cmd'])==p['startup_sha256']\n"
 ' except (Stop,KeyError,TypeError):return False\n'
 'def creation_time(pod):\n'
 ' try:\n'
 "  dt=datetime.datetime.fromisoformat(pod['createdAt'].replace('Z','+00:00'))\n"
 '  if dt.tzinfo is None:raise ValueError()\n'
 '  return dt.timestamp()\n'
 " except Exception:raise Stop('TARGET_CLOCK')from None\n"
 'def runtime_mapping_compatible(pod):\n'
 ' # List responses may explicitly report null runtime. Missing metadata is not null.\n'
 " if 'runtime'not in pod:return False\n"
 " runtime=pod['runtime']\n"
 " return runtime is None or(type(runtime)is dict and type(runtime.get('ports'))is list and runtime['ports']==[])\n"
 'def valid_centres(ids):\n'
 " return (type(ids)is list and 1<=len(ids)<=16 and all(type(v)is str and re.fullmatch(r'(?:EU|EUR)-[A-Z0-9]+-[0-9]+',v)for v in ids)and ids==sorted(set(ids)))\n"
 'def load_policy(text,lock):\n'
 " if not isinstance(text,str)or len(text)>16384:raise Stop('POLICY_REQUIRED')\n"
 ' p=strict_json(text)\n'
 " if not isinstance(p,dict)or set(p)!=FIELDS:raise Stop('POLICY_SCHEMA')\n"
 " h=lock.get('sha256')if isinstance(lock,dict)else None\n"
 " if not isinstance(h,str)or not re.fullmatch('[a-f0-9]{64}',h)or hashlib.sha256(canonical(p)).hexdigest()!=h:raise Stop('POLICY_LOCK')\n"
 " if not isinstance(p['startup_sha256'],str)or not re.fullmatch('[a-f0-9]{64}',p['startup_sha256']):raise Stop('POLICY_SCHEMA')\n"
 " if p['approved']is not True or p['billing_mode']!='prepaid'or p['auto_pay_disabled']is not True or p['risk_or_contract_approval']is not True:raise Stop('APPROVAL_REQUIRED')\n"
 " if not isinstance(p['name'],str)or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{5,79}',p['name']):raise Stop('POLICY_SCHEMA')\n"
 " if not isinstance(p['image'],str)or not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',p['image']):raise Stop('POLICY_SCHEMA')\n"
 " if not isinstance(p['gpu_type'],str)or not 1<=len(p['gpu_type'])<=80 or any(ord(c)<32 for c in p['gpu_type']):raise Stop('POLICY_SCHEMA')\n"
 " if type(p['gpu_count'])is not int or p['gpu_count']!=1 or type(p['container_disk_gb'])is not int or not 1<=p['container_disk_gb']<=50:raise Stop('POLICY_SCHEMA')\n"
 " if not valid_centres(p['data_center_ids']):raise Stop('POLICY_SCHEMA')\n"
 " if type(p['quoted_hourly_usd'])not in(int,float)or not math.isfinite(p['quoted_hourly_usd'])or not 0<p['quoted_hourly_usd']<=2:raise Stop('POLICY_SCHEMA')\n"
 ' return p\n'
 '\n'
 'def policy_from_environment(e,lock):\n'
 ' def boolean(name):\n'
 '  v=e.get(name)\n'
 "  if v not in ('true','false'):raise Stop('POLICY_REQUIRED')\n"
 "  return v=='true'\n"
 ' def integer(name):\n'
 "  v=e.get(name,'')\n"
 "  if not re.fullmatch('[0-9]{1,3}',v):raise Stop('POLICY_REQUIRED')\n"
 '  return int(v)\n'
 " try:price=float(e.get('POLICY_MAX_HOURLY_USD',''))\n"
 " except Exception:raise Stop('POLICY_REQUIRED')from None\n"
 " p=dict(approved=boolean('POLICY_APPROVED'),billing_mode=e.get('POLICY_BILLING_MODE'),auto_pay_disabled=boolean('POLICY_AUTO_PAY_DISABLED'),risk_or_contract_approval=boolean('POLICY_RISK_ACCEPTED'),name=e.get('POLICY_NAME'),image=e.get('POLICY_IMAGE'),gpu_type=e.get('POLICY_GPU_TYPE'),gpu_count=integer('POLICY_GPU_COUNT'),container_disk_gb=integer('POLICY_CONTAINER_DISK_GB'),data_center_ids=e.get('POLICY_DATA_CENTER','').split(','),quoted_hourly_usd=price,startup_sha256=e.get('POLICY_STARTUP_SHA256'))\n"
 ' try:text=json.dumps(p,allow_nan=False)\n'
 " except Exception:raise Stop('POLICY_REQUIRED')from None\n"
 ' return load_policy(text,lock)\n'
 '\n'
 'def bind(p,pod,now,earliest):\n'
 " if not isinstance(pod,dict)or pod.get('name')!=p['name']or not isinstance(pod.get('id'),str)or not ID.fullmatch(pod['id']):raise Stop('TARGET_AMBIGUOUS')\n"
 ' created=creation_time(pod)\n'
 " if not earliest-5<=created<=now or now-created>7200:raise Stop('TARGET_CLOCK')\n"
 " candidate={'pod_id':pod['id'],'created_unix':created,'deadline_unix':created+EXPIRY,'network_volume_ids':[],'persistent_disk_gb':0,'data_center_id':pod.get('dataCenterId')}\n"
 " if not valid_target(p,pod,candidate):raise Stop('TARGET_NOT_AUTHORISED')\n"
 ' # No deletion authority exists before the complete approved policy matches.\n'
 ' return dict(candidate,approved=True),True\n'
 '\n'
 'def valid_target(p,pod,r):\n'
 " gpu=pod.get('gpu');cost=pod.get('cost');mounts=pod.get('mounts');ports=pod.get('ports');network=pod.get('globalNetworking')\n"
 " try:same_creation=creation_time(pod)==r['created_unix']\n"
 ' except (Stop,KeyError,TypeError):return False\n'
 " return (same_creation and startup_matches(p,pod)and runtime_mapping_compatible(pod)and pod.get('id')==r['pod_id']and pod.get('name')==p['name']and pod.get('image')==p['image']and pod.get('cloud')=='SECURE'and valid_centres(p['data_center_ids'])and pod.get('dataCenterId')in p['data_center_ids']and pod.get('dataCenterId')==r.get('data_center_id')and type(pod.get('disk'))is int and pod['disk']==p['container_disk_gb']and isinstance(ports,list)and ports==[]and isinstance(mounts,dict)and mounts=={}and isinstance(gpu,dict)and gpu.get('id')==p['gpu_type']and type(gpu.get('count'))is int and gpu['count']==1 and type(cost)in(int,float)and math.isfinite(cost)and 0<cost<=p['quoted_hourly_usd']+0.01 and isinstance(network,dict)and network.get('enabled')is False)\n"
 '\n'
 'def watch(p,token,transport=request,clock=time.time,mono=time.monotonic,sleep=time.sleep):\n'
 ' counts=inventory(token,transport,mono)\n'
 " if any(counts.values()):raise Stop('ACCOUNT_NOT_EMPTY')\n"
 " emit('READY_EMPTY_ACCOUNT');start=mono();wall=clock();r=None;end=None;beat=start\n"
 ' try:\n'
 '  while r is None and mono()-start<600:\n'
 "   if abs((clock()-wall)-(mono()-start))>5:raise Stop('CLOCK_DRIFT')\n"
 "   pods=listing('/pods','pods',token,transport,mono,min(mono()+30,start+600))\n"
 '   if mono()-start>=600:\n'
 "    if pods:raise Stop('ARM_WINDOW_EXPIRED')\n"
 '    break\n'
 '   if pods:\n'
 "    if len(pods)!=1:raise Stop('TARGET_AMBIGUOUS')\n"
 '    r,valid=bind(p,pods[0],clock(),wall)\n'
 "    if not valid:raise Stop('TARGET_POLICY_CHANGED')\n"
 "    end=mono()+max(0,r['deadline_unix']-clock());emit('TARGET_BOUND');break\n"
 '   sleep(min(5,max(0,600-(mono()-start))))\n'
 "  if r is None:emit('NO_RESOURCE_CREATED');return\n"
 "  while mono()<end and clock()<r['deadline_unix']:\n"
 "   if abs((clock()-wall)-(mono()-start))>5:raise Stop('CLOCK_DRIFT')\n"
 "   remaining=min(end-mono(),r['deadline_unix']-clock())\n"
 '   if remaining<=0:break\n'
 '   # Reject a second Pod without ever granting it deletion authority.\n'
 "   current=listing('/pods','pods',token,transport,mono,min(end,mono()+30))\n"
 "   if len(current)!=1 or current[0].get('id')!=r['pod_id']:raise Stop('TARGET_AMBIGUOUS')\n"
 "   remaining=min(end-mono(),r['deadline_unix']-clock())\n"
 '   if remaining<=0:break\n'
 "   status,pod=transport('GET','/pods/'+r['pod_id'],token,timeout=min(15,remaining))\n"
 '   if status==404:break\n'
 "   if status!=200 or not isinstance(pod,dict)or not valid_target(p,pod,r):raise Stop('TARGET_POLICY_CHANGED')\n"
 "   if mono()-beat>=60:emit('WATCHDOG_HEARTBEAT');beat=mono()\n"
 '   sleep(min(15,max(0,end-mono())))\n'
 ' finally:\n'
 '  if r is not None:\n'
 "   terminate(r,token,transport,clock,sleep,mono);emit('TARGET_ABSENT')\n"
 "   counts=inventory(token,transport,mono);emit('RECONCILIATION',counts)\n"
 "   if any(counts.values()):raise Stop('OTHER_RESOURCES_REMAIN')\n"
 '\n'
 'def verify_context(e):\n'
 " expected=e.get('CONTROLLER_REPOSITORY','');pin=e.get('REVIEWED_CONTROLLER_COMMIT','')\n"
 " if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',expected)or not re.fullmatch('[a-f0-9]{40}',pin)or e.get('GITHUB_REPOSITORY')!=expected or e.get('GITHUB_SHA')!=pin or e.get('GITHUB_REF')!='refs/heads/main'or e.get('GITHUB_EVENT_NAME')!='workflow_dispatch':raise Stop('WORKFLOW_CONTEXT')\n"
 '\n'
 'def main():\n'
 ' try:\n'
 "  if len(sys.argv)!=2 or sys.argv[1]not in('watch','inventory'):raise Stop('ACTION_NOT_ALLOWED')\n"
 '  verify_context(os.environ)\n'
 "  policy=policy_from_environment(os.environ,strict_json((P/'policy-lock.json').read_text()))\n"
 "  token=os.environ.get('TRIAL_RUNPOD_TOKEN')\n"
 "  if not token:raise Stop('CREDENTIAL_REQUIRED')\n"
 "  def interrupted(signum,frame):raise Stop('INTERRUPTED')\n"
 '  for sig in(signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)\n'
 "  if sys.argv[1]=='watch':watch(policy,token)\n"
 '  else:\n'
 "   counts=inventory(token);emit('RECONCILIATION',counts)\n"
 "   if any(counts.values()):raise Stop('OTHER_RESOURCES_REMAIN')\n"
 '  return 0\n'
 ' except BaseException:\n'
 '  # Do not print exception text, provider records, inputs, headers or tracebacks.\n'
 "  emit('STOP');return 1\n"
 "if __name__=='__main__':sys.exit(main())\n"
)
SENTINEL='PRIVATE_SENTINEL_NEVER_LOG_9381'
class DiagnosticsTests(unittest.TestCase):
 def rejected(self,field,value,code,remove=False):
  item=pod()
  if remove:item.pop(field)
  else:item[field]=value
  output=io.StringIO();clock=Clock();calls=[];lists=0
  def tx(method,path,token,**kwargs):
   nonlocal lists
   calls.append((method,path))
   if method!='GET':self.fail('No deletion authority before binding')
   key=dict(inv.CATEGORIES.values())[path]
   if path=='/pods':lists+=1
   return 200,{key:[item] if path=='/pods'and lists>=2 else [],'pagination':{'hasNextPage':False,'nextCursor':None}}
  with contextlib.redirect_stdout(output),self.assertRaises(c.Stop):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  events=[json.loads(line)for line in output.getvalue().splitlines()]
  self.assertTrue(any(x.get('reason')==code for x in events),events)
  self.assertFalse(any(m=='DELETE'for m,_ in calls));self.assertNotIn('TARGET_BOUND',output.getvalue());self.assertNotIn(SENTINEL,output.getvalue())
  for event in events:
   if event['event']=='BINDING_REJECT':self.assertEqual(set(event),{'event','reason'});self.assertIn(event['reason'],d.CODES)
 def test_clock_drift_unchanged_and_diagnosable(self):
  values=iter([NOW,NOW+6])
  with patch.object(c,'inventory',return_value={k:0 for k in inv.CATEGORIES}),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(c.Stop,'CLOCK_DRIFT'):
   c.watch(policy(),KEY,clock=lambda:next(values),mono=lambda:0,sleep=lambda n:None)
 def test_inventory_schema_failure_during_wait_never_deletes(self):
  calls=[]
  def tx(method,path,token,**kwargs):calls.append((method,path));return 200,{'pods':SENTINEL}
  with patch.object(c,'inventory',return_value={k:0 for k in inv.CATEGORIES}),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(c.Stop,'INVENTORY_SCHEMA'):
   clock=Clock();c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertEqual(calls,[('GET','/pods')])
 def test_watch_authorisation_cleanup_and_deadlines_unchanged(self):
  self.assertEqual(hashlib.sha256(BASELINE_V4_SOURCE.encode()).hexdigest(),BASELINE_V4_SHA256)
  a=ast.parse(BASELINE_V4_SOURCE);b=ast.parse(pathlib.Path(c.__file__).read_text())
  for name in ['watch','load_policy','verify_context','startup_matches','creation_time','runtime_mapping_compatible','policy_from_environment']:
   old=next(x for x in a.body if isinstance(x,ast.FunctionDef)and x.name==name);new=next(x for x in b.body if isinstance(x,ast.FunctionDef)and x.name==name)
   self.assertEqual(ast.dump(old),ast.dump(new))
 def test_missing_nested_metadata_is_explicit(self):
  for field,value in [('gpu',{'id':'NVIDIA L40S'}),('globalNetworking',{}),('runtime',{})]:
   with self.subTest(field=field):self.rejected(field,value,'API_METADATA_MISSING')
 def test_valid_target_no_diagnostic(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):receipt,ok=c.bind(policy(),pod(),NOW,NOW)
  self.assertTrue(ok);self.assertEqual(out.getvalue(),'');self.assertEqual(receipt['deadline_unix']-receipt['created_unix'],6300)
 def test_authoritative_bodies_byte_equivalent(self):
  self.assertEqual(hashlib.sha256(BASELINE_V4_SOURCE.encode()).hexdigest(),BASELINE_V4_SHA256)
  ref=ast.parse(BASELINE_V4_SOURCE);new=ast.parse(pathlib.Path(c.__file__).read_text())
  for original,renamed in [('bind','_bind_v4'),('valid_target','_valid_target_v4')]:
   a=next(x for x in ref.body if isinstance(x,ast.FunctionDef)and x.name==original);b=next(x for x in new.body if isinstance(x,ast.FunctionDef)and x.name==renamed)
   self.assertEqual(ast.dump(ast.Module(body=a.body,type_ignores=[])),ast.dump(ast.Module(body=b.body,type_ignores=[])))
 def test_diagnostic_failure_never_approves(self):
  item=pod();item['image']='wrong'
  with patch.object(d,'reasons',side_effect=RuntimeError(SENTINEL)),contextlib.redirect_stdout(io.StringIO())as out,self.assertRaises(c.Stop):c.bind(policy(),item,NOW,NOW)
  self.assertNotIn(SENTINEL,out.getvalue());self.assertIn('DIAGNOSTIC_UNAVAILABLE',out.getvalue())
 def test_stop_does_not_print_unknown_exception(self):
  for error in [RuntimeError(SENTINEL),c.Stop(SENTINEL),c.Stop({'secret':SENTINEL})]:
   with contextlib.redirect_stdout(io.StringIO())as out:c.safe_stop(error)
   self.assertEqual(json.loads(out.getvalue()),{'event':'CONTROLLER_REJECT','reason':'UNCLASSIFIED_FAILURE'})
 def test_untrusted_reason_never_printed(self):
  with contextlib.redirect_stdout(io.StringIO())as out:d.emit_code(SENTINEL)
  self.assertEqual(json.loads(out.getvalue())['reason'],'DIAGNOSTIC_UNAVAILABLE')
 def test_binding_policy_drift_both_allowed_locations_rejected(self):
  p=policy();p['data_center_ids']=['EU-TEST-1','EUR-TEST-2'];receipt,_=c.bind(p,pod(),NOW,NOW);changed=pod();changed['dataCenterId']='EUR-TEST-2'
  with contextlib.redirect_stdout(io.StringIO())as out:self.assertFalse(c.valid_target(p,changed,receipt))
  self.assertIn('DATA_CENTER',out.getvalue())
 def test_all_allowlisted_stop_reasons_fixed(self):
  for code in c.SAFE_STOP_CODES:
   with contextlib.redirect_stdout(io.StringIO())as out:c.safe_stop(c.Stop(code))
   self.assertEqual(json.loads(out.getvalue()),{'event':'CONTROLLER_REJECT','reason':code})
 def test_main_transport_failure_sanitised(self):
  with patch.object(c,'verify_context'),patch.object(c,'policy_from_environment',return_value=policy()),patch.dict(c.os.environ,{'TRIAL_RUNPOD_TOKEN':SENTINEL}),patch.object(c,'watch',side_effect=c.Stop('API_UNAVAILABLE')),patch.object(c.sys,'argv',['controller.py','watch']),contextlib.redirect_stdout(io.StringIO())as out:
   self.assertEqual(c.main(),1)
  self.assertNotIn(SENTINEL,out.getvalue());self.assertEqual([json.loads(x)for x in out.getvalue().splitlines()],[{'event':'CONTROLLER_REJECT','reason':'API_UNAVAILABLE'},{'event':'STOP'}])
 def test_diagnostic_output_failure_never_authorises(self):
  item=pod();item['ports']=['22/tcp']
  with patch.object(d,'emit_code',side_effect=RuntimeError(SENTINEL)),self.assertRaises(c.Stop):c.bind(policy(),item,NOW,NOW)
variants=[('name',SENTINEL,'POD_NAME'),('id','../'+SENTINEL,'POD_ID'),('createdAt','bad','CREATION_TIMESTAMP'),('createdAt','2026-01-01T00:00:01Z','CREATION_WINDOW'),('dataCenterId','EU-OTHER-1','DATA_CENTER'),('gpu',{'id':SENTINEL,'count':1},'GPU_TYPE'),('gpu',{'id':'NVIDIA L40S','count':2},'GPU_COUNT'),('gpu',{'id':'NVIDIA L40S','count':True},'GPU_COUNT'),('globalNetworking',{'enabled':True},'GLOBAL_NETWORKING'),('globalNetworking',False,'GLOBAL_NETWORKING'),('image',SENTINEL,'IMAGE_DIGEST'),('entrypoint',['/bin/sh','-c'],'STARTUP_FINGERPRINT'),('cmd',[SENTINEL],'STARTUP_FINGERPRINT'),('args',SENTINEL,'STARTUP_ARGS'),('args','{}','STARTUP_ARGS'),('disk',49,'STORAGE'),('disk',True,'STORAGE'),('mounts',{'private':SENTINEL},'MOUNTS'),('ports',['22/tcp'],'EXPOSED_PORTS'),('runtime',{'ports':[SENTINEL]},'RUNTIME_PORTS'),('cost',2,'PRICING'),('cost',float('nan'),'PRICING'),('cost',True,'PRICING'),('cloud',SENTINEL,'CLOUD')]
for index,(field,value,code)in enumerate(variants):
 def test(self,f=field,v=value,k=code):self.rejected(f,v,k)
 setattr(DiagnosticsTests,'test_rejection_%02d_%s'%(index,code.lower()),test)
for field in pod():
 def test(self,f=field):self.rejected(f,None,'API_METADATA_MISSING',remove=True)
 setattr(DiagnosticsTests,'test_missing_'+field,test)
if __name__=='__main__':unittest.main(verbosity=2)
