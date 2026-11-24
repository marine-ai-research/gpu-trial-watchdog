"""Finite, fixed-policy independent watchdog. No resource-creation API or shell."""
import datetime,hashlib,json,math,os,pathlib,re,signal,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from terminate_trial import Stop,request,terminate,strict_json,ID
from reconcile_resources import inventory,listing
P=pathlib.Path(__file__).resolve().parent
EXPIRY=105*60
FIELDS={'approved','billing_mode','auto_pay_disabled','risk_or_contract_approval','name','image','gpu_type','gpu_count','container_disk_gb','data_center_id','quoted_hourly_usd','startup_sha256'}
EVENTS={'READY_EMPTY_ACCOUNT','NO_RESOURCE_CREATED','TARGET_BOUND','TARGET_ABSENT','RECONCILIATION','STOP','WATCHDOG_HEARTBEAT'}
def emit(event,counts=None):
 if event not in EVENTS:raise Stop('LOG_POLICY')
 data={'event':event}
 if counts is not None:
  if set(counts)!={'pods','queued','network_volumes','global_volumes','serverless','clusters'}or any(type(v)is not int or not 0<=v<=10000 for v in counts.values()):raise Stop('LOG_POLICY')
  data.update(counts=counts,all_billable_resources_verified=False)
 print(json.dumps(data,sort_keys=True),flush=True)
def canonical(p):return json.dumps(p,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def startup_fingerprint(entrypoint,cmd):
 # Exact exec-form arrays only: no shell parsing, whitespace folding or args fallback.
 if type(entrypoint)is not list or not entrypoint or type(cmd)is not list or len(entrypoint)+len(cmd)>256:raise Stop('STARTUP_SCHEMA')
 if any(type(v)is not str or len(v)>4096 or '\x00'in v for v in entrypoint+cmd)or not entrypoint[0].strip():raise Stop('STARTUP_SCHEMA')
 return hashlib.sha256(canonical({'entrypoint':entrypoint,'cmd':cmd})).hexdigest()
def startup_matches(p,pod):
 try:
  raw=pod['args']
  if type(raw)is not str:return False
  if raw:
   decoded=strict_json(raw)
   if type(decoded)is not dict or set(decoded)!={'entrypoint','cmd'}or decoded!={'entrypoint':pod['entrypoint'],'cmd':pod['cmd']}:return False
  return startup_fingerprint(pod['entrypoint'],pod['cmd'])==p['startup_sha256']
 except (Stop,KeyError,TypeError):return False
def creation_time(pod):
 try:
  dt=datetime.datetime.fromisoformat(pod['createdAt'].replace('Z','+00:00'))
  if dt.tzinfo is None:raise ValueError()
  return dt.timestamp()
 except Exception:raise Stop('TARGET_CLOCK')from None
def runtime_mapping_compatible(pod):
 # List responses may explicitly report null runtime. Missing metadata is not null.
 if 'runtime'not in pod:return False
 runtime=pod['runtime']
 return runtime is None or(type(runtime)is dict and type(runtime.get('ports'))is list and runtime['ports']==[])
def load_policy(text,lock):
 if not isinstance(text,str)or len(text)>16384:raise Stop('POLICY_REQUIRED')
 p=strict_json(text)
 if not isinstance(p,dict)or set(p)!=FIELDS:raise Stop('POLICY_SCHEMA')
 h=lock.get('sha256')if isinstance(lock,dict)else None
 if not isinstance(h,str)or not re.fullmatch('[a-f0-9]{64}',h)or hashlib.sha256(canonical(p)).hexdigest()!=h:raise Stop('POLICY_LOCK')
 if not isinstance(p['startup_sha256'],str)or not re.fullmatch('[a-f0-9]{64}',p['startup_sha256']):raise Stop('POLICY_SCHEMA')
 if p['approved']is not True or p['billing_mode']!='prepaid'or p['auto_pay_disabled']is not True or p['risk_or_contract_approval']is not True:raise Stop('APPROVAL_REQUIRED')
 if not isinstance(p['name'],str)or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{5,79}',p['name']):raise Stop('POLICY_SCHEMA')
 if not isinstance(p['image'],str)or not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',p['image']):raise Stop('POLICY_SCHEMA')
 if not isinstance(p['gpu_type'],str)or not 1<=len(p['gpu_type'])<=80 or any(ord(c)<32 for c in p['gpu_type']):raise Stop('POLICY_SCHEMA')
 if type(p['gpu_count'])is not int or p['gpu_count']!=1 or type(p['container_disk_gb'])is not int or not 1<=p['container_disk_gb']<=50:raise Stop('POLICY_SCHEMA')
 if not isinstance(p['data_center_id'],str)or not re.fullmatch('[A-Z0-9-]{3,40}',p['data_center_id']):raise Stop('POLICY_SCHEMA')
 if type(p['quoted_hourly_usd'])not in(int,float)or not math.isfinite(p['quoted_hourly_usd'])or not 0<p['quoted_hourly_usd']<=2:raise Stop('POLICY_SCHEMA')
 return p

def policy_from_environment(e,lock):
 def boolean(name):
  v=e.get(name)
  if v not in ('true','false'):raise Stop('POLICY_REQUIRED')
  return v=='true'
 def integer(name):
  v=e.get(name,'')
  if not re.fullmatch('[0-9]{1,3}',v):raise Stop('POLICY_REQUIRED')
  return int(v)
 try:price=float(e.get('POLICY_MAX_HOURLY_USD',''))
 except Exception:raise Stop('POLICY_REQUIRED')from None
 p=dict(approved=boolean('POLICY_APPROVED'),billing_mode=e.get('POLICY_BILLING_MODE'),auto_pay_disabled=boolean('POLICY_AUTO_PAY_DISABLED'),risk_or_contract_approval=boolean('POLICY_RISK_ACCEPTED'),name=e.get('POLICY_NAME'),image=e.get('POLICY_IMAGE'),gpu_type=e.get('POLICY_GPU_TYPE'),gpu_count=integer('POLICY_GPU_COUNT'),container_disk_gb=integer('POLICY_CONTAINER_DISK_GB'),data_center_id=e.get('POLICY_DATA_CENTER'),quoted_hourly_usd=price,startup_sha256=e.get('POLICY_STARTUP_SHA256'))
 try:text=json.dumps(p,allow_nan=False)
 except Exception:raise Stop('POLICY_REQUIRED')from None
 return load_policy(text,lock)

def bind(p,pod,now,earliest):
 if not isinstance(pod,dict)or pod.get('name')!=p['name']or not isinstance(pod.get('id'),str)or not ID.fullmatch(pod['id']):raise Stop('TARGET_AMBIGUOUS')
 created=creation_time(pod)
 if not earliest-5<=created<=now or now-created>7200:raise Stop('TARGET_CLOCK')
 candidate={'pod_id':pod['id'],'created_unix':created,'deadline_unix':created+EXPIRY,'network_volume_ids':[],'persistent_disk_gb':0}
 if not valid_target(p,pod,candidate):raise Stop('TARGET_NOT_AUTHORISED')
 # No deletion authority exists before the complete approved policy matches.
 return dict(candidate,approved=True),True

def valid_target(p,pod,r):
 gpu=pod.get('gpu');cost=pod.get('cost');mounts=pod.get('mounts');ports=pod.get('ports');network=pod.get('globalNetworking')
 try:same_creation=creation_time(pod)==r['created_unix']
 except (Stop,KeyError,TypeError):return False
 return (same_creation and startup_matches(p,pod)and runtime_mapping_compatible(pod)and pod.get('id')==r['pod_id']and pod.get('name')==p['name']and pod.get('image')==p['image']and pod.get('cloud')=='SECURE'and pod.get('dataCenterId')==p['data_center_id']and type(pod.get('disk'))is int and pod['disk']==p['container_disk_gb']and isinstance(ports,list)and ports==[]and isinstance(mounts,dict)and mounts=={}and isinstance(gpu,dict)and gpu.get('id')==p['gpu_type']and type(gpu.get('count'))is int and gpu['count']==1 and type(cost)in(int,float)and math.isfinite(cost)and 0<cost<=p['quoted_hourly_usd']+0.01 and isinstance(network,dict)and network.get('enabled')is False)

def watch(p,token,transport=request,clock=time.time,mono=time.monotonic,sleep=time.sleep):
 counts=inventory(token,transport,mono)
 if any(counts.values()):raise Stop('ACCOUNT_NOT_EMPTY')
 emit('READY_EMPTY_ACCOUNT');start=mono();wall=clock();r=None;end=None;beat=start
 try:
  while r is None and mono()-start<600:
   if abs((clock()-wall)-(mono()-start))>5:raise Stop('CLOCK_DRIFT')
   pods=listing('/pods','pods',token,transport,mono,min(mono()+30,start+600))
   if mono()-start>=600:
    if pods:raise Stop('ARM_WINDOW_EXPIRED')
    break
   if pods:
    if len(pods)!=1:raise Stop('TARGET_AMBIGUOUS')
    r,valid=bind(p,pods[0],clock(),wall)
    if not valid:raise Stop('TARGET_POLICY_CHANGED')
    end=mono()+max(0,r['deadline_unix']-clock());emit('TARGET_BOUND');break
   sleep(min(5,max(0,600-(mono()-start))))
  if r is None:emit('NO_RESOURCE_CREATED');return
  while mono()<end and clock()<r['deadline_unix']:
   if abs((clock()-wall)-(mono()-start))>5:raise Stop('CLOCK_DRIFT')
   remaining=min(end-mono(),r['deadline_unix']-clock())
   if remaining<=0:break
   status,pod=transport('GET','/pods/'+r['pod_id'],token,timeout=min(15,remaining))
   if status==404:break
   if status!=200 or not isinstance(pod,dict)or not valid_target(p,pod,r):raise Stop('TARGET_POLICY_CHANGED')
   if mono()-beat>=60:emit('WATCHDOG_HEARTBEAT');beat=mono()
   sleep(min(15,max(0,end-mono())))
 finally:
  if r is not None:
   terminate(r,token,transport,clock,sleep,mono);emit('TARGET_ABSENT')
   counts=inventory(token,transport,mono);emit('RECONCILIATION',counts)
   if any(counts.values()):raise Stop('OTHER_RESOURCES_REMAIN')

def verify_context(e):
 expected=e.get('CONTROLLER_REPOSITORY','');pin=e.get('REVIEWED_CONTROLLER_COMMIT','')
 if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',expected)or not re.fullmatch('[a-f0-9]{40}',pin)or e.get('GITHUB_REPOSITORY')!=expected or e.get('GITHUB_SHA')!=pin or e.get('GITHUB_REF')!='refs/heads/main'or e.get('GITHUB_EVENT_NAME')!='workflow_dispatch':raise Stop('WORKFLOW_CONTEXT')

def main():
 try:
  if len(sys.argv)!=2 or sys.argv[1]not in('watch','inventory'):raise Stop('ACTION_NOT_ALLOWED')
  verify_context(os.environ)
  policy=policy_from_environment(os.environ,strict_json((P/'policy-lock.json').read_text()))
  token=os.environ.get('TRIAL_RUNPOD_TOKEN')
  if not token:raise Stop('CREDENTIAL_REQUIRED')
  def interrupted(signum,frame):raise Stop('INTERRUPTED')
  for sig in(signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
  if sys.argv[1]=='watch':watch(policy,token)
  else:
   counts=inventory(token);emit('RECONCILIATION',counts)
   if any(counts.values()):raise Stop('OTHER_RESOURCES_REMAIN')
  return 0
 except BaseException:
  # Do not print exception text, provider records, inputs, headers or tracebacks.
  emit('STOP');return 1
if __name__=='__main__':sys.exit(main())
