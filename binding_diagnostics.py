"""Advisory fixed-code diagnostics. Never grants target/deletion authority."""
import json,math
CODES=frozenset('POD_NAME POD_ID CREATION_TIMESTAMP CREATION_WINDOW CREATION_IDENTITY DATA_CENTER GPU_TYPE GPU_COUNT GLOBAL_NETWORKING IMAGE_DIGEST STARTUP_FINGERPRINT STARTUP_ARGS STORAGE MOUNTS EXPOSED_PORTS RUNTIME_PORTS PRICING CLOUD API_METADATA_MISSING POD_SCHEMA DIAGNOSTIC_UNAVAILABLE'.split())
def emit_code(code):
 # No values, identifiers, exception text, source paths or provider objects.
 if type(code)is not str or code not in CODES:code='DIAGNOSTIC_UNAVAILABLE'
 print(json.dumps({'event':'BINDING_REJECT','reason':code},sort_keys=True),flush=True)
def reasons(c,p,pod,r=None,now=None,earliest=None):
 if type(pod)is not dict:return ('POD_SCHEMA',)
 codes=[]
 def check(ok,code):
  if not ok and code not in codes:codes.append(code)
 required={'id','name','createdAt','image','cloud','dataCenterId','disk','ports','mounts','gpu','cost','globalNetworking','entrypoint','cmd','args','runtime'}
 check(required<=pod.keys(),'API_METADATA_MISSING')
 for key,fields in [('gpu',{'id','count'}),('globalNetworking',{'enabled'})]:
  if isinstance(pod.get(key),dict):check(fields<=pod[key].keys(),'API_METADATA_MISSING')
 if isinstance(pod.get('runtime'),dict):check('ports'in pod['runtime'],'API_METADATA_MISSING')
 check(pod.get('name')==p['name'],'POD_NAME')
 check(type(pod.get('id'))is str and bool(c.ID.fullmatch(pod['id'])),'POD_ID')
 try:
  created=c.creation_time(pod)
  if now is not None:check(earliest-5<=created<=now and now-created<=7200,'CREATION_WINDOW')
  if r is not None:check(created==r['created_unix'],'CREATION_IDENTITY')
 except Exception:check(False,'CREATION_TIMESTAMP')
 check(c.valid_centres(p['data_center_ids']) and pod.get('dataCenterId')in p['data_center_ids'] and (r is None or pod.get('dataCenterId')==r.get('data_center_id')),'DATA_CENTER')
 check(pod.get('image')==p['image'],'IMAGE_DIGEST')
 check(pod.get('cloud')=='SECURE','CLOUD')
 check(type(pod.get('disk'))is int and pod['disk']==p['container_disk_gb'],'STORAGE')
 check(isinstance(pod.get('mounts'),dict)and pod['mounts']=={},'MOUNTS')
 check(isinstance(pod.get('ports'),list)and pod['ports']==[],'EXPOSED_PORTS')
 check(c.runtime_mapping_compatible(pod),'RUNTIME_PORTS')
 gpu=pod.get('gpu');check(isinstance(gpu,dict)and gpu.get('id')==p['gpu_type'],'GPU_TYPE')
 check(isinstance(gpu,dict)and type(gpu.get('count'))is int and gpu['count']==1,'GPU_COUNT')
 net=pod.get('globalNetworking');check(isinstance(net,dict)and net.get('enabled')is False,'GLOBAL_NETWORKING')
 cost=pod.get('cost');check(type(cost)in(int,float)and math.isfinite(cost)and 0<cost<=p['quoted_hourly_usd']+0.01,'PRICING')
 try:check(c.startup_fingerprint(pod['entrypoint'],pod['cmd'])==p['startup_sha256'],'STARTUP_FINGERPRINT')
 except Exception:check(False,'STARTUP_FINGERPRINT')
 try:
  raw=pod['args'];check(type(raw)is str and (not raw or (type(c.strict_json(raw))is dict and c.strict_json(raw)=={'entrypoint':pod['entrypoint'],'cmd':pod['cmd']} and set(c.strict_json(raw))=={'entrypoint','cmd'})),'STARTUP_ARGS')
 except Exception:check(False,'STARTUP_ARGS')
 if r is not None:check(pod.get('id')==r['pod_id'],'POD_ID')
 return tuple(codes)
def report(c,p,pod,r=None,now=None,earliest=None):
 try:
  codes=reasons(c,p,pod,r,now,earliest)
  for code in codes or ('DIAGNOSTIC_UNAVAILABLE',):emit_code(code)
 except BaseException:
  # Diagnostic failure must never turn rejection into acceptance.
  try:emit_code('DIAGNOSTIC_UNAVAILABLE')
  except BaseException:pass
