"""Fixed-origin read/delete transport and exact-target bounded termination."""
import json,math,re,time,urllib.request,urllib.error
BASE='https://api.runpod.io/v2'
ID=re.compile(r'[A-Za-z0-9_-]{6,80}')
COLLECTIONS={'/pods','/queued-pods','/network-volumes','/global-volumes','/serverless','/clusters'}
class Stop(RuntimeError):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def strict_json(text):
 def pairs(items):
  d={}
  for k,v in items:
   if k in d:raise Stop('INVALID_JSON')
   d[k]=v
  return d
 def bad(_):raise Stop('INVALID_JSON')
 try:return json.loads(text,object_pairs_hook=pairs,parse_constant=bad)
 except Exception:raise Stop('INVALID_JSON') from None

def request(method,path,token,timeout=15):
 if not isinstance(token,str)or not token or '\r'in token or '\n'in token:raise Stop('CREDENTIAL_REQUIRED')
 base=path.split('?',1)[0]if isinstance(path,str)else ''
 target=base.startswith('/pods/')and bool(ID.fullmatch(base[6:]))
 if method not in ('GET','DELETE')or not (base in COLLECTIONS or target)or(method=='DELETE'and not target):raise Stop('TRANSPORT_POLICY')
 if '?'in path and not(method=='GET'and base in COLLECTIONS and re.fullmatch(r'cursor=[A-Za-z0-9%_.~+\-=]{1,2048}',path.split('?',1)[1])):raise Stop('TRANSPORT_POLICY')
 req=urllib.request.Request(BASE+path,method=method,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
 try:
  with OPENER.open(req,timeout=max(0.1,min(15,timeout)))as r:
   if r.status==404:return 404,None
   if r.status not in (200,202,204):raise Stop('API_RESPONSE')
   raw=r.read(1048577)
   if len(raw)>1048576:raise Stop('API_RESPONSE')
   return r.status,strict_json(raw.decode('utf-8'))if raw else None
 except urllib.error.HTTPError as e:
  if e.code==404:return 404,None
  raise Stop('API_UNAVAILABLE')from None
 except Exception:raise Stop('API_UNAVAILABLE')from None

def validate_receipt(r,now):
 if r.get('approved')is not True or not isinstance(r.get('pod_id'),str)or not ID.fullmatch(r['pod_id']):raise Stop('INVALID_RECEIPT')
 created=r.get('created_unix');deadline=r.get('deadline_unix')
 if any(type(v)not in(int,float)or not math.isfinite(v)for v in(created,deadline,now)):raise Stop('INVALID_RECEIPT')
 if deadline-created!=105*60 or r.get('network_volume_ids')!=[]or r.get('persistent_disk_gb')!=0:raise Stop('INVALID_RECEIPT')
 return '/pods/'+r['pod_id']

def terminate(r,token,transport=request,clock=time.time,sleep=time.sleep,mono=time.monotonic):
 path=validate_receipt(r,clock());end=mono()+120
 for delay in(0,2,5):
  if mono()+delay>=end:break
  if delay:sleep(delay)
  try:
   status,_=transport('DELETE',path,token,timeout=min(15,end-mono()))
   if status not in(200,202,204,404):continue
   for pause in(1,2,5):
    if mono()+pause+0.1>=end:break
    sleep(pause);status,_=transport('GET',path,token,timeout=min(15,end-mono()))
    if status==404:return True
  except Exception:continue
 raise Stop('TERMINATION_UNCONFIRMED')
