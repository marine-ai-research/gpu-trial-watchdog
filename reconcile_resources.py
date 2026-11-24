"""Read-only paginated inventory. Never prints provider records or identifiers."""
import time,urllib.parse
from terminate_trial import request,Stop
CATEGORIES={'pods':('/pods','pods'),'queued':('/queued-pods','queuedPods'),'network_volumes':('/network-volumes','networkVolumes'),'global_volumes':('/global-volumes','globalVolumes'),'serverless':('/serverless','endpoints'),'clusters':('/clusters','clusters')}
def listing(path,key,token,transport=request,mono=time.monotonic,deadline=None):
 if (path,key)not in CATEGORIES.values():raise Stop('INVENTORY_POLICY')
 end=deadline if deadline is not None else mono()+120
 items=[];cursor=None;seen=set()
 for _ in range(100):
  if mono()>=end:raise Stop('INVENTORY_TIMEOUT')
  url=path+('?'+urllib.parse.urlencode({'cursor':cursor})if cursor else '')
  status,data=transport('GET',url,token,timeout=min(15,end-mono()))
  if status!=200 or not isinstance(data,dict)or not isinstance(data.get(key),list):raise Stop('INVENTORY_SCHEMA')
  rows=data[key]
  if len(rows)>1000 or len(items)+len(rows)>10000 or any(not isinstance(x,dict)for x in rows):raise Stop('INVENTORY_LIMIT')
  items.extend(rows);pg=data.get('pagination')
  if not isinstance(pg,dict)or type(pg.get('hasNextPage'))is not bool or 'nextCursor'not in pg:raise Stop('INVENTORY_SCHEMA')
  if not pg['hasNextPage']:
   if pg.get('nextCursor')not in(None,''):raise Stop('INVENTORY_SCHEMA')
   return items
  cursor=pg.get('nextCursor')
  if not isinstance(cursor,str)or not cursor or len(cursor)>256 or cursor in seen:raise Stop('INVENTORY_CURSOR')
  seen.add(cursor)
 raise Stop('INVENTORY_LIMIT')
def inventory(token,transport=request,mono=time.monotonic):
 end=mono()+120
 return {k:len(listing(path,key,token,transport,mono,end))for k,(path,key)in CATEGORIES.items()}
