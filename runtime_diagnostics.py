"""Bounded value-free observations, buffered until termination attempts finish.

No network, clock, filesystem, credential or policy access. Never authorises.
"""
import json

def kind(value):
 return {type(None):'NULL',bool:'BOOLEAN',int:'NUMBER',float:'NUMBER',str:'STRING',list:'ARRAY',dict:'OBJECT'}.get(type(value),'UNEXPECTED')
def field(obj,key):
 if type(obj)is not dict or key not in obj:return {'presence':'MISSING','type':'MISSING','state':'MISSING'}
 v=obj[key];k=kind(v)
 state='NULL'if v is None else ('EMPTY'if len(v)==0 else'NON_EMPTY')if type(v)in(str,list,dict)else'NOT_APPLICABLE'
 return {'presence':'PRESENT','type':k,'state':state}
def port(obj,key):
 if key not in obj:return 'MISSING'
 v=obj[key]
 return 'NULL'if v is None else'ZERO'if type(v)is int and v==0 else'VALID_PORT'if type(v)is int and 1<=v<=65535 else'INVALID'
def mapping(value):
 if type(value)is not dict:return {'entry_type':kind(value)}
 protocol=value.get('type');protocol=protocol if type(protocol)is str and protocol in('tcp','http','udp')else'OTHER_OR_MISSING'
 a,b=port(value,'private'),port(value,'public')
 return {'entry_type':'OBJECT','protocol':protocol,'internal_port':a,'external_port':b,'mapping':'EXTERNAL_PORT_PRESENT'if b=='VALID_PORT'else'NO_VALID_EXTERNAL_PORT_REPORTED','ip_field':field(value,'ip'),'unknown_keys_present':len(value)>4 or any(k not in('private','public','type','ip')for k in value)}
def snapshot(pod):
 runtime=pod.get('runtime')if type(pod)is dict else None
 ports=runtime.get('ports')if type(runtime)is dict else None
 count=len(ports)if type(ports)is list else None
 return {'runtime':field(pod,'runtime'),'runtime_ports':field(runtime,'ports'),'mapping_count_capped':min(count,8)if count is not None else None,'mapping_count_over_cap':count>8 if count is not None else False,'mappings':[mapping(v)for v in ports[:8]]if type(ports)is list else [],'configured_ports':field(pod,'ports'),'configured_ports_explicit_empty':type(pod)is dict and type(pod.get('ports'))is list and pod['ports']==[]}

class Recorder:
 def __init__(self):self.reset()
 def reset(self):self.baseline=None;self.last=None;self.events=[];self.latest=None;self.omitted=0
 def observe(self,pod,phase):
  data=snapshot(pod)
  if phase=='BOUND':self.reset();self.baseline=data
  event={'event':'RUNTIME_SHAPE','phase':phase,'changed_since_binding':self.baseline is not None and data!=self.baseline,'changed_since_previous':self.last is not None and data!=self.last,'shape':data}
  if phase in('BOUND','REJECTED')or data!=self.last:
   if len(self.events)<16:self.events.append(event)
   else:self.omitted=min(10000,self.omitted+1)
   self.latest=event
  self.last=data
 def delete(self,stage,status=None):
  event={'event':'DELETE_EVIDENCE','stage':stage}
  if stage=='HTTP_RESPONSE':event['http_status']=status if type(status)is int and 100<=status<=599 else'UNEXPECTED_STATUS'
  if len(self.events)<32:self.events.append(event)
 def flush(self):
  events=self.events[:]
  if self.latest is not None and self.latest not in events:events.append(self.latest)
  if self.omitted:events.append({'event':'RUNTIME_DIAGNOSTIC_TRUNCATED','omitted_capped':self.omitted})
  self.reset()
  for event in events:
   try:print(json.dumps(event,sort_keys=True),flush=True)
   except BaseException:pass

recorder=Recorder()
def safe(method,*args):
 try:getattr(recorder,method)(*args)
 except BaseException:pass
