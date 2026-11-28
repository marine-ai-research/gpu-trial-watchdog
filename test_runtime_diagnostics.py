"""Offline synthetic schemas and emergency cleanup; no network or credentials."""
import sys,pathlib
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import unittest,copy,json,io,contextlib,ast
from unittest.mock import patch
import controller as c
import runtime_diagnostics as d
import terminate_trial as t
import reconcile_resources as inv
from test_watchdog import policy,pod,Clock,NOW,KEY

class Tests(unittest.TestCase):
 def setUp(self):d.recorder.reset()
 def test_runtime_schema_matrix(self):
  for value,k,state in [(None,'NULL','NULL'),({},'OBJECT','EMPTY'),([], 'ARRAY','EMPTY'),('','STRING','EMPTY'),(False,'BOOLEAN','NOT_APPLICABLE')]:
   with self.subTest(k=k):
    data=d.snapshot({'runtime':value,'ports':[]});self.assertEqual(data['runtime']['type'],k);self.assertEqual(data['runtime']['state'],state)
 def test_missing_runtime(self):self.assertEqual(d.snapshot({})['runtime']['presence'],'MISSING')
 def test_runtime_ports_matrix_and_acceptance(self):
  for value,accepted in [(None,False),([],True),({},False),('',False),('bad',False),(0,False),(False,False),([{}],False)]:
   with self.subTest(value=value):
    item=pod();item['runtime']={'ports':value};data=d.snapshot(item)
    self.assertEqual(c.runtime_mapping_compatible(item),accepted)
    self.assertEqual(data['runtime_ports']['type'],d.kind(value))
    self.assertEqual(data['runtime_ports']['state'],'NULL'if value is None else'EMPTY'if type(value)in(list,dict,str)and not value else'NON_EMPTY'if type(value)in(list,dict,str)else'NOT_APPLICABLE')
 def test_missing_ports(self):self.assertEqual(d.snapshot({'runtime':{}})['runtime_ports']['presence'],'MISSING')
 def test_configured_ports_matrix(self):
  for obj,expected in [({},False),({'ports':None},False),({'ports':[]},True),({'ports':['22/tcp']},False),({'ports':''},False)]:self.assertEqual(d.snapshot(obj)['configured_ports_explicit_empty'],expected)
 def test_populated_mapping_sanitised(self):
  raw={'private':22,'public':34446,'type':'tcp','ip':'203.0.113.9'}
  out=d.mapping(raw);self.assertEqual(out['protocol'],'tcp');self.assertEqual(out['mapping'],'EXTERNAL_PORT_PRESENT');self.assertNotIn(raw['ip'],json.dumps(out));self.assertNotIn('34446',json.dumps(out))
 def test_protocol_allowlist_and_malicious_fields(self):
  secret='SECRET https://private.invalid 192.0.2.1'
  value={'private':secret,'public':secret,'type':secret,'ip':secret,secret:secret}
  out=d.mapping(value);self.assertNotIn(secret,json.dumps(out));self.assertTrue(out['unknown_keys_present']);self.assertEqual(out['protocol'],'OTHER_OR_MISSING')
 def test_protocol_classes(self):
  for v in ['tcp','http','udp','TCP',None,{},1]:self.assertEqual(d.mapping({'type':v})['protocol'],v if type(v)is str and v in('tcp','http','udp')else'OTHER_OR_MISSING')
 def test_port_classifications(self):
  for value,want in [(None,'NULL'),(0,'ZERO'),(22,'VALID_PORT'),(65535,'VALID_PORT'),(65536,'INVALID'),(-1,'INVALID'),(True,'INVALID'),('22','INVALID')]:self.assertEqual(d.port({'x':value},'x'),want)
 def test_mapping_count_bounded(self):
  data=d.snapshot({'runtime':{'ports':[{}]*10000}});self.assertEqual(data['mapping_count_capped'],8);self.assertTrue(data['mapping_count_over_cap']);self.assertEqual(len(data['mappings']),8)
 def test_malformed_entries(self):
  data=d.snapshot({'runtime':{'ports':[None,False,1,'secret',[],{}]}});self.assertEqual(len(data['mappings']),6);self.assertNotIn('secret',json.dumps(data))
 def test_transitions_null_empty_populated(self):
  item=pod();d.recorder.observe(item,'BOUND');item['runtime']={'ports':[]};d.recorder.observe(item,'VALIDATED');item['runtime']['ports']=[{'private':22,'public':12345,'type':'tcp','ip':'192.0.2.2'}];d.recorder.observe(item,'REJECTED')
  self.assertEqual([e['changed_since_binding']for e in d.recorder.events],[False,True,True]);self.assertEqual(d.recorder.events[-1]['phase'],'REJECTED')
 def test_repeated_unchanged_suppressed(self):
  item=pod();d.recorder.observe(item,'BOUND')
  for _ in range(100):d.recorder.observe(item,'VALIDATED')
  self.assertEqual(len(d.recorder.events),1)
 def test_output_bound_preserves_latest_rejection(self):
  item=pod();d.recorder.observe(item,'BOUND')
  for n in range(100):item['runtime']={'ports':None if n%2 else[]};d.recorder.observe(item,'REJECTED')
  with contextlib.redirect_stdout(io.StringIO())as out:d.recorder.flush()
  lines=out.getvalue().splitlines();self.assertLessEqual(len(lines),18);self.assertIn('RUNTIME_DIAGNOSTIC_TRUNCATED',out.getvalue());self.assertEqual(d.recorder.events,[])
 def test_no_output_before_cleanup(self):
  with contextlib.redirect_stdout(io.StringIO())as out:d.safe('observe',pod(),'BOUND');d.safe('delete','DISPATCH_ATTEMPT')
  self.assertEqual(out.getvalue(),'')
 def cleanup(self,broken=False,response=204):
  receipt,_=c.bind(policy(),pod(),NOW,NOW);clock=Clock();calls=[];out=io.StringIO()
  def tx(method,path,key,**kw):
   calls.append((method,path,clock.mono()));self.assertEqual(out.getvalue(),'');return (response,None)if method=='DELETE'else(404,None)
  with patch.object(d,'snapshot',side_effect=RuntimeError('SECRET'))if broken else contextlib.nullcontext():
   with contextlib.redirect_stdout(out):result=c.terminate(receipt,KEY,tx,clock.time,clock.sleep,clock.mono)
  return result,calls,out.getvalue()
 def test_delete_evidence_after_absence_readback(self):
  result,calls,out=self.cleanup();self.assertTrue(result);self.assertEqual([x[:2]for x in calls],[('DELETE','/pods/pod_test123'),('GET','/pods/pod_test123')]);self.assertIn('DISPATCH_ATTEMPT',out);self.assertIn('"http_status": 204',out);self.assertNotIn(KEY,out);self.assertNotIn('pod_test123',out)
 def test_delete_404_evidence(self):self.assertIn('"http_status": 404',self.cleanup(response=404)[2])
 def test_recorder_failure_cannot_prevent_delete(self):
  with patch.object(d.recorder,'delete',side_effect=RuntimeError('SECRET')),patch.object(d.recorder,'flush',side_effect=RuntimeError('SECRET')):
   result,calls,out=self.cleanup();self.assertTrue(result);self.assertEqual(calls[0][0],'DELETE');self.assertEqual(out,'')
 def test_snapshot_failure_is_contained(self):
  with patch.object(d,'snapshot',side_effect=RuntimeError('SECRET')):receipt,ok=c.bind(policy(),pod(),NOW,NOW)
  self.assertTrue(ok);self.assertTrue(receipt['approved'])
 def test_output_failure_contained(self):
  d.recorder.observe(pod(),'BOUND')
  with patch('builtins.print',side_effect=BrokenPipeError('SECRET')):d.recorder.flush()
  self.assertEqual(d.recorder.events,[])
 def test_initial_bad_runtime_never_deletes(self):
  item=pod();item['runtime']={'ports':[{}]}
  with contextlib.redirect_stdout(io.StringIO()),patch.object(c,'_terminate_v5')as terminate,self.assertRaises(c.Stop):c.bind(policy(),item,NOW,NOW)
  terminate.assert_not_called()
 def test_startup_transition_emergency_integration(self):
  clock=Clock();state={'lists':0,'reads':0,'deleted':False};calls=[];out=io.StringIO()
  def tx(method,path,key,**kw):
   calls.append((method,path,clock.mono()))
   if path in dict(inv.CATEGORIES.values()):
    name=dict(inv.CATEGORIES.values())[path]
    if path=='/pods':state['lists']+=1
    return 200,{name:[pod()]if path=='/pods'and state['lists']>=2 and not state['deleted']else[],'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':state['deleted']=True;return 204,None
   if state['deleted']:return 404,None
   state['reads']+=1;item=pod();item['runtime']={'ports':[]if state['reads']==1 else[{'type':'tcp','private':22,'public':23456,'ip':'192.0.2.4'}]};return 200,item
  with contextlib.redirect_stdout(out),self.assertRaisesRegex(c.Stop,'TARGET_POLICY_CHANGED'):c.watch(policy(),KEY,tx,clock.time,clock.mono,clock.sleep)
  self.assertEqual(next(at for m,p,at in calls if m=='DELETE'),15);self.assertIn('RUNTIME_PORTS',out.getvalue());self.assertIn('TARGET_ABSENT',out.getvalue());self.assertIn('RECONCILIATION',out.getvalue());self.assertNotIn('192.0.2.4',out.getvalue())
 def test_transport_exception_no_raw_leak_and_bounded_retries(self):
  receipt,_=c.bind(policy(),pod(),NOW,NOW);clock=Clock();calls=[]
  def tx(*args,**kw):calls.append(args[:2]);raise RuntimeError('SECRET')
  with contextlib.redirect_stdout(io.StringIO())as out,self.assertRaisesRegex(t.Stop,'TERMINATION_UNCONFIRMED'):c.terminate(receipt,KEY,tx,clock.time,clock.sleep,clock.mono)
  self.assertEqual(len(calls),3);self.assertNotIn('SECRET',out.getvalue());self.assertEqual(out.getvalue().count('DISPATCH_ATTEMPT'),3)

if __name__=='__main__':unittest.main()
