"""Offline negative authorisation tests. Network attempts forbidden."""
import sys,pathlib
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import copy,contextlib,io,json,unittest
import test_watchdog as b
c,t,r=b.c,b.t,b.r
NETWORK=[]
def audit(event,args):
 if event.startswith('socket.'):
  NETWORK.append(event);raise RuntimeError('OFFLINE_ONLY')
sys.addaudithook(audit)
def policy():
 p=b.policy();p['data_center_ids']=['EU-FR-1','EUR-IS-2'];return p
def pod(dc='EU-FR-1'):
 x=b.pod();x['dataCenterId']=dc;return x
class Tests(unittest.TestCase):
 def test_each_centre_binds_exact_location(self):
  for dc in policy()['data_center_ids']:
   receipt,_=c.bind(policy(),pod(dc),b.NOW,b.NOW)
   self.assertEqual(receipt['data_center_id'],dc);self.assertEqual(receipt['deadline_unix']-receipt['created_unix'],6300)
 def test_reject_bad_allowlists_even_with_matching_hash(self):
  for ids in (None,'EU-FR-1',[],['EU-FR-1','EU-FR-1'],['EUR-IS-2','EU-FR-1'],['US-TX-3'],['EU-*'],['EU-FR-1 '],[None],['EU-FR-1']*17):
   p=policy();p['data_center_ids']=ids
   with self.subTest(ids=ids),self.assertRaises(t.Stop):c.load_policy(json.dumps(p),b.lock(p))
 def test_no_silent_legacy_field(self):
  p=policy();p['data_center_id']='EU-FR-1'
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(p),b.lock(p))
 def test_env_is_strict_scalar_csv(self):
  p=policy();e={'POLICY_APPROVED':'true','POLICY_BILLING_MODE':'prepaid','POLICY_AUTO_PAY_DISABLED':'true','POLICY_RISK_ACCEPTED':'true','POLICY_NAME':p['name'],'POLICY_IMAGE':p['image'],'POLICY_DATA_CENTER':'EU-FR-1,EUR-IS-2','POLICY_GPU_TYPE':p['gpu_type'],'POLICY_MAX_HOURLY_USD':'1.10','POLICY_GPU_COUNT':'1','POLICY_CONTAINER_DISK_GB':'50','POLICY_STARTUP_SHA256':p['startup_sha256']}
  self.assertEqual(c.policy_from_environment(e,b.lock(p)),p)
  for value in ('EU-FR-1, EUR-IS-2','EU-FR-1,','*','EUR-IS-2,EU-FR-1'):
   with self.subTest(value=value),self.assertRaises(t.Stop):c.policy_from_environment(dict(e,POLICY_DATA_CENTER=value),b.lock(p))
 def test_policy_expansion_requires_new_hash(self):
  p=policy();p['data_center_ids'].append('EUR-NO-1')
  with self.assertRaises(t.Stop):c.load_policy(json.dumps(p),b.lock(policy()))
 def test_location_drift_even_within_allowlist_rejected(self):
  receipt,_=c.bind(policy(),pod(),b.NOW,b.NOW)
  self.assertFalse(c.valid_target(policy(),pod('EUR-IS-2'),receipt))
 def test_missing_unexpected_non_europe_locations_never_bind(self):
  for dc in (None,'','US-TX-3','EU-NL-1','eu-fr-1','EU-FR-1 '):
   with self.subTest(dc=dc),self.assertRaises(t.Stop):c.bind(policy(),pod(dc),b.NOW,b.NOW)
 def run_watch(self,mode):
  clock=b.Clock();calls=[];state={'lists':0,'deleted':False}
  def tx(method,path,token,**kw):
   calls.append((method,path))
   if path in dict(r.CATEGORIES.values()):
    key=dict(r.CATEGORIES.values())[path];rows=[]
    if path=='/pods':
     state['lists']+=1
     if state['lists']>=2 and not state['deleted']:
      rows=[pod()]
      if mode=='unexpected':rows=[pod('EU-NL-1')]
      if mode=='multiple-initial' or(mode=='multiple-later'and state['lists']>=3):rows.append(dict(pod(),id='pod_other123'))
    return 200,{key:rows,'pagination':{'hasNextPage':False,'nextCursor':None}}
   if method=='DELETE':state['deleted']=True;return 204,None
   if state['deleted']:return 404,None
   if mode=='location-drift':return 200,pod('EUR-IS-2')
   return 200,pod()
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(t.Stop):c.watch(policy(),b.KEY,tx,clock.time,clock.mono,clock.sleep)
  return calls
 def test_multiple_initial_grants_no_delete(self):
  self.assertFalse(any(m=='DELETE'for m,p in self.run_watch('multiple-initial')))
 def test_initial_unexpected_centre_grants_no_delete(self):
  self.assertFalse(any(m=='DELETE'for m,p in self.run_watch('unexpected')))
 def test_multiple_after_binding_cleans_original_id_only(self):
  self.assertEqual([p for m,p in self.run_watch('multiple-later')if m=='DELETE'],['/pods/pod_test123'])
 def test_drift_after_binding_cleans_original_id_only(self):
  self.assertEqual([p for m,p in self.run_watch('location-drift')if m=='DELETE'],['/pods/pod_test123'])
 def test_same_identity_restrictions_at_both_locations(self):
  for dc in policy()['data_center_ids']:
   for key,val in [('ports',['22/tcp']),('mounts',{'persistent':{}}),('image','latest'),('cloud','COMMUNITY'),('disk',51),('cost',2),('entrypoint',['/bin/sh'])]:
    x=pod(dc);x[key]=val
    with self.subTest(dc=dc,key=key),self.assertRaises(t.Stop):c.bind(policy(),x,b.NOW,b.NOW)
 @classmethod
 def tearDownClass(cls):
  if NETWORK:raise AssertionError('Socket attempt during offline suite')
if __name__=='__main__':unittest.main(verbosity=2)
