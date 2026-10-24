"""Isolated validator tests. Network is denied, not probed."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('validator', Path(__file__).with_name('validate-contracts.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
BASE = {'openapi':'3.1.0','info':{'title':'fixture','version':'1'},'paths':{'/test':{'get':{'responses':{'200':{'description':'OK'}}}}}}

class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.net = patch.object(socket.socket, 'connect', side_effect=AssertionError('NETWORK_DENIED'))
        self.net.start()
    def tearDown(self):
        self.net.stop()
        self.tmp.cleanup()
    def run_doc(self, doc, kind='openapi'):
        self.root.joinpath('doc.json').write_text(json.dumps(doc))
        return v.Bundle(self.root).validate('doc.json', kind)
    def test_positive_full_openapi(self): self.run_doc(BASE)
    def test_duplicate_yaml(self):
        self.root.joinpath('doc.yaml').write_text('openapi: 3.1.0\nopenapi: 3.0.0\n')
        with self.assertRaises(v.GuardError): v.Bundle(self.root).validate('doc.yaml','openapi')
    def test_duplicate_json(self):
        self.root.joinpath('doc.json').write_text('{"openapi":"3.1.0","openapi":"3.1.0"}')
        with self.assertRaises(v.GuardError): v.Bundle(self.root).validate('doc.json','openapi')
    def test_external_ref_preflight(self):
        for ref in ['https://invalid.example/schema','http://127.0.0.1/x','file:///etc/passwd','//host/x']:
            with self.subTest(ref=ref), patch.object(v.OpenAPIV31SpecValidator,'validate',side_effect=AssertionError('VALIDATOR_MUST_NOT_RUN')):
                d=copy.deepcopy(BASE); d['components']={'schemas':{'X':{'$ref':ref}}}
                with self.assertRaises(v.GuardError): self.run_doc(d)
    def test_dialect_downgrade(self):
        d=copy.deepcopy(BASE); d['openapi']='3.0.3'
        with self.assertRaises(v.GuardError): self.run_doc(d)
    def test_invalid_response(self):
        d=copy.deepcopy(BASE); d['paths']['/test']['get']['responses']['200']={}
        with self.assertRaises(Exception): self.run_doc(d)
    def test_bad_ref(self):
        d=copy.deepcopy(BASE); d['components']={'schemas':{'X':{'$ref':'#/components/schemas/NO'}}}
        with self.assertRaises(v.GuardError): self.run_doc(d)
    def test_schema_error_in_openapi(self):
        d=copy.deepcopy(BASE); d['components']={'schemas':{'X':{'type':'NOT_A_TYPE'}}}
        with self.assertRaises(Exception): self.run_doc(d)
    def test_positive_local_file_ref(self):
        self.root.joinpath('response.json').write_text('{"description":"local"}')
        d=copy.deepcopy(BASE); d['paths']['/test']['get']['responses']['200']={'$ref':'response.json'}
        self.run_doc(d)
    def test_traversal_and_encoded_path(self):
        for ref in ['../outside.json','#badanchor','%2e%2e/out.json']:
            d=copy.deepcopy(BASE); d['components']={'schemas':{'X':{'$ref':ref}}}
            with self.assertRaises(v.GuardError): self.run_doc(d)
    def test_symlink_ref(self):
        self.root.joinpath('link.json').symlink_to('/etc/passwd')
        d=copy.deepcopy(BASE); d['components']={'schemas':{'X':{'$ref':'link.json'}}}
        with self.assertRaises(v.GuardError): self.run_doc(d)
    def test_draft202012_positive_and_schema_error(self):
        self.run_doc({'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'https://example.invalid/id','type':'object'},'schema')
        with self.assertRaises(Exception): self.run_doc({'$schema':'https://json-schema.org/draft/2020-12/schema','type':42},'schema')
    def test_cli_schema_instance(self):
        import subprocess
        schema={'$schema':'https://json-schema.org/draft/2020-12/schema','type':'object','properties':{'n':{'type':'integer'}},'required':['n']}
        self.root.joinpath('schema.json').write_text(json.dumps(schema))
        for value, code in [({'n':1},0),({'n':'bad'},1)]:
            self.root.joinpath('instance.json').write_text(json.dumps(value))
            run=subprocess.run([__import__('sys').executable,str(Path(__file__).with_name('validate-contracts.py')),'--bundle',str(self.root),'--instance','schema.json','instance.json'],capture_output=True,text=True)
            self.assertEqual(run.returncode,code,run.stderr)
    def test_alias_cycle(self):
        self.root.joinpath('doc.yaml').write_text('x: &x [*x]')
        with self.assertRaises(v.GuardError): v.Bundle(self.root).validate('doc.yaml','openapi')

if __name__ == '__main__': unittest.main(verbosity=2)
