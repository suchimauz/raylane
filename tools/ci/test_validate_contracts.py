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

    # --- B3: capability-profile semantic consistency ---
    def _profile(self):
        return {
            'profileVersion': 1,
            'protocols': {
                'demo': {
                    'fields': {
                        'host': {'type':'string','classification':'known','required':True,'minLength':1,'maxLength':253},
                        'port': {'type':'integer','classification':'known','minimum':1,'maximum':65535,'default':443},
                        'mode': {'type':'enum','classification':'known','allowedValues':['a','b'],'default':'a'},
                        'tags': {'type':'array','classification':'known','itemType':'string','minItems':1,'maxItems':8},
                        'token': {'type':'string','classification':'secret','secret':True},
                    }
                }
            }
        }
    def _check_profile(self, doc, expect_ok):
        errs = []
        try:
            v.Bundle.profile_semantics(doc)
        except v.GuardError as e:
            errs.append(str(e))
        if expect_ok:
            self.assertEqual(errs, [], 'valid profile rejected: %s' % errs)
        else:
            self.assertTrue(errs, 'invalid profile accepted')
    def test_profile_positive(self):
        self._check_profile(self._profile(), expect_ok=True)
    def test_profile_wrong_default_type(self):
        d = self._profile(); d['protocols']['demo']['fields']['host']['default'] = 12345
        self._check_profile(d, expect_ok=False)
    def test_profile_dangling_dependency(self):
        d = self._profile(); d['protocols']['demo']['fields']['host']['dependencies'] = {'requires':['definitelyUndeclared']}
        self._check_profile(d, expect_ok=False)
    def test_profile_integer_boolean_distinction(self):
        d = self._profile(); d['protocols']['demo']['fields']['flag'] = {'type':'boolean','classification':'known','default':0}
        self._check_profile(d, expect_ok=False)
    def test_profile_enum_default_not_member(self):
        d = self._profile(); d['protocols']['demo']['fields']['mode']['default'] = 'zzz'
        self._check_profile(d, expect_ok=False)
    def test_profile_enum_default_wrong_type(self):
        d = self._profile(); d['protocols']['demo']['fields']['mode']['default'] = 123
        self._check_profile(d, expect_ok=False)
    def test_profile_reversed_integer_bounds(self):
        d = self._profile(); d['protocols']['demo']['fields']['port']['minimum'] = 70000; d['protocols']['demo']['fields']['port']['maximum'] = 1
        self._check_profile(d, expect_ok=False)
    def test_profile_reversed_length_bounds(self):
        d = self._profile(); d['protocols']['demo']['fields']['host']['minLength'] = 300; d['protocols']['demo']['fields']['host']['maxLength'] = 1
        self._check_profile(d, expect_ok=False)
    def test_profile_reversed_item_bounds(self):
        d = self._profile(); d['protocols']['demo']['fields']['tags']['minItems'] = 9; d['protocols']['demo']['fields']['tags']['maxItems'] = 1
        self._check_profile(d, expect_ok=False)
    def test_profile_secret_default_rejected(self):
        d = self._profile(); d['protocols']['demo']['fields']['token']['default'] = 'x'
        self._check_profile(d, expect_ok=False)
    def test_profile_allowed_values_duplicate(self):
        d = self._profile(); d['protocols']['demo']['fields']['mode']['allowedValues'] = ['a','a']
        self._check_profile(d, expect_ok=False)
    def test_profile_dependency_same_protocol_membership(self):
        # dependency on a field in ANOTHER protocol is a dangling reference
        d = self._profile(); d['protocols']['other'] = {'fields': {'ext': {'type':'string','classification':'known'}}}
        d['protocols']['demo']['fields']['host']['dependencies'] = {'requires':['ext']}
        self._check_profile(d, expect_ok=False)

    # --- B1/B2: OpenAPI body limits and conflict-response consistency ---
    def _openapi(self):
        repo = Path(__file__).resolve().parents[2]
        return v.Bundle(repo / 'contracts').validate('openapi.yaml', 'openapi')
    def test_openapi_body_limits_and_conflicts(self):
        # Real repository contract: every request-body operation has a finite
        # byte bound + 413, creates carry the typed Conflict 409, and the
        # checker accepts the authored contract.
        v.Bundle.body_limit_semantics(self._openapi())
    def test_openapi_missing_409_is_rejected(self):
        # Regression: if a required create 409 disappears, the checker fails.
        import copy
        for path in ('/nodes', '/subscriptions', '/rule-sources', '/rules'):
            with self.subTest(path=path):
                d = copy.deepcopy(self._openapi())
                del d['paths'][path]['post']['responses']['409']
                with self.assertRaises(v.GuardError):
                    v.Bundle.body_limit_semantics(d)
    def test_openapi_untyped_409_is_rejected(self):
        # Nominal presence of 409 must not bypass the typed-response invariant:
        # a description-only Response Object is a valid generic OpenAPI
        # response but has lost the shared typed Conflict schema.
        import copy
        for path in ('/nodes', '/subscriptions', '/rule-sources', '/rules'):
            with self.subTest(path=path):
                d = copy.deepcopy(self._openapi())
                d['paths'][path]['post']['responses']['409'] = {'description': 'untyped arbitrary conflict'}
                with self.assertRaises(v.GuardError):
                    v.Bundle.body_limit_semantics(d)
    def test_openapi_wrong_ref_409_is_rejected(self):
        # A 409 referencing a different component (typed or not) is rejected.
        import copy
        for path in ('/nodes', '/subscriptions', '/rule-sources', '/rules'):
            with self.subTest(path=path):
                d = copy.deepcopy(self._openapi())
                d['paths'][path]['post']['responses']['409'] = {'$ref': '#/components/responses/PayloadTooLarge'}
                with self.assertRaises(v.GuardError):
                    v.Bundle.body_limit_semantics(d)
    def test_openapi_body_without_limit_or_413_is_rejected(self):
        import copy
        d = copy.deepcopy(self._openapi())
        del d['paths']['/bootstrap']['post']['x-body-limit-bytes']
        with self.assertRaises(v.GuardError):
            v.Bundle.body_limit_semantics(d)
        d = copy.deepcopy(self._openapi())
        del d['paths']['/bootstrap']['post']['responses']['413']
        with self.assertRaises(v.GuardError):
            v.Bundle.body_limit_semantics(d)
    def test_openapi_non_finite_or_nonpositive_limit_rejected(self):
        # Declared-bound decision logic at the boundary: the checker accepts
        # the declared limit value and rejects 0 / limit+1-style invalid
        # declarations (non-integer, non-positive, boolean). Contract values
        # only — no HTTP enforcement is executed here.
        import copy
        base = self._openapi()
        ok = copy.deepcopy(base)
        ok['paths']['/session']['post']['x-body-limit-bytes'] += 0  # exactly the limit
        v.Bundle.body_limit_semantics(ok)
        for bad in (0, -1, '1MiB', True, 1.5):
            with self.subTest(bad=bad):
                d = copy.deepcopy(base)
                d['paths']['/session']['post']['x-body-limit-bytes'] = bad
                with self.assertRaises(v.GuardError):
                    v.Bundle.body_limit_semantics(d)
    def test_openapi_limits_table_cross_check(self):
        repo = Path(__file__).resolve().parents[2]
        tbl = v.Bundle.limits_table(repo / 'docs/engineering/foundation-decisions.md')
        doc = self._openapi()
        v.Bundle.body_limit_semantics(doc, tbl)  # positive: docs agree with contract
        import copy
        with self.assertRaises(v.GuardError):  # contradicted value
            v.Bundle.body_limit_semantics(doc, [(o, 1 if o == 'restoreBackup' else l) for o, l in tbl])
        with self.assertRaises(v.GuardError):  # dropped row
            v.Bundle.body_limit_semantics(doc, [r for r in tbl if r[0] != 'createNode'])
        with self.assertRaises(v.GuardError):  # invented operation
            v.Bundle.body_limit_semantics(doc, tbl + [('nonexistentOperation', 10)])
    def test_openapi_restore_base64_bounds_consistent(self):
        # Encoded body limit must be able to carry the base64 archive field
        # bound; the decoded bound follows by base64 arithmetic. Contract
        # check only — no HTTP or restore execution.
        import copy
        doc = self._openapi()
        v.Bundle.body_limit_semantics(doc)  # positive: current values agree
        d = copy.deepcopy(doc)
        d['paths']['/restores']['post']['x-body-limit-bytes'] = 1024  # < encoded maxLength
        with self.assertRaises(v.GuardError):
            v.Bundle.body_limit_semantics(d)
        d = copy.deepcopy(doc)
        d['components']['schemas']['RestoreRequest']['properties']['archive']['maxLength'] = 10 ** 12
        with self.assertRaises(v.GuardError):
            v.Bundle.body_limit_semantics(d)

if __name__ == '__main__': unittest.main(verbosity=2)
