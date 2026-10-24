#!/usr/bin/env python3
"""Offline OpenAPI3.1 / Draft202012 validation of a supplied, bounded local bundle."""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, unquote
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from jsonschema_path import SchemaPath
from openapi_spec_validator import OpenAPIV31SpecValidator

class GuardError(ValueError):
    pass

class UniqueSafeLoader(yaml.SafeLoader):
    pass

def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise GuardError('duplicate or non-string mapping key')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result

UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)

class Bundle:
    def __init__(self, root):
        raw = Path(root).absolute()
        if raw.is_symlink() or any(p.is_symlink() for p in raw.parents):
            raise GuardError('symlink bundle root')
        self.root = raw.resolve(strict=True)
        self.docs = {}
        self.active = set()

    def local_path(self, relative):
        # Ref percent encoding is deliberately unsupported, not decoded ambiguously.
        if '%' in relative or '\\' in relative:
            raise GuardError('encoded/backslash path forbidden')
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts:
            raise GuardError('absolute/traversal path forbidden')
        candidate = self.root / p
        for part in [candidate, *candidate.parents]:
            if part == self.root.parent:
                break
            if part.is_symlink():
                raise GuardError('symlink input forbidden')
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(self.root) or not resolved.is_file():
            raise GuardError('input outside bundle')
        return resolved

    def load(self, path):
        uri = path.as_uri()
        if uri in self.docs:
            return self.docs[uri]
        if len(self.docs) >= 128 or path.stat().st_size > 2 * 1024 * 1024:
            raise GuardError('bundle file count/size limit')
        doc = yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueSafeLoader)
        # Root schema identity is not a fetch scope in this offline profile.
        if isinstance(doc, dict) and '$schema' in doc:
            doc.pop('$id', None)
        self.docs[uri] = doc
        self.scan(doc, path, set(), 0)
        return doc

    def ref_target(self, ref, path):
        if not isinstance(ref, str):
            raise GuardError('reference must be string')
        u = urlsplit(ref)
        if u.scheme or u.netloc or u.query or ref.startswith('/'):
            raise GuardError('external/absolute reference forbidden')
        target = path if not u.path else self.local_path(str(path.parent.relative_to(self.root) / u.path))
        document = self.load(target)
        fragment = unquote(u.fragment)
        if fragment and not fragment.startswith('/'):
            raise GuardError('named anchors unsupported by offline CI profile')
        node = document
        if fragment:
            for token in fragment[1:].split('/'):
                token = token.replace('~1', '/').replace('~0', '~')
                try:
                    node = node[int(token)] if isinstance(node, list) else node[token]
                except (KeyError, IndexError, ValueError, TypeError):
                    raise GuardError('unresolved local reference') from None
        return target.as_uri() + ('#' + u.fragment if u.fragment else '')

    def scan(self, node, path, parents, depth):
        if depth > 64:
            raise GuardError('nesting limit')
        if isinstance(node, (dict, list)):
            if id(node) in parents:
                raise GuardError('recursive YAML alias')
            parents = parents | {id(node)}
        if isinstance(node, dict):
            # $id changes resolution scope; unsupported instead of accidental network use.
            if '$id' in node or '$dynamicRef' in node:
                raise GuardError('$id/$dynamicRef unsupported in offline CI profile')
            if '$ref' in node:
                self.ref_target(node['$ref'], path)
            for value in node.values():
                self.scan(value, path, parents, depth + 1)
        elif isinstance(node, list):
            for value in node:
                self.scan(value, path, parents, depth + 1)

    def cached(self, uri):
        key = uri.split('#', 1)[0]
        if key not in self.docs:
            raise GuardError('uncached resource access denied')
        return self.docs[key]

    def validate(self, relative, kind):
        path = self.local_path(relative)
        doc = self.load(path)  # all references pre-scanned BEFORE validator invocation
        if kind == 'openapi':
            if not isinstance(doc, dict) or doc.get('openapi') not in ('3.1.0', '3.1.1', '3.1.2'):
                raise GuardError('OpenAPI 3.1.x exact supported dialect required')
            handlers = {scheme: self.cached for scheme in ('<all_urls>', 'http', 'https', 'file')}
            schema_path = SchemaPath.from_dict(doc, base_uri=path.as_uri(), handlers=handlers)
            OpenAPIV31SpecValidator(schema_path).validate()
            # OAS base meta-schema allows schema vocabularies: validate actual
            # Schema Objects with the established Draft202012 implementation too.
            def schema_objects(node):
                if isinstance(node, dict):
                    for key, value in node.items():
                        if key == 'schema' and isinstance(value, (dict, bool)):
                            Draft202012Validator.check_schema(value)
                        elif key == 'schemas' and isinstance(value, dict):
                            for item in value.values():
                                Draft202012Validator.check_schema(item)
                        schema_objects(value)
                elif isinstance(node, list):
                    for item in node:
                        schema_objects(item)
            schema_objects(doc)
            for cached_doc in self.docs.values():
                if isinstance(cached_doc, dict) and '$schema' in cached_doc:
                    Draft202012Validator.check_schema(cached_doc)
        elif kind == 'schema':
            # Root $id is allowed as a document identity only; may not alter nested scope.
            Draft202012Validator.check_schema(doc)
            if doc.get('$schema') != 'https://json-schema.org/draft/2020-12/schema':
                raise GuardError('Draft202012 required')
        else:
            raise GuardError('unknown kind')
        return doc

    @staticmethod
    def limits_table(path):
        """Parse the documentation limits table: [(operationId, bytes)] from rows
        of the form '| ... (operationId) | <digits> ... |'. Extracts the
        parenthesised operationId and the leading integer of the value cell."""
        text = Path(path).read_text(encoding='utf-8')
        rows = []
        for line in text.splitlines():
            m = re.match(r'^\|\s*((?:GET|PUT|POST|PATCH|DELETE)[^|]*)\|([^|]*)\|?[^|]*', line)
            if not m:
                continue
            label = m.group(1).strip()
            value = re.search(r'\b(\d+)\b', m.group(2))
            if not value:
                continue
            op = re.search(r'\((\w+)\)', label)
            rows.append((op.group(1) if op else label, int(value.group(1))))
        return rows

    @staticmethod
    def body_limit_semantics(doc, limits_table=None):
        """OpenAPI body-limit and conflict-response consistency (B1/B2).

        Repository-contract checks over the parsed document: every operation
        with a requestBody declares a positive finite integer
        `x-body-limit-bytes`; each such operation also declares the 413
        response; each create whose contract promises a conflict path
        (createNode, createSubscription, createRuleSource — createRule
        already carried it) declares a structurally referenced 409; and the
        documented limits table lists exactly the request-body operations
        with the values the contract declares. Tests inspect contracts, not
        a running HTTP server; nothing here executes HTTP.
        """
        if not isinstance(doc, dict) or not isinstance(doc.get('paths'), dict):
            return  # not an OpenAPI document
        methods = ('get', 'put', 'post', 'patch', 'delete', 'options', 'head', 'trace')
        conflict_creates = {'createNode', 'createSubscription', 'createRuleSource', 'createRule'}
        declared = {}
        for path, item in doc['paths'].items():
            if not isinstance(item, dict):
                continue
            for method in methods:
                op = item.get(method)
                if not isinstance(op, dict) or 'requestBody' not in op:
                    continue
                oid = op.get('operationId', '%s %s' % (method, path))
                responses = op.get('responses')
                if not isinstance(responses, dict):
                    responses = {}
                if '413' not in responses:
                    raise GuardError('openapi: operation %s has a requestBody but no 413 response' % oid)
                limit = op.get('x-body-limit-bytes')
                if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                    raise GuardError('openapi: operation %s lacks a positive finite integer x-body-limit-bytes' % oid)
                if oid in conflict_creates and '409' not in responses:
                    raise GuardError('openapi: create operation %s lacks the required 409 response' % oid)
                declared[oid] = limit
        # Base64-decoded payload bound inside an encoded request body: the
        # restore body is base64 text, so its decoded archive length is
        # bounded by the archive schema bound through base64 arithmetic.
        schemas = ((doc.get('components') or {}).get('schemas') or {})
        restore = schemas.get('RestoreRequest')
        if isinstance(restore, dict):
            archive = ((restore.get('properties') or {}).get('archive') or {})
            encoded_field = archive.get('maxLength')
            body_limit = declared.get('restoreBackup')
            if isinstance(encoded_field, int) and isinstance(body_limit, int):
                if 4 * body_limit // 3 < encoded_field:
                    raise GuardError('openapi: restoreBackup x-body-limit-bytes %d cannot carry the archive maxLength %d encoded base64' % (body_limit, encoded_field))
                decoded_bound = 3 * encoded_field // 4
                if decoded_bound * 4 // 3 > body_limit:
                    raise GuardError('openapi: restoreBackup decoded archive bound exceeds its encoded body limit')
        if limits_table is not None:
            method_to_op = {}
            declared_keys = {}
            for path, item in doc['paths'].items():
                if not isinstance(item, dict):
                    continue
                for method in methods:
                    op = item.get(method)
                    if isinstance(op, dict) and 'requestBody' in op and isinstance(op.get('operationId'), str):
                        key = (method.upper(), path)
                        method_to_op[key] = op['operationId']
            table = {}
            for key, value in limits_table:
                if key in declared:
                    table[key] = value
                else:
                    m = re.match(r'^(GET|PUT|POST|PATCH|DELETE)\s+(\S+)\s*$', key)
                    resolved = method_to_op.get((m.group(1), m.group(2))) if m else None
                    if resolved is None:
                        raise GuardError('openapi: limits table row %r names no request-body operation' % key)
                    if resolved in table and table[resolved] != value:
                        raise GuardError('openapi: limits table contradicts itself for %s' % resolved)
                    table[resolved] = value
            missing = sorted(set(declared) - set(table))
            extra = sorted(set(table) - set(declared))
            if missing:
                raise GuardError('openapi: limits table misses body operations: %s' % ', '.join(missing))
            if extra:
                raise GuardError('openapi: limits table names non-body operations: %s' % ', '.join(extra))
            for oid, value in sorted(table.items()):
                if value != declared[oid]:
                    raise GuardError('openapi: limits table value %r for %s contradicts x-body-limit-bytes %r' % (value, oid, declared[oid]))

    @staticmethod
    def profile_semantics(doc):
        """Focused capability-profile consistency (B3).

        Cross-field rules a JSON Schema cannot express: dependency target
        membership within the same protocol, ordered numeric/length/item
        bounds, default validity against the declared constraints, enum
        default membership, allowedValues element type and uniqueness, and
        secret/known consistency. Uses the established jsonschema Draft202012
        validator to check that each default actually satisfies the per-field
        constraints; it does not build a general parser or compiler.
        """
        if not isinstance(doc, dict) or not isinstance(doc.get('protocols'), dict):
            return  # not a capability-profile document
        type_map = {
            'string': {'string'}, 'integer': {'integer'}, 'boolean': {'boolean'},
            'array': {'array'}, 'object': {'object'}, 'enum': set(),
        }
        for proto_name, proto in doc['protocols'].items():
            if not isinstance(proto, dict) or not isinstance(proto.get('fields'), dict):
                raise GuardError('profile: protocol %s lacks a fields object' % proto_name)
            fields = proto['fields']
            for fname, spec in fields.items():
                if not isinstance(spec, dict):
                    raise GuardError('profile: field %s.%s is not an object' % (proto_name, fname))
                ftype = spec.get('type')
                classification = spec.get('classification')
                # secret/known consistency
                if classification == 'secret' and 'default' in spec:
                    raise GuardError('profile: secret field %s.%s must not carry a default' % (proto_name, fname))
                # ordered bounds
                if 'minimum' in spec and 'maximum' in spec and spec['minimum'] > spec['maximum']:
                    raise GuardError('profile: field %s.%s minimum exceeds maximum' % (proto_name, fname))
                if 'minLength' in spec and 'maxLength' in spec and spec['minLength'] > spec['maxLength']:
                    raise GuardError('profile: field %s.%s minLength exceeds maxLength' % (proto_name, fname))
                if 'minItems' in spec and 'maxItems' in spec and spec['minItems'] > spec['maxItems']:
                    raise GuardError('profile: field %s.%s minItems exceeds maxItems' % (proto_name, fname))
                # dependency target membership (same protocol)
                deps = spec.get('dependencies')
                if deps is not None:
                    if not isinstance(deps, dict):
                        raise GuardError('profile: field %s.%s dependencies not an object' % (proto_name, fname))
                    for key in ('requires', 'incompatibleWith'):
                        targets = deps.get(key)
                        if targets is None:
                            continue
                        if not isinstance(targets, list):
                            raise GuardError('profile: field %s.%s dependencies.%s not an array' % (proto_name, fname, key))
                        for t in targets:
                            if t not in fields:
                                raise GuardError('profile: field %s.%s %s undeclared dependency %r' % (proto_name, fname, key, t))
                # allowedValues type/uniqueness and enum default membership
                allowed = spec.get('allowedValues')
                if allowed is not None:
                    if ftype != 'enum':
                        raise GuardError('profile: field %s.%s allowedValues on non-enum type' % (proto_name, fname))
                    if not isinstance(allowed, list) or not allowed:
                        raise GuardError('profile: field %s.%s allowedValues must be a non-empty array' % (proto_name, fname))
                    seen = set()
                    for v in allowed:
                        if isinstance(v, (list, dict)):
                            raise GuardError('profile: field %s.%s allowedValues has non-scalar element' % (proto_name, fname))
                        marker = (type(v).__name__, v if isinstance(v, (str, int, bool)) else None)
                        if marker in seen:
                            raise GuardError('profile: field %s.%s allowedValues has duplicate %r' % (proto_name, fname, v))
                        seen.add(marker)
                # default validity: build the per-field constraint schema and
                # validate the default with the established Draft202012 validator.
                if 'default' in spec and classification == 'known':
                    sub = {}
                    if ftype == 'enum':
                        sub['enum'] = allowed if isinstance(allowed, list) else []
                    elif ftype == 'array':
                        sub['type'] = 'array'
                        it = spec.get('itemType')
                        if it in ('string', 'integer'):
                            sub['items'] = {'type': it}
                        if 'minItems' in spec:
                            sub['minItems'] = spec['minItems']
                        if 'maxItems' in spec:
                            sub['maxItems'] = spec['maxItems']
                    elif ftype == 'integer':
                        sub['type'] = 'integer'
                        if 'minimum' in spec:
                            sub['minimum'] = spec['minimum']
                        if 'maximum' in spec:
                            sub['maximum'] = spec['maximum']
                    elif ftype == 'string':
                        sub['type'] = 'string'
                        if 'minLength' in spec:
                            sub['minLength'] = spec['minLength']
                        if 'maxLength' in spec:
                            sub['maxLength'] = spec['maxLength']
                        if 'pattern' in spec:
                            sub['pattern'] = spec['pattern']
                    elif ftype == 'boolean':
                        sub['type'] = 'boolean'
                    elif ftype == 'object':
                        sub['type'] = 'object'
                    if sub:
                        errs = list(Draft202012Validator(sub).iter_errors(spec['default']))
                        if errs:
                            raise GuardError('profile: field %s.%s default violates declared constraints' % (proto_name, fname))
                    # enum default membership is covered by the enum sub-schema above.

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', required=True)
    p.add_argument('--openapi', action='append', default=[])
    p.add_argument('--schema', action='append', default=[])
    p.add_argument('--limits-table', help='Markdown file with the | Operation | x-body-limit-bytes | documentation table to cross-check')
    p.add_argument('--instance', nargs=2, action='append', default=[], metavar=('SCHEMA', 'INSTANCE'))
    args = p.parse_args()
    b = Bundle(args.bundle)
    try:
        for name in args.openapi:
            doc = b.validate(name, 'openapi')
            if args.limits_table:
                # The documentation table lives outside the contract bundle;
                # it is read as plain Markdown text, never as a contract ref.
                Bundle.body_limit_semantics(doc, Bundle.limits_table(args.limits_table))
        for name in args.schema:
            b.validate(name, 'schema')
        for name, value in args.instance:
            schema = b.validate(name, 'schema')
            instance = b.load(b.local_path(value))
            Bundle.profile_semantics(instance)
            registry = Registry(retrieve=lambda uri: Resource.from_contents(b.cached(uri), default_specification=DRAFT202012))
            registry = registry.with_resources((uri, Resource.from_contents(doc, default_specification=DRAFT202012)) for uri, doc in b.docs.items())
            Draft202012Validator(schema, registry=registry).validate(instance)
    except Exception as error:
        # Parser/validator messages may contain raw imported values: never echo them.
        print('FAIL: contract validation rejected (' + type(error).__name__ + ')', file=sys.stderr)
        return 1
    print('PASS: offline full-validator checks; files=' + str(len(b.docs)))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
