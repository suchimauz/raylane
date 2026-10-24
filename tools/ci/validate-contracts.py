#!/usr/bin/env python3
"""Offline OpenAPI3.1 / Draft202012 validation of a supplied, bounded local bundle."""
import argparse
import json
from pathlib import Path
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

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', required=True)
    p.add_argument('--openapi', action='append', default=[])
    p.add_argument('--schema', action='append', default=[])
    p.add_argument('--instance', nargs=2, action='append', default=[], metavar=('SCHEMA', 'INSTANCE'))
    args = p.parse_args()
    b = Bundle(args.bundle)
    try:
        for name in args.openapi:
            b.validate(name, 'openapi')
        for name in args.schema:
            b.validate(name, 'schema')
        for name, value in args.instance:
            schema = b.validate(name, 'schema')
            instance = b.load(b.local_path(value))
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
