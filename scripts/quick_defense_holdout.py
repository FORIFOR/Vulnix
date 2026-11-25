"""Declared ground truth for a second, offline quick-defense fixture.

No target program from this directory is executed by the browser or OSS comparison.
"""
import base64
import hashlib
import json
from pathlib import Path


def write_fixture(root: Path) -> list[dict]:
    fixture_marker = base64.b32encode(hashlib.sha256(b"vulnix public benchmark invalid synthetic credential")
                                      .digest()).decode().lower()[:36]
    token_prefix = "gh" + "p_"
    files = {
        ".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash"]}}, indent=2),
        "cloudformation.json": json.dumps({"Resources": {
            "AdminFirewall": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [
                {"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22},
            ]}},
            "ApiStage": {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {"DefaultRouteSettings": {
                "ThrottlingRateLimit": 10, "ThrottlingBurstLimit": 15,
            }}},
        }}, indent=2),
        "database/render.ts": (
            "export function show(req, element) {\n"
            "  const content = req.params.title;\n"
            "  element.innerHTML = content;\n}\n"
            "export function showText(req, element) {\n"
            "  const content = req.params.title;\n"
            "  element.textContent = content;\n}\n"
        ),
        "auth-options.ts": (
            'import { SAML } from "@node-saml/node-saml";\n'
            "const sp = new SAML({ wantAssertionsSigned: true, wantAuthnResponseSigned: true });\n"
            "const otherSp = new SAML(loadOptions());\n"
            'import { parseXml } from "libxmljs";\n'
            "const parsed = parseXml(input, { noent: true, dtdload: false, nonet: true });\n"
        ),
        "Dockerfile": "FROM alpine:3.22\nUSER 0\n",
        "network-policy.json": json.dumps({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "synthetic-egress"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]},
        }, indent=2),
        "role-manifest.json": json.dumps({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "synthetic-role"},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}],
        }, indent=2),
        "requirements.txt": "synthetic-python==1.1rc1\nsynthetic-fixed==3.0\n",
        "go.mod": "module example.invalid/holdout\n\ngo 1.23.0\n\nrequire example.invalid/dependency v1.3.0\n",
        "package-lock.json": json.dumps({
            "name": "defense-holdout", "lockfileVersion": 3,
            "packages": {"": {"name": "defense-holdout", "version": "1.0.0",
                              "dependencies": {"fixture-npm": "2.1.0"}},
                         "node_modules/fixture-npm": {"version": "2.1.0", "integrity": "sha512-synthetic",
                                                      "resolved": "https://registry.example.invalid/fixture.tgz"}},
        }, indent=2),
        "literal.ts": (
            "// Deliberately invalid synthetic credential marker for the secret scanner.\n"
            'const sample = "-----BEGIN PRIVATE KEY-----\\nSYNTHETIC_ONLY\\n-----END PRIVATE KEY-----";\n'
            f'const fixtureOnly = "{token_prefix}{fixture_marker}";\n'
        ),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    rules = [
        ("CVE-2099-40101", "npm", "fixture-npm", "SEMVER", "2.0.0", "2.2.0"),
        ("CVE-2099-40102", "PyPI", "synthetic-python", "ECOSYSTEM", "1.0", "1.1"),
        ("CVE-2099-40103", "Go", "example.invalid/dependency", "SEMVER", "1.2.0", "1.4.0"),
        ("CVE-2099-40104", "PyPI", "synthetic-fixed", "ECOSYSTEM", "0", "3.0"),
    ]
    return [{
        "id": f"GHSA-fixture-{i:04d}", "aliases": [cve], "modified": "2026-11-25T00:00:00Z",
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{
            "type": kind, "events": [{"introduced": start}, {"fixed": fixed}],
        }]}],
    } for i, (cve, ecosystem, name, kind, start, fixed) in enumerate(rules, 1)]
