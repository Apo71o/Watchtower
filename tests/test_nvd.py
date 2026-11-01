import json
from pathlib import Path

import pytest

from watchtower.core import nvd
from watchtower.core.assessment import assess
from watchtower.core.nmap_runner import Host, Port, parse_xml

FX = Path(__file__).parent / "fixtures"
SAMPLE = json.loads((FX / "nvd_api2_sample.json").read_text())


class FakeResp:
    def __init__(self, status, data=None):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, params, headers, timeout):
        self.calls.append((url, dict(params), dict(headers)))
        return self.responses.pop(0)


def test_cpe_conversion():
    assert nvd.cpe22_to_23("cpe:/a:openbsd:openssh:8.9p1") == "cpe:2.3:a:openbsd:openssh:8.9p1"
    assert nvd.cpe22_to_23("cpe:/a:vsftpd:vsftpd:2.3.4") == "cpe:2.3:a:vsftpd:vsftpd:2.3.4"
    assert nvd.cpe22_to_23("cpe:/o:linux:linux_kernel") is None       # no version: would match everything
    assert nvd.cpe22_to_23("garbage") is None


def test_parse_response():
    cves = nvd.parse_response(SAMPLE)
    assert [c["id"] for c in cves] == ["CVE-2011-2523", "CVE-2099-0001"]       # rejected entry dropped
    v = cves[0]
    assert v["cvss"] == 9.8 and v["vector"].startswith("3.1 CVSS:3.1/") and v["cwe"] == "CWE-78"
    assert v["exploit_refs"] == ["https://www.exploit-db.com/exploits/49757"] and "backdoor" in v["description"]
    assert cves[1]["cvss"] == 3.7 and cves[1]["published"] == "2099-01-01"


def test_client_paging_throttle_logging():
    page1 = {**SAMPLE, "resultsPerPage": 2, "totalResults": 4}
    page2 = {**SAMPLE, "resultsPerPage": 2, "startIndex": 2, "totalResults": 4}
    sess = FakeSession([FakeResp(200, page1), FakeResp(200, page2)])
    logged, slept = [], []
    client = nvd.NvdClient(sess, on_request=lambda u, p: logged.append(p), sleep=slept.append)
    out = client.fetch("cpe:2.3:a:vsftpd:vsftpd:2.3.4")
    assert len(sess.calls) == 2 and [p["startIndex"] for p in logged] == [0, 2]
    assert sess.calls[0][1]["virtualMatchString"] == "cpe:2.3:a:vsftpd:vsftpd:2.3.4" and sess.calls[0][2] == {}
    assert slept and slept[0] > 5          # 5 requests / 30 s without a key
    assert len(out) == 4


def test_client_api_key_and_errors():
    sess = FakeSession([FakeResp(200, {**SAMPLE, "totalResults": 2})])
    nvd.NvdClient(sess, api_key="k3y", sleep=lambda s: None).fetch("cpe:2.3:a:x:y:1")
    assert sess.calls[0][2] == {"apiKey": "k3y"}
    with pytest.raises(nvd.NvdError, match="rate limit"):
        nvd.NvdClient(FakeSession([FakeResp(429)]), sleep=lambda s: None).fetch("cpe:2.3:a:x:y:1")
    with pytest.raises(nvd.NvdError, match="HTTP 500"):
        nvd.NvdClient(FakeSession([FakeResp(500)]), sleep=lambda s: None).fetch("cpe:2.3:a:x:y:1")


def test_findings_upstream_vs_distro_package():
    cache = {"cpe:2.3:a:vsftpd:vsftpd:2.3.4": nvd.parse_response(SAMPLE),
             "cpe:2.3:a:openbsd:openssh:8.9p1": nvd.parse_response(SAMPLE)}
    h = Host("10.0.0.5", "up", ports=[
        Port("tcp", 21, "open", service="ftp", product="vsftpd", version="2.3.4", cpes=["cpe:/a:vsftpd:vsftpd:2.3.4"]),
        Port("tcp", 22, "open", service="ssh", product="OpenSSH", version="8.9p1 Ubuntu 3ubuntu0.13",
             cpes=["cpe:/a:openbsd:openssh:8.9p1"])])
    fs = nvd.findings_for_host(h, cache)
    ftp = [f for f in fs if f.port == "21/tcp"]
    ssh = [f for f in fs if f.port == "22/tcp"]
    assert {f.cve_id for f in ftp} == {"CVE-2011-2523", "CVE-2099-0001"} and not any(f.unverified for f in ftp)
    assert all(f.unverified and f.weight == 0 and "Ubuntu" in f.confidence for f in ssh)
    from watchtower.core import risk_scoring
    assert risk_scoring.breakdown(ssh, 0)["worst_cvss"] == 0


def test_assess_merges_with_dataset():
    lab = (FX / "nmap_lab.xml").read_text()
    cache = {"cpe:2.3:a:vsftpd:vsftpd:2.3.4": nvd.parse_response(SAMPLE)}
    a = assess([{"id": 1, "raw_output": lab}], [], nvd_cache=cache)
    hits = [f for f in a.findings if f.cve_id == "CVE-2011-2523"]
    assert len(hits) == 1 and hits[0].source.startswith("dataset")      # dataset entry wins the dedupe
    assert any(f.cve_id == "CVE-2099-0001" and f.kind == "nvd" for f in a.findings)
    assert nvd.host_cpes([h for h in parse_xml(lab).hosts]) == {"cpe:2.3:a:vsftpd:vsftpd:2.3.4"}
