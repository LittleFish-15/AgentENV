"""Keep the tested M/N runtime running in its private network namespace."""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


WORK = Path('/home/jwk/agent/sp3-mn')
APP = WORK / 'aenv-tit-d01'
TARGET = WORK / 'src/AgentENV/target/release'
SERVER, DAEMON = TARGET / 'server', TARGET / 'uvm-ublk-daemon'
SERVER_SHA = '1d450f7cabbd10c41ef11bd6dc093e962b2439204a5a376e1bb2c748210ca917'
DAEMON_SHA = '08a546cefb2a6867887e71f83b091abe82ca84396da3e227774815d2cf828571'
PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
CONTROL, FORWARD = Path('/dev/ublk-control'), Path('/proc/sys/net/ipv4/ip_forward')
RULE = Path('/run/udev/rules.d/98-agentenv-mn-titanic-service.rules')
ACL_BEFORE = ['user::rw-', 'group::---', 'other::---']
ACL_DURING = ['user::rw-', 'user:1204:rw-', 'group::---', 'mask::rw-', 'other::---']
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
API_PORT = 19384
BODY_LIMIT = 2 * 1024 * 1024
UNIT = 'aenv-mn-titanic.service'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'


# Reuse the working udev permission scope and runtime checks from the acceptance run.
OWNER_C = 'LyogdWRldiBQUk9HUkFNLCBtZXRhZGF0YSBHRVRfREVWX0lORk8gb25seS4gR3JhbnQgb25seSBrZXJuZWwtb3duZWQgandrIGRldmljZXMuICovCiNkZWZpbmUgX0dOVV9TT1VSQ0UKI2luY2x1ZGUgPGxpbnV4L2lvX3VyaW5nLmg+CiNpbmNsdWRlIDxsaW51eC91YmxrX2NtZC5oPgojaW5jbHVkZSA8c3lzL3N5c2NhbGwuaD4KI2luY2x1ZGUgPHN5cy9tbWFuLmg+CiNpbmNsdWRlIDxzeXMvc3RhdC5oPgojaW5jbHVkZSA8ZmNudGwuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8c3RkaW50Lmg+CiNpbmNsdWRlIDxzdGRkZWYuaD4KI2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHN0cmluZy5oPgojaW5jbHVkZSA8bGltaXRzLmg+CgppbnQgbWFpbihpbnQgYXJnYyxjaGFyICoqYXJndikgewogICAgaWYoZ2V0ZXVpZCgpIT0wIHx8IGFyZ2MhPTIpIHJldHVybiAyOwogICAgYWxhcm0oMSk7IC8qIEEgc3R1Y2sgbWV0YWRhdGEgcXVlcnkgbXVzdCBub3QgaW5kZWZpbml0ZWx5IHN0YWxsIGEgdWRldiB3b3JrZXIuICovCiAgICBjb25zdCBjaGFyICpzPWFyZ3ZbMV07CiAgICBpZihzdHJuY21wKHMsInVibGtjIiw1KSAmJiBzdHJuY21wKHMsInVibGtiIiw1KSkgcmV0dXJuIDI7CiAgICBpZighc1s1XSB8fCBzdHJsZW4ocyk+MTUpIHJldHVybiAyOwogICAgZm9yKHNpemVfdCBpPTU7c1tpXTtpKyspIGlmKHNbaV08JzAnfHxzW2ldPic5JykgcmV0dXJuIDI7CiAgICBjaGFyICplbmQ9TlVMTDt1bnNpZ25lZCBsb25nIGlkPXN0cnRvdWwocys1LCZlbmQsMTApOwogICAgaWYoIWVuZHx8KmVuZHx8aWQ+VUlOVF9NQVgpIHJldHVybiAyOwogICAgc3RydWN0IGlvX3VyaW5nX3BhcmFtcyBwPXswfTtwLmZsYWdzPUlPUklOR19TRVRVUF9TUUUxMjg7CiAgICBpbnQgcmluZz1zeXNjYWxsKF9fTlJfaW9fdXJpbmdfc2V0dXAsMiwmcCk7CiAgICBpZihyaW5nPDApIHJldHVybiAzOwogICAgc2l6ZV90IHNxc3o9cC5zcV9vZmYuYXJyYXkrcC5zcV9lbnRyaWVzKnNpemVvZih1bnNpZ25lZCk7CiAgICBzaXplX3QgY3Fzej1wLmNxX29mZi5jcWVzK3AuY3FfZW50cmllcypzaXplb2Yoc3RydWN0IGlvX3VyaW5nX2NxZSk7CiAgICBpZihwLmZlYXR1cmVzJklPUklOR19GRUFUX1NJTkdMRV9NTUFQKSB7IGlmKGNxc3o+c3Fzeikgc3Fzej1jcXN6OyBjcXN6PXNxc3o7IH0KICAgIHZvaWQgKnNxPW1tYXAoTlVMTCxzcXN6LFBST1RfUkVBRHxQUk9UX1dSSVRFLE1BUF9TSEFSRUQscmluZyxJT1JJTkdfT0ZGX1NRX1JJTkcpOwogICAgaWYoc3E9PU1BUF9GQUlMRUQpIHtjbG9zZShyaW5nKTtyZXR1cm4gMzt9CiAgICB2b2lkICpjcT0ocC5mZWF0dXJlcyZJT1JJTkdfRkVBVF9TSU5HTEVfTU1BUCk/c3E6CiAgICAgICAgbW1hcChOVUxMLGNxc3osUFJPVF9SRUFEfFBST1RfV1JJVEUsTUFQX1NIQVJFRCxyaW5nLElPUklOR19PRkZfQ1FfUklORyk7CiAgICBpZihjcT09TUFQX0ZBSUxFRCkge211bm1hcChzcSxzcXN6KTtjbG9zZShyaW5nKTtyZXR1cm4gMzt9CiAgICBzaXplX3QgZXN6PXAuc3FfZW50cmllcyoxMjg7CiAgICBzdHJ1Y3QgaW9fdXJpbmdfc3FlICplcz1tbWFwKE5VTEwsZXN6LFBST1RfUkVBRHxQUk9UX1dSSVRFLE1BUF9TSEFSRUQscmluZyxJT1JJTkdfT0ZGX1NRRVMpOwogICAgaW50IGN0cmw9b3BlbigiL2Rldi91YmxrLWNvbnRyb2wiLE9fUkRXUnxPX0NMT0VYRUN8T19OT0ZPTExPV3xPX05PTkJMT0NLKTsKICAgIGludCBvaz0wOwogICAgaWYoZXMhPU1BUF9GQUlMRUQgJiYgY3RybD49MCkgewogICAgICAgIHN0cnVjdCBzdGF0IHN0OwogICAgICAgIHN0cnVjdCB1Ymxrc3J2X2N0cmxfZGV2X2luZm8gaW5mbz17MH07CiAgICAgICAgc3RydWN0IHVibGtzcnZfY3RybF9jbWQgY21kPXswfTtjbWQuZGV2X2lkPSh1bnNpZ25lZClpZDtjbWQucXVldWVfaWQ9KHVpbnQxNl90KS0xOwogICAgICAgIGNtZC5sZW49c2l6ZW9mKGluZm8pO2NtZC5hZGRyPSh1aW50NjRfdCkodWludHB0cl90KSZpbmZvOwogICAgICAgIF9TdGF0aWNfYXNzZXJ0KHNpemVvZihjbWQpPD04MCwiY3RybCBwYXlsb2FkIGV4Y2VlZHMgU1FFMTI4Iik7CiAgICAgICAgX1N0YXRpY19hc3NlcnQob2Zmc2V0b2Yoc3RydWN0IGlvX3VyaW5nX3NxZSxjbWQpPT00OCwiU1FFIGNvbW1hbmQgb2Zmc2V0IGRpZmZlcnMiKTsKICAgICAgICBpZihmc3RhdChjdHJsLCZzdCk9PTAgJiYgU19JU0NIUihzdC5zdF9tb2RlKSAmJiBzdC5zdF91aWQ9PTApIHsKICAgICAgICAgICAgbWVtc2V0KGVzLDAsMTI4KTtlcy0+b3Bjb2RlPUlPUklOR19PUF9VUklOR19DTUQ7ZXMtPmZkPWN0cmw7CiAgICAgICAgICAgIGVzLT5jbWRfb3A9VUJMS19VX0NNRF9HRVRfREVWX0lORk87ZXMtPnVzZXJfZGF0YT0weDY4NzA2MTYyOwogICAgICAgICAgICBtZW1jcHkoZXMtPmNtZCwmY21kLHNpemVvZihjbWQpKTsKICAgICAgICAgICAgdW5zaWduZWQgKnRhaWw9KHVuc2lnbmVkKikoKGNoYXIqKXNxK3Auc3Ffb2ZmLnRhaWwpOwogICAgICAgICAgICB1bnNpZ25lZCAqYXJyYXk9KHVuc2lnbmVkKikoKGNoYXIqKXNxK3Auc3Ffb2ZmLmFycmF5KTthcnJheVswXT0wOwogICAgICAgICAgICBfX2F0b21pY19zdG9yZV9uKHRhaWwsMSxfX0FUT01JQ19SRUxFQVNFKTsKICAgICAgICAgICAgaW50IHJjPXN5c2NhbGwoX19OUl9pb191cmluZ19lbnRlcixyaW5nLDEsMSxJT1JJTkdfRU5URVJfR0VURVZFTlRTLE5VTEwsMCk7CiAgICAgICAgICAgIHVuc2lnbmVkICpoZWFkPSh1bnNpZ25lZCopKChjaGFyKiljcStwLmNxX29mZi5oZWFkKSwqY3RhaWw9KHVuc2lnbmVkKikoKGNoYXIqKWNxK3AuY3Ffb2ZmLnRhaWwpOwogICAgICAgICAgICB1bnNpZ25lZCBoPV9fYXRvbWljX2xvYWRfbihoZWFkLF9fQVRPTUlDX0FDUVVJUkUpLHQ9X19hdG9taWNfbG9hZF9uKGN0YWlsLF9fQVRPTUlDX0FDUVVJUkUpOwogICAgICAgICAgICBzdHJ1Y3QgaW9fdXJpbmdfY3FlICpjcWU9KHZvaWQqKSgoY2hhciopY3ErcC5jcV9vZmYuY3Flcyk7CiAgICAgICAgICAgIGlmKHJjPT0xICYmIHQtaD09MSAmJiBjcWVbaCYocC5jcV9lbnRyaWVzLTEpXS5yZXM9PTAgJiYKICAgICAgICAgICAgICAgIGNxZVtoJihwLmNxX2VudHJpZXMtMSldLnVzZXJfZGF0YT09MHg2ODcwNjE2MiAmJiBpbmZvLmRldl9pZD09aWQgJiYKICAgICAgICAgICAgICAgIGluZm8ub3duZXJfdWlkPT0xMjA0ICYmIGluZm8ub3duZXJfZ2lkPT0xMjA1KSBvaz0xOwogICAgICAgIH0KICAgIH0KICAgIGlmKGN0cmw+PTApY2xvc2UoY3RybCk7CiAgICBpZihlcyE9TUFQX0ZBSUxFRCltdW5tYXAoZXMsZXN6KTsKICAgIGlmKGNxIT1zcSltdW5tYXAoY3EsY3Fzeik7CiAgICBtdW5tYXAoc3Esc3Fzeik7Y2xvc2UocmluZyk7CiAgICBpZihvaykgeyBwdXRzKCIxMjA0OjEyMDUiKTsgcmV0dXJuIDA7IH0KICAgIHJldHVybiAxOyAvKiBVbnN1cHBvcnRlZC9taXNtYXRjaGVkIGtlcm5lbCBtZXRhZGF0YSBmYWlscyBjbG9zZWQuICovCn0K'
OWNER_C_SHA = '267fb85d059df72c1707e30d3740ae97ef8e62697d93c2b7a36760d1696fb721'
UBLK_HEADER = 'LyogU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEdQTC0yLjAgV0lUSCBMaW51eC1zeXNjYWxsLW5vdGUgKi8KI2lmbmRlZiBVU0VSX0JMS19EUlZfQ01EX0lOQ19ICiNkZWZpbmUgVVNFUl9CTEtfRFJWX0NNRF9JTkNfSAoKI2luY2x1ZGUgPGxpbnV4L3R5cGVzLmg+CgovKiB1YmxrIHNlcnZlciBjb21tYW5kIGRlZmluaXRpb24gKi8KCi8qCiAqIEFkbWluIGNvbW1hbmRzLCBpc3N1ZWQgYnkgdWJsayBzZXJ2ZXIsIGFuZCBoYW5kbGVkIGJ5IHVibGsgZHJpdmVyLgogKgogKiBMZWdhY3kgY29tbWFuZCBkZWZpbml0aW9uLCBkb24ndCB1c2UgaW4gbmV3IGFwcGxpY2F0aW9uLCBhbmQgZG9uJ3QKICogYWRkIG5ldyBzdWNoIGRlZmluaXRpb24gYW55IG1vcmUKICovCiNkZWZpbmUJVUJMS19DTURfR0VUX1FVRVVFX0FGRklOSVRZCTB4MDEKI2RlZmluZQlVQkxLX0NNRF9HRVRfREVWX0lORk8JMHgwMgojZGVmaW5lCVVCTEtfQ01EX0FERF9ERVYJCTB4MDQKI2RlZmluZQlVQkxLX0NNRF9ERUxfREVWCQkweDA1CiNkZWZpbmUJVUJMS19DTURfU1RBUlRfREVWCTB4MDYKI2RlZmluZQlVQkxLX0NNRF9TVE9QX0RFVgkweDA3CiNkZWZpbmUJVUJMS19DTURfU0VUX1BBUkFNUwkweDA4CiNkZWZpbmUJVUJMS19DTURfR0VUX1BBUkFNUwkweDA5CiNkZWZpbmUJVUJMS19DTURfU1RBUlRfVVNFUl9SRUNPVkVSWQkweDEwCiNkZWZpbmUJVUJMS19DTURfRU5EX1VTRVJfUkVDT1ZFUlkJMHgxMQojZGVmaW5lCVVCTEtfQ01EX0dFVF9ERVZfSU5GTzIJCTB4MTIKCi8qIEFueSBuZXcgY3RybCBjb21tYW5kIHNob3VsZCBlbmNvZGUgYnkgX19JTyooKSAqLwojZGVmaW5lIFVCTEtfVV9DTURfR0VUX1FVRVVFX0FGRklOSVRZCVwKCV9JT1IoJ3UnLCBVQkxLX0NNRF9HRVRfUVVFVUVfQUZGSU5JVFksIHN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kKQojZGVmaW5lIFVCTEtfVV9DTURfR0VUX0RFVl9JTkZPCQlcCglfSU9SKCd1JywgVUJMS19DTURfR0VUX0RFVl9JTkZPLCBzdHJ1Y3QgdWJsa3Nydl9jdHJsX2NtZCkKI2RlZmluZSBVQkxLX1VfQ01EX0FERF9ERVYJCVwKCV9JT1dSKCd1JywgVUJMS19DTURfQUREX0RFViwgc3RydWN0IHVibGtzcnZfY3RybF9jbWQpCiNkZWZpbmUgVUJMS19VX0NNRF9ERUxfREVWCQlcCglfSU9XUigndScsIFVCTEtfQ01EX0RFTF9ERVYsIHN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kKQojZGVmaW5lIFVCTEtfVV9DTURfU1RBUlRfREVWCQlcCglfSU9XUigndScsIFVCTEtfQ01EX1NUQVJUX0RFViwgc3RydWN0IHVibGtzcnZfY3RybF9jbWQpCiNkZWZpbmUgVUJMS19VX0NNRF9TVE9QX0RFVgkJXAoJX0lPV1IoJ3UnLCBVQkxLX0NNRF9TVE9QX0RFViwgc3RydWN0IHVibGtzcnZfY3RybF9jbWQpCiNkZWZpbmUgVUJMS19VX0NNRF9TRVRfUEFSQU1TCQlcCglfSU9XUigndScsIFVCTEtfQ01EX1NFVF9QQVJBTVMsIHN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kKQojZGVmaW5lIFVCTEtfVV9DTURfR0VUX1BBUkFNUwkJXAoJX0lPUigndScsIFVCTEtfQ01EX0dFVF9QQVJBTVMsIHN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kKQojZGVmaW5lIFVCTEtfVV9DTURfU1RBUlRfVVNFUl9SRUNPVkVSWQlcCglfSU9XUigndScsIFVCTEtfQ01EX1NUQVJUX1VTRVJfUkVDT1ZFUlksIHN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kKQojZGVmaW5lIFVCTEtfVV9DTURfRU5EX1VTRVJfUkVDT1ZFUlkJXAoJX0lPV1IoJ3UnLCBVQkxLX0NNRF9FTkRfVVNFUl9SRUNPVkVSWSwgc3RydWN0IHVibGtzcnZfY3RybF9jbWQpCiNkZWZpbmUgVUJMS19VX0NNRF9HRVRfREVWX0lORk8yCVwKCV9JT1IoJ3UnLCBVQkxLX0NNRF9HRVRfREVWX0lORk8yLCBzdHJ1Y3QgdWJsa3Nydl9jdHJsX2NtZCkKI2RlZmluZSBVQkxLX1VfQ01EX0dFVF9GRUFUVVJFUwlcCglfSU9SKCd1JywgMHgxMywgc3RydWN0IHVibGtzcnZfY3RybF9jbWQpCgovKgogKiA2NGJpdHMgYXJlIGVub3VnaCBub3csIGFuZCBpdCBzaG91bGQgYmUgZWFzeSB0byBleHRlbmQgaW4gY2FzZSBvZgogKiBydW5uaW5nIG91dCBvZiBmZWF0dXJlIGZsYWdzCiAqLwojZGVmaW5lIFVCTEtfRkVBVFVSRVNfTEVOICA4CgovKgogKiBJTyBjb21tYW5kcywgaXNzdWVkIGJ5IHVibGsgc2VydmVyLCBhbmQgaGFuZGxlZCBieSB1YmxrIGRyaXZlci4KICoKICogRkVUQ0hfUkVROiBpc3N1ZWQgdmlhIHNxZShVUklOR19DTUQpIGJlZm9yZWhhbmQgZm9yIGZldGNoaW5nIElPIHJlcXVlc3QKICogICAgICBmcm9tIHVibGsgZHJpdmVyLCBzaG91bGQgYmUgaXNzdWVkIG9ubHkgd2hlbiBzdGFydGluZyBkZXZpY2UuIEFmdGVyCiAqICAgICAgdGhlIGFzc29jaWF0ZWQgY3FlIGlzIHJldHVybmVkLCByZXF1ZXN0J3MgdGFnIGNhbiBiZSByZXRyaWV2ZWQgdmlhCiAqICAgICAgY3FlLT51c2VyZGF0YS4KICoKICogQ09NTUlUX0FORF9GRVRDSF9SRVE6IGlzc3VlZCB2aWEgc3FlKFVSSU5HX0NNRCkgYWZ0ZXIgdWJsa3NlcnZlciBoYW5kbGVkCiAqICAgICAgdGhpcyBJTyByZXF1ZXN0LCByZXF1ZXN0J3MgaGFuZGxpbmcgcmVzdWx0IGlzIGNvbW1pdHRlZCB0byB1YmxrCiAqICAgICAgZHJpdmVyLCBtZWFudGltZSBGRVRDSF9SRVEgaXMgcGlnZ3liYWNrLCBhbmQgRkVUQ0hfUkVRIGhhcyB0byBiZQogKiAgICAgIGhhbmRsZWQgYmVmb3JlIGNvbXBsZXRpbmcgaW8gcmVxdWVzdC4KICoKICogTkVFRF9HRVRfREFUQTogb25seSB1c2VkIGZvciB3cml0ZSByZXF1ZXN0cyB0byBzZXQgaW8gYWRkciBhbmQgY29weSBkYXRhCiAqICAgICAgV2hlbiBORUVEX0dFVF9EQVRBIGlzIHNldCwgdWJsa3NydiBoYXMgdG8gaXNzdWUgVUJMS19JT19ORUVEX0dFVF9EQVRBCiAqICAgICAgY29tbWFuZCBhZnRlciB1YmxrIGRyaXZlciByZXR1cm5zIFVCTEtfSU9fUkVTX05FRURfR0VUX0RBVEEuCiAqCiAqICAgICAgSXQgaXMgb25seSB1c2VkIGlmIHVibGtzcnYgc2V0IFVCTEtfRl9ORUVEX0dFVF9EQVRBIGZsYWcKICogICAgICB3aGlsZSBzdGFydGluZyBhIHVibGsgZGV2aWNlLgogKi8KCi8qCiAqIExlZ2FjeSBJTyBjb21tYW5kIGRlZmluaXRpb24sIGRvbid0IHVzZSBpbiBuZXcgYXBwbGljYXRpb24sIGFuZCBkb24ndAogKiBhZGQgbmV3IHN1Y2ggZGVmaW5pdGlvbiBhbnkgbW9yZQogKi8KI2RlZmluZQlVQkxLX0lPX0ZFVENIX1JFUQkJMHgyMAojZGVmaW5lCVVCTEtfSU9fQ09NTUlUX0FORF9GRVRDSF9SRVEJMHgyMQojZGVmaW5lCVVCTEtfSU9fTkVFRF9HRVRfREFUQQkweDIyCgovKiBBbnkgbmV3IElPIGNvbW1hbmQgc2hvdWxkIGVuY29kZSBieSBfX0lPV1IoKSAqLwojZGVmaW5lCVVCTEtfVV9JT19GRVRDSF9SRVEJCVwKCV9JT1dSKCd1JywgVUJMS19JT19GRVRDSF9SRVEsIHN0cnVjdCB1Ymxrc3J2X2lvX2NtZCkKI2RlZmluZQlVQkxLX1VfSU9fQ09NTUlUX0FORF9GRVRDSF9SRVEJXAoJX0lPV1IoJ3UnLCBVQkxLX0lPX0NPTU1JVF9BTkRfRkVUQ0hfUkVRLCBzdHJ1Y3QgdWJsa3Nydl9pb19jbWQpCiNkZWZpbmUJVUJMS19VX0lPX05FRURfR0VUX0RBVEEJCVwKCV9JT1dSKCd1JywgVUJMS19JT19ORUVEX0dFVF9EQVRBLCBzdHJ1Y3QgdWJsa3Nydl9pb19jbWQpCgovKiBvbmx5IEFCT1JUIG1lYW5zIHRoYXQgbm8gcmUtZmV0Y2ggKi8KI2RlZmluZSBVQkxLX0lPX1JFU19PSwkJCTAKI2RlZmluZSBVQkxLX0lPX1JFU19ORUVEX0dFVF9EQVRBCTEKI2RlZmluZSBVQkxLX0lPX1JFU19BQk9SVAkJKC1FTk9ERVYpCgojZGVmaW5lIFVCTEtTUlZfQ01EX0JVRl9PRkZTRVQJMAojZGVmaW5lIFVCTEtTUlZfSU9fQlVGX09GRlNFVAkweDgwMDAwMDAwCgovKiB0YWcgYml0IGlzIDE2Yml0LCBzbyBmYXIgbGltaXQgYXQgbW9zdCA0MDk2IElPcyBmb3IgZWFjaCBxdWV1ZSAqLwojZGVmaW5lIFVCTEtfTUFYX1FVRVVFX0RFUFRICTQwOTYKCi8qIHNpbmdsZSBJTyBidWZmZXIgbWF4IHNpemUgaXMgMzJNQiAqLwojZGVmaW5lIFVCTEtfSU9fQlVGX09GRgkJMAojZGVmaW5lIFVCTEtfSU9fQlVGX0JJVFMJMjUKI2RlZmluZSBVQkxLX0lPX0JVRl9CSVRTX01BU0sJKCgxVUxMIDw8IFVCTEtfSU9fQlVGX0JJVFMpIC0gMSkKCi8qIHNvIGF0IG1vc3QgNjRLIElPcyBmb3IgZWFjaCBxdWV1ZSAqLwojZGVmaW5lIFVCTEtfVEFHX09GRgkJVUJMS19JT19CVUZfQklUUwojZGVmaW5lIFVCTEtfVEFHX0JJVFMJCTE2CiNkZWZpbmUgVUJMS19UQUdfQklUU19NQVNLCSgoMVVMTCA8PCBVQkxLX1RBR19CSVRTKSAtIDEpCgovKiBtYXggNDA5NiBxdWV1ZXMgKi8KI2RlZmluZSBVQkxLX1FJRF9PRkYJCShVQkxLX1RBR19PRkYgKyBVQkxLX1RBR19CSVRTKQojZGVmaW5lIFVCTEtfUUlEX0JJVFMJCTEyCiNkZWZpbmUgVUJMS19RSURfQklUU19NQVNLCSgoMVVMTCA8PCBVQkxLX1FJRF9CSVRTKSAtIDEpCgojZGVmaW5lIFVCTEtfTUFYX05SX1FVRVVFUwkoMVUgPDwgVUJMS19RSURfQklUUykKCiNkZWZpbmUgVUJMS1NSVl9JT19CVUZfVE9UQUxfQklUUwkoVUJMS19RSURfT0ZGICsgVUJMS19RSURfQklUUykKI2RlZmluZSBVQkxLU1JWX0lPX0JVRl9UT1RBTF9TSVpFCSgxVUxMIDw8IFVCTEtTUlZfSU9fQlVGX1RPVEFMX0JJVFMpCgovKgogKiB6ZXJvIGNvcHkgcmVxdWlyZXMgNGsgYmxvY2sgc2l6ZSwgYW5kIGNhbiByZW1hcCB1YmxrIGRyaXZlcidzIGlvCiAqIHJlcXVlc3QgaW50byB1Ymxrc3J2J3Mgdm0gc3BhY2UKICovCiNkZWZpbmUgVUJMS19GX1NVUFBPUlRfWkVST19DT1BZCSgxVUxMIDw8IDApCgovKgogKiBGb3JjZSB0byBjb21wbGV0ZSBpbyBjbWQgdmlhIGlvX3VyaW5nX2NtZF9jb21wbGV0ZV9pbl90YXNrIHNvIHRoYXQKICogcGVyZm9ybWFuY2UgY29tcGFyaXNvbiBpcyBkb25lIGVhc2lseSB3aXRoIHVzaW5nIHRhc2tfd29ya19hZGQKICovCiNkZWZpbmUgVUJMS19GX1VSSU5HX0NNRF9DT01QX0lOX1RBU0sJKDFVTEwgPDwgMSkKCi8qCiAqIFVzZXIgc2hvdWxkIGlzc3VlIGlvIGNtZCBhZ2FpbiBmb3Igd3JpdGUgcmVxdWVzdHMgdG8KICogc2V0IGlvIGJ1ZmZlciBhZGRyZXNzIGFuZCBjb3B5IGRhdGEgZnJvbSBiaW8gdmVjdG9ycwogKiB0byB0aGUgdXNlcnNwYWNlIGlvIGJ1ZmZlci4KICoKICogSW4gdGhpcyBtb2RlLCB0YXNrX3dvcmsgaXMgbm90IHVzZWQuCiAqLwojZGVmaW5lIFVCTEtfRl9ORUVEX0dFVF9EQVRBICgxVUwgPDwgMikKCiNkZWZpbmUgVUJMS19GX1VTRVJfUkVDT1ZFUlkJKDFVTCA8PCAzKQoKI2RlZmluZSBVQkxLX0ZfVVNFUl9SRUNPVkVSWV9SRUlTU1VFCSgxVUwgPDwgNCkKCi8qCiAqIFVucHJpdmlsZWdlZCB1c2VyIGNhbiBjcmVhdGUgL2Rldi91YmxrY04gYW5kIC9kZXYvdWJsa2JOLgogKgogKiAvZGV2L3VibGstY29udHJvbCBuZWVkcyB0byBiZSBhdmFpbGFibGUgZm9yIHVucHJpdmlsZWdlZCB1c2VyLCBhbmQgaXQKICogY2FuIGJlIGRvbmUgdmlhIHVkZXYgcnVsZSB0byBtYWtlIGFsbCBjb250cm9sIGNvbW1hbmRzIGF2YWlsYWJsZSB0bwogKiB1bnByaXZpbGVnZWQgdXNlci4gRXhjZXB0IGZvciB0aGUgY29tbWFuZCBvZiBVQkxLX0NNRF9BRERfREVWLCBhbGwKICogb3RoZXIgY29tbWFuZHMgYXJlIG9ubHkgYWxsb3dlZCBmb3IgdGhlIG93bmVyIG9mIHRoZSBzcGVjaWZpZWQgZGV2aWNlLgogKgogKiBXaGVuIHVzZXJzcGFjZSBzZW5kcyBVQkxLX0NNRF9BRERfREVWLCB0aGUgZGV2aWNlIHBhaXIncyBvd25lcl91aWQgYW5kCiAqIG93bmVyX2dpZCBhcmUgc3RvcmVkIHRvIHVibGtzcnZfY3RybF9kZXZfaW5mbyBieSBrZXJuZWwsIHNvIGZhciBvbmx5CiAqIHRoZSBjdXJyZW50IHVzZXIncyB1aWQvZ2lkIGlzIHN0b3JlZCwgdGhhdCBzYWlkIG93bmVyIG9mIHRoZSBjcmVhdGVkCiAqIGRldmljZSBpcyBhbHdheXMgdGhlIGN1cnJlbnQgdXNlci4KICoKICogV2Ugc3RpbGwgbmVlZCB1ZGV2IHJ1bGUgdG8gYXBwbHkgT1dORVIvR1JPVVAgd2l0aCB0aGUgc3RvcmVkIG93bmVyX3VpZAogKiBhbmQgb3duZXJfZ2lkLgogKgogKiBUaGVuIHVibGsgc2VydmVyIGNhbiBiZSBydW4gYXMgdW5wcml2aWxlZ2VkIHVzZXIsIGFuZCAvZGV2L3VibGtiTiBjYW4KICogYmUgYWNjZXNzZWQgYW5kIG1hbmFnZWQgYnkgaXRzIG93bmVyIHJlcHJlc2VudGVkIGJ5IG93bmVyX3VpZC9vd25lcl9naWQuCiAqLwojZGVmaW5lIFVCTEtfRl9VTlBSSVZJTEVHRURfREVWCSgxVUwgPDwgNSkKCi8qIHVzZSBpb2N0bCBlbmNvZGluZyBmb3IgdXJpbmcgY29tbWFuZCAqLwojZGVmaW5lIFVCTEtfRl9DTURfSU9DVExfRU5DT0RFCSgxVUwgPDwgNikKCi8qCiAqICBDb3B5IGJldHdlZW4gcmVxdWVzdCBhbmQgdXNlciBidWZmZXIgYnkgcHJlYWQoKS9wd3JpdGUoKQogKgogKiAgTm90IGF2YWlsYWJsZSBmb3IgVUJMS19GX1VOUFJJVklMRUdFRF9ERVYsIG90aGVyd2lzZSB1c2Vyc3BhY2UgbWF5CiAqICBkZWNlaXZlIHVzIGJ5IG5vdCBmaWxsaW5nIHJlcXVlc3QgYnVmZmVyLCB0aGVuIGtlcm5lbCB1bmluaXRpYWxpemVkCiAqICBkYXRhIG1heSBiZSBsZWFrZWQuCiAqLwojZGVmaW5lIFVCTEtfRl9VU0VSX0NPUFkJKDFVTCA8PCA3KQoKLyoKICogVXNlciBzcGFjZSBzZXRzIHRoaXMgZmxhZyB3aGVuIHNldHRpbmcgdXAgdGhlIGRldmljZSB0byByZXF1ZXN0IHpvbmVkIHN0b3JhZ2Ugc3VwcG9ydC4gS2VybmVsIG1heQogKiBkZW55IHRoZSByZXF1ZXN0IGJ5IHJldHVybmluZyBhbiBlcnJvci4KICovCiNkZWZpbmUgVUJMS19GX1pPTkVEICgxVUxMIDw8IDgpCgovKiBkZXZpY2Ugc3RhdGUgKi8KI2RlZmluZSBVQkxLX1NfREVWX0RFQUQJMAojZGVmaW5lIFVCTEtfU19ERVZfTElWRQkxCiNkZWZpbmUgVUJMS19TX0RFVl9RVUlFU0NFRAkyCgovKiBzaGlwcGVkIHZpYSBzcWUtPmNtZCBvZiBpb191cmluZyBjb21tYW5kICovCnN0cnVjdCB1Ymxrc3J2X2N0cmxfY21kIHsKCS8qIHNlbnQgdG8gd2hpY2ggZGV2aWNlLCBtdXN0IGJlIHZhbGlkICovCglfX3UzMglkZXZfaWQ7CgoJLyogc2VudCB0byB3aGljaCBxdWV1ZSwgbXVzdCBiZSAtMSBpZiB0aGUgY21kIGlzbid0IGZvciBxdWV1ZSAqLwoJX191MTYJcXVldWVfaWQ7CgkvKgoJICogY21kIHNwZWNpZmljIGJ1ZmZlciwgY2FuIGJlIElOIG9yIE9VVC4KCSAqLwoJX191MTYJbGVuOwoJX191NjQJYWRkcjsKCgkvKiBpbmxpbmUgZGF0YSAqLwoJX191NjQJZGF0YVsxXTsKCgkvKgoJICogVXNlZCBmb3IgVUJMS19GX1VOUFJJVklMRUdFRF9ERVYgYW5kIFVCTEtfQ01EX0dFVF9ERVZfSU5GTzIKCSAqIG9ubHksIGluY2x1ZGUgbnVsbCBjaGFyCgkgKi8KCV9fdTE2CWRldl9wYXRoX2xlbjsKCV9fdTE2CXBhZDsKCV9fdTMyCXJlc2VydmVkOwp9OwoKc3RydWN0IHVibGtzcnZfY3RybF9kZXZfaW5mbyB7CglfX3UxNglucl9od19xdWV1ZXM7CglfX3UxNglxdWV1ZV9kZXB0aDsKCV9fdTE2CXN0YXRlOwoJX191MTYJcGFkMDsKCglfX3UzMgltYXhfaW9fYnVmX2J5dGVzOwoJX191MzIJZGV2X2lkOwoKCV9fczMyCXVibGtzcnZfcGlkOwoJX191MzIJcGFkMTsKCglfX3U2NAlmbGFnczsKCgkvKiBGb3IgdWJsa3NydiBpbnRlcm5hbCB1c2UsIGludmlzaWJsZSB0byB1YmxrIGRyaXZlciAqLwoJX191NjQJdWJsa3Nydl9mbGFnczsKCglfX3UzMglvd25lcl91aWQ7CS8qIHN0b3JlIGJ5IGtlcm5lbCAqLwoJX191MzIJb3duZXJfZ2lkOwkvKiBzdG9yZSBieSBrZXJuZWwgKi8KCV9fdTY0CXJlc2VydmVkMTsKCV9fdTY0ICAgcmVzZXJ2ZWQyOwp9OwoKI2RlZmluZQkJVUJMS19JT19PUF9SRUFECQkwCiNkZWZpbmUJCVVCTEtfSU9fT1BfV1JJVEUJCTEKI2RlZmluZQkJVUJMS19JT19PUF9GTFVTSAkJMgojZGVmaW5lCQlVQkxLX0lPX09QX0RJU0NBUkQJCTMKI2RlZmluZQkJVUJMS19JT19PUF9XUklURV9TQU1FCQk0CiNkZWZpbmUJCVVCTEtfSU9fT1BfV1JJVEVfWkVST0VTCQk1CiNkZWZpbmUJCVVCTEtfSU9fT1BfWk9ORV9PUEVOCQkxMAojZGVmaW5lCQlVQkxLX0lPX09QX1pPTkVfQ0xPU0UJCTExCiNkZWZpbmUJCVVCTEtfSU9fT1BfWk9ORV9GSU5JU0gJCTEyCiNkZWZpbmUJCVVCTEtfSU9fT1BfWk9ORV9BUFBFTkQJCTEzCiNkZWZpbmUJCVVCTEtfSU9fT1BfWk9ORV9SRVNFVF9BTEwJMTQKI2RlZmluZQkJVUJMS19JT19PUF9aT05FX1JFU0VUCQkxNQovKgogKiBDb25zdHJ1Y3QgYSB6b25lIHJlcG9ydC4gVGhlIHJlcG9ydCByZXF1ZXN0IGlzIGNhcnJpZWQgaW4gYHN0cnVjdAogKiB1Ymxrc3J2X2lvX2Rlc2NgLiBUaGUgYHN0YXJ0X3NlY3RvcmAgZmllbGQgbXVzdCBiZSB0aGUgZmlyc3Qgc2VjdG9yIG9mIGEgem9uZQogKiBhbmQgc2hhbGwgaW5kaWNhdGUgdGhlIGZpcnN0IHpvbmUgb2YgdGhlIHJlcG9ydC4gVGhlIGBucl96b25lc2Agc2hhbGwKICogaW5kaWNhdGUgaG93IG1hbnkgem9uZXMgc2hvdWxkIGJlIHJlcG9ydGVkIGF0IG1vc3QuIFRoZSByZXBvcnQgc2hhbGwgYmUKICogZGVsaXZlcmVkIGFzIGEgYHN0cnVjdCBibGtfem9uZWAgYXJyYXkuIFRvIHJlcG9ydCBmZXdlciB6b25lcyB0aGFuIHJlcXVlc3RlZCwKICogemVybyB0aGUgbGFzdCBlbnRyeSBvZiB0aGUgcmV0dXJuZWQgYXJyYXkuCiAqCiAqIFJlbGF0ZWQgZGVmaW5pdGlvbnMoYmxrX3pvbmUsIGJsa196b25lX2NvbmQsIGJsa196b25lX3R5cGUsIC4uLikgaW4KICogaW5jbHVkZS91YXBpL2xpbnV4L2Jsa3pvbmVkLmggYXJlIHBhcnQgb2YgdWJsayBVQVBJLgogKi8KI2RlZmluZQkJVUJMS19JT19PUF9SRVBPUlRfWk9ORVMJCTE4CgojZGVmaW5lCQlVQkxLX0lPX0ZfRkFJTEZBU1RfREVWCQkoMVUgPDwgOCkKI2RlZmluZQkJVUJMS19JT19GX0ZBSUxGQVNUX1RSQU5TUE9SVAkoMVUgPDwgOSkKI2RlZmluZQkJVUJMS19JT19GX0ZBSUxGQVNUX0RSSVZFUgkoMVUgPDwgMTApCiNkZWZpbmUJCVVCTEtfSU9fRl9NRVRBCQkJKDFVIDw8IDExKQojZGVmaW5lCQlVQkxLX0lPX0ZfRlVBCQkJKDFVIDw8IDEzKQojZGVmaW5lCQlVQkxLX0lPX0ZfTk9VTk1BUAkJKDFVIDw8IDE1KQojZGVmaW5lCQlVQkxLX0lPX0ZfU1dBUAkJCSgxVSA8PCAxNikKCi8qCiAqIGlvIGNtZCBpcyBkZXNjcmliZWQgYnkgdGhpcyBzdHJ1Y3R1cmUsIGFuZCBzdG9yZWQgaW4gc2hhcmUgbWVtb3J5LCBpbmRleGVkCiAqIGJ5IHJlcXVlc3QgdGFnLgogKgogKiBUaGUgZGF0YSBpcyBzdG9yZWQgYnkgdWJsayBkcml2ZXIsIGFuZCByZWFkIGJ5IHVibGtzcnYgYWZ0ZXIgb25lIGZldGNoIGNvbW1hbmQKICogcmV0dXJucy4KICovCnN0cnVjdCB1Ymxrc3J2X2lvX2Rlc2MgewoJLyogb3A6IGJpdCAwLTcsIGZsYWdzOiBiaXQgOC0zMSAqLwoJX191MzIJCW9wX2ZsYWdzOwoKCXVuaW9uIHsKCQlfX3UzMgkJbnJfc2VjdG9yczsKCQlfX3UzMgkJbnJfem9uZXM7IC8qIGZvciBVQkxLX0lPX09QX1JFUE9SVF9aT05FUyAqLwoJfTsKCgkvKiBzdGFydCBzZWN0b3IgZm9yIHRoaXMgaW8gKi8KCV9fdTY0CQlzdGFydF9zZWN0b3I7CgoJLyogYnVmZmVyIGFkZHJlc3MgaW4gdWJsa3NydiBkYWVtb24gdm0gc3BhY2UsIGZyb20gdWJsayBkcml2ZXIgKi8KCV9fdTY0CQlhZGRyOwp9OwoKc3RhdGljIGlubGluZSBfX3U4IHVibGtzcnZfZ2V0X29wKGNvbnN0IHN0cnVjdCB1Ymxrc3J2X2lvX2Rlc2MgKmlvZCkKewoJcmV0dXJuIGlvZC0+b3BfZmxhZ3MgJiAweGZmOwp9CgpzdGF0aWMgaW5saW5lIF9fdTMyIHVibGtzcnZfZ2V0X2ZsYWdzKGNvbnN0IHN0cnVjdCB1Ymxrc3J2X2lvX2Rlc2MgKmlvZCkKewoJcmV0dXJuIGlvZC0+b3BfZmxhZ3MgPj4gODsKfQoKLyogaXNzdWVkIHRvIHVibGsgZHJpdmVyIHZpYSAvZGV2L3VibGtjTiAqLwpzdHJ1Y3QgdWJsa3Nydl9pb19jbWQgewoJX191MTYJcV9pZDsKCgkvKiBmb3IgZmV0Y2gvY29tbWl0IHdoaWNoIHJlc3VsdCAqLwoJX191MTYJdGFnOwoKCS8qIGlvIHJlc3VsdCwgaXQgaXMgdmFsaWQgZm9yIENPTU1JVCogY29tbWFuZCBvbmx5ICovCglfX3MzMglyZXN1bHQ7CgoJdW5pb24gewoJCS8qCgkJICogdXNlcnNwYWNlIGJ1ZmZlciBhZGRyZXNzIGluIHVibGtzcnYgZGFlbW9uIHByb2Nlc3MsIHZhbGlkIGZvcgoJCSAqIEZFVENIKiBjb21tYW5kIG9ubHkKCQkgKgoJCSAqIGBhZGRyYCBzaG91bGQgbm90IGJlIHVzZWQgd2hlbiBVQkxLX0ZfVVNFUl9DT1BZIGlzIGVuYWJsZWQsCgkJICogYmVjYXVzZSB1c2Vyc3BhY2UgaGFuZGxlcyBkYXRhIGNvcHkgYnkgcHJlYWQoKS9wd3JpdGUoKSBvdmVyCgkJICogL2Rldi91YmxrY04uIEJ1dCBpbiBjYXNlIG9mIFVCTEtfRl9aT05FRCwgdGhpcyB1bmlvbiBpcwoJCSAqIHJlLXVzZWQgdG8gcGFzcyBiYWNrIHRoZSBhbGxvY2F0ZWQgTEJBIGZvcgoJCSAqIFVCTEtfSU9fT1BfWk9ORV9BUFBFTkQgd2hpY2ggYWN0dWFsbHkgZGVwZW5kcyBvbgoJCSAqIFVCTEtfRl9VU0VSX0NPUFkKCQkgKi8KCQlfX3U2NAlhZGRyOwoJCV9fdTY0CXpvbmVfYXBwZW5kX2xiYTsKCX07Cn07CgpzdHJ1Y3QgdWJsa19wYXJhbV9iYXNpYyB7CiNkZWZpbmUgVUJMS19BVFRSX1JFQURfT05MWSAgICAgICAgICAgICgxIDw8IDApCiNkZWZpbmUgVUJMS19BVFRSX1JPVEFUSU9OQUwgICAgICAgICAgICgxIDw8IDEpCiNkZWZpbmUgVUJMS19BVFRSX1ZPTEFUSUxFX0NBQ0hFICAgICAgICgxIDw8IDIpCiNkZWZpbmUgVUJMS19BVFRSX0ZVQSAgICAgICAgICAgICAgICAgICgxIDw8IDMpCglfX3UzMglhdHRyczsKCV9fdTgJbG9naWNhbF9ic19zaGlmdDsKCV9fdTgJcGh5c2ljYWxfYnNfc2hpZnQ7CglfX3U4CWlvX29wdF9zaGlmdDsKCV9fdTgJaW9fbWluX3NoaWZ0OwoKCV9fdTMyCW1heF9zZWN0b3JzOwoJX191MzIJY2h1bmtfc2VjdG9yczsKCglfX3U2NCAgIGRldl9zZWN0b3JzOwoJX191NjQgICB2aXJ0X2JvdW5kYXJ5X21hc2s7Cn07CgpzdHJ1Y3QgdWJsa19wYXJhbV9kaXNjYXJkIHsKCV9fdTMyCWRpc2NhcmRfYWxpZ25tZW50OwoKCV9fdTMyCWRpc2NhcmRfZ3JhbnVsYXJpdHk7CglfX3UzMgltYXhfZGlzY2FyZF9zZWN0b3JzOwoKCV9fdTMyCW1heF93cml0ZV96ZXJvZXNfc2VjdG9yczsKCV9fdTE2CW1heF9kaXNjYXJkX3NlZ21lbnRzOwoJX191MTYJcmVzZXJ2ZWQwOwp9OwoKLyoKICogcmVhZC1vbmx5LCBjYW4ndCBzZXQgdmlhIFVCTEtfQ01EX1NFVF9QQVJBTVMsIGRpc2tfZGV2dCBpcyBhdmFpbGFibGUKICogYWZ0ZXIgZGV2aWNlIGlzIHN0YXJ0ZWQKICovCnN0cnVjdCB1YmxrX3BhcmFtX2RldnQgewoJX191MzIgICBjaGFyX21ham9yOwoJX191MzIgICBjaGFyX21pbm9yOwoJX191MzIgICBkaXNrX21ham9yOwoJX191MzIgICBkaXNrX21pbm9yOwp9OwoKc3RydWN0IHVibGtfcGFyYW1fem9uZWQgewoJX191MzIJbWF4X29wZW5fem9uZXM7CglfX3UzMgltYXhfYWN0aXZlX3pvbmVzOwoJX191MzIJbWF4X3pvbmVfYXBwZW5kX3NlY3RvcnM7CglfX3U4CXJlc2VydmVkWzIwXTsKfTsKCnN0cnVjdCB1YmxrX3BhcmFtcyB7CgkvKgoJICogVG90YWwgbGVuZ3RoIG9mIHBhcmFtZXRlcnMsIHVzZXJzcGFjZSBoYXMgdG8gc2V0ICdsZW4nIGZvciBib3RoCgkgKiBTRVRfUEFSQU1TIGFuZCBHRVRfUEFSQU1TIGNvbW1hbmQsIGFuZCBkcml2ZXIgbWF5IHVwZGF0ZSBsZW4KCSAqIGlmIHR3byBzaWRlcyB1c2UgZGlmZmVyZW50IHZlcnNpb24gb2YgJ3VibGtfcGFyYW1zJywgc2FtZSB3aXRoCgkgKiAndHlwZXMnIGZpZWxkcy4KCSAqLwoJX191MzIJbGVuOwojZGVmaW5lIFVCTEtfUEFSQU1fVFlQRV9CQVNJQyAgICAgICAgICAgKDEgPDwgMCkKI2RlZmluZSBVQkxLX1BBUkFNX1RZUEVfRElTQ0FSRCAgICAgICAgICgxIDw8IDEpCiNkZWZpbmUgVUJMS19QQVJBTV9UWVBFX0RFVlQgICAgICAgICAgICAoMSA8PCAyKQojZGVmaW5lIFVCTEtfUEFSQU1fVFlQRV9aT05FRCAgICAgICAgICAgKDEgPDwgMykKCV9fdTMyCXR5cGVzOwkJCS8qIHR5cGVzIG9mIHBhcmFtZXRlciBpbmNsdWRlZCAqLwoKCXN0cnVjdCB1YmxrX3BhcmFtX2Jhc2ljCQliYXNpYzsKCXN0cnVjdCB1YmxrX3BhcmFtX2Rpc2NhcmQJZGlzY2FyZDsKCXN0cnVjdCB1YmxrX3BhcmFtX2RldnQJCWRldnQ7CglzdHJ1Y3QgdWJsa19wYXJhbV96b25lZAl6b25lZDsKfTsKCiNlbmRpZgo='
UBLK_HEADER_SHA = '74d0c820041344d8fe9faaeccd938503ab33c26794d1789076e0b151a1472ec9'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def pinned(path, expected):
    need(path.resolve(strict=True) == path and path.is_file() and
         hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'Input digest differs: ' + str(path))


def acl():
    report = subprocess.check_output(['/usr/bin/getfacl', '-cpn', '--', str(CONTROL)],
                                     env=ENV, text=True, timeout=8)
    return [line for line in report.splitlines() if line.strip()]


def identity():
    info = CONTROL.lstat()
    need(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0,
         'Expected root-owned ublk character device')
    return info.st_dev, info.st_ino, info.st_rdev


def interrupted(*_):
    raise InterruptedError('Template capture interrupted')


def device_nodes():
    present = {}
    for path in Path('/dev').glob('ublk*'):
        if not re.fullmatch(r'ublk[cb][0-9]+', path.name):
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        present[path.name] = {'id': [info.st_ino, info.st_rdev], 'uid': info.st_uid,
                              'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}
    return present


@contextmanager
def scoped_udev():
    udevadm = shutil.which('udevadm', path=ENV['PATH'])
    gcc = shutil.which('gcc', path=ENV['PATH'])
    need(udevadm and gcc and Path('/run/udev').is_dir(), 'Existing udev or native compiler unavailable')
    need(not os.path.lexists(RULE), 'A prior temporary device rule requires reconciliation')
    original = device_nodes()
    with tempfile.TemporaryDirectory(prefix='mn-tcap-owner-', dir='/run') as temporary:
        staging = Path(temporary)
        (staging / 'linux').mkdir(mode=0o700)
        payloads = [(staging / 'owner.c', OWNER_C, OWNER_C_SHA),
                    (staging / 'linux/ublk_cmd.h', UBLK_HEADER, UBLK_HEADER_SHA)]
        for path, payload, wanted in payloads:
            raw = base64.b64decode(payload, validate=True)
            need(hashlib.sha256(raw).hexdigest() == wanted, 'Pinned ublk query source differs')
            path.write_bytes(raw)
        helper = staging / 'ublk-owner'
        subprocess.run([gcc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(staging),
                        str(staging / 'owner.c'), '-o', str(helper)], env=ENV, check=True, timeout=80)
        helper.chmod(0o700)
        rule = (
            f'ACTION=="add", KERNEL=="ublkc[0-9]*", PROGRAM=="{helper} %k", '
            'RESULT=="1204:1205", OWNER="1204", GROUP="1205", MODE="0600"\n'
            f'ACTION=="add", SUBSYSTEM=="block", KERNEL=="ublkb[0-9]*", PROGRAM=="{helper} %k", '
            'RESULT=="1204:1205", OWNER="1204", GROUP="1205", MODE="0600"\n'
        ).encode()
        made_parent, installed = False, False
        try:
            if not os.path.lexists(RULE.parent):
                RULE.parent.mkdir(mode=0o755)
                RULE.parent.chmod(0o755)
                made_parent = True
            info = RULE.parent.lstat()
            need(RULE.parent.resolve() == RULE.parent and stat.S_ISDIR(info.st_mode)
                 and info.st_uid == 0 and not info.st_mode & 0o022, 'udev rule parent differs')
            with RULE.open('xb') as stream:
                installed = True
                stream.write(rule)
                os.fchmod(stream.fileno(), 0o644)
            subprocess.run([udevadm, 'control', '--reload-rules'], env=ENV, check=True, timeout=15)
            print(json.dumps({'event': 'temporary_owner_verified_ublk_udev_rule', 'name': RULE.name,
                              'existingUblkNodes': sorted(original)}), flush=True)
            yield
        finally:
            if installed:
                need(RULE.read_bytes() == rule, 'Temporary udev rule changed unexpectedly')
                RULE.unlink()
                subprocess.run([udevadm, 'control', '--reload-rules'], env=ENV, check=True, timeout=15)
            if made_parent and not any(RULE.parent.iterdir()):
                RULE.parent.rmdir()
            deadline = time.monotonic() + 6
            while True:
                final = device_nodes()
                remaining = {name: info for name, info in final.items()
                             if name not in original or original[name]['id'] != info['id']}
                if not remaining or time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
            changes = [name for name, info in final.items()
                       if name in original and info['id'] == original[name]['id'] and info != original[name]]
            print(json.dumps({'event': 'temporary_udev_rule_removed', 'leftoverUblkNodes': remaining,
                              'changedExistingNodes': changes}), flush=True)
            need(not remaining and not changes, 'Ublk node state needs reconciliation')


def report(status, **fields):
    print(json.dumps({'status': status, **fields}, sort_keys=True), flush=True)


def document(path):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= BODY_LIMIT,
         'Unexpected evidence path: ' + str(path))
    return json.loads(path.read_bytes())


def checked_generation(run, manifest, host, provider_pid):
    root = Path('/etc/aenv/ub') / ('relay-' + run)
    cfg = root / 'device-root.json'
    process = Path('/proc') / str(provider_pid)
    need((process / 'exe').resolve(strict=True) == PROVIDER
         and (process / 'cmdline').read_bytes().split(b'\x00')[1:3] == [b'root', os.fsencode(cfg)],
         'Staged Provider has exited or changed identity')
    config = document(cfg)
    index = document(root / 'index/stable-index.json')
    need(config['node'] == host and config['run'] == run and config['manifestSha256'] == manifest
         and config['device']['bootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and index['state'] == 'metadata_ready' and index['mode'] == 'host-dax-stable-demand'
         and len(index['replicas']) == 10 and all(
             row['generation'] == run and row['manifestSha256'] == 'sha256:' + manifest
             for row in index['replicas']), 'Provider index or generation changed')
    return root, [lower['layerDigest'] for lower in index['replicas']]


def request_http(method, path, headers=None, body=None, timeout=20):
    client = http.client.HTTPConnection('127.0.0.1', API_PORT, timeout=timeout)
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        data = response.read(BODY_LIMIT + 1)
        need(len(data) <= BODY_LIMIT, 'Unexpected HTTP response size')
        return response.status, data
    finally:
        client.close()


def wait_health(server, deadline):
    while time.monotonic() < deadline:
        need(server.poll() is None, 'AENV Server exited during startup')
        try:
            if request_http('GET', '/health', timeout=2)[0] in (200, 204):
                return
        except (ConnectionError, TimeoutError, http.client.HTTPException):
            pass
        time.sleep(0.4)
    raise RuntimeError('AENV Server health did not become ready')


def service_status(unit):
    result = subprocess.run([SYSTEMCTL, 'show', unit, '--no-pager', '-p', 'ActiveState', '-p', 'SubState',
                             '-p', 'MainPID', '-p', 'LoadState'],
                            env=ENV, text=True, capture_output=True, check=True, timeout=8)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def match_process(path, role=None, config=None):
    result = []
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if Path(os.readlink(process / 'exe')) != path:
                continue
            if role and (process / 'cmdline').read_bytes().split(b'\0')[1:3] != [
                    role.encode(), os.fsencode(config)]:
                continue
            result.append(int(process.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return result


def chain(args, host, root):
    platform = {unit: service_status(unit) for unit in ('ubse.service', 'ubsmd.service')}
    need(all(row['ActiveState'] == 'active' and int(row['MainPID']) > 0 for row in platform.values()),
         'UBSE or ubsmd is not active; retain existing deployment')
    config = document(root / 'device-root.json')
    need(config['device']['enginePid'] == int(platform['ubse.service']['MainPID']),
         'The pinned Provider engine identity differs from UBSE')
    state = document(root / 'device-state/root.json')
    need(state['run'] == args.run and state['phase'] in ('serving', 'unit_bound', 'slot_verified'),
         'Existing Provider is not serving')
    sdk = Path('/var/lib/aenv-ub-sdk') / ('relay-' + args.run)
    processes = match_process(PROVIDER, 'sdk', sdk / 'device-sdk.json')
    need(len(processes) == 1 and (sdk / 'sdk.sock').is_socket()
         and (root / 'broker/broker.sock').is_socket(), 'Existing Provider SDK or broker is unavailable')
    if host == 'agent1':
        directory = document(sdk / ('directory-' + args.run + '.json'))
        need(directory['run'] == args.run and set(directory['ready']) == {'agent1', 'agent2'}
             and not directory['faulted'] and not directory['closed'], 'The Provider owner directory is unavailable')
    return platform, processes[0]


def runtime_argv(args, mode, host_net=None):
    argv = [PYTHON, '-I', '-B', str(Path(__file__).resolve()), '--run', args.run,
            '--manifest-sha', args.manifest_sha, '--provider-pid', str(args.provider_pid), '--mode', mode]
    return argv + ['--host-net', host_net] if host_net else argv


def run_inside(args, host):
    need(os.readlink('/proc/self/ns/net') != args.host_net, 'Network namespace was not isolated')
    subprocess.run(['/usr/sbin/ip', 'link', 'set', 'dev', 'lo', 'up'], env=ENV, check=True, timeout=10)
    FORWARD.write_text('1\n')
    need(FORWARD.read_text().strip() == '1', 'Private network forwarding did not become ready')
    environment = {**ENV, 'HOME': '/home/jwk', 'API_ADDR': f'127.0.0.1:{API_PORT}',
                   'AENV_UBLK_DAEMON_BINARY_PATH': str(DAEMON),
                   'AENV_UBLK_DAEMON_METRICS_LISTEN_ADDR': '127.0.0.1:9103', 'RUST_LOG': 'info'}
    argv = ['/usr/bin/setpriv', '--reuid=1204', '--regid=1205', '--init-groups', '--no-new-privs',
            '--inh-caps=-all,+net_admin,+sys_admin', '--ambient-caps=-all,+net_admin,+sys_admin',
            '--bounding-set=-all,+net_admin,+sys_admin', '--', str(SERVER), '--config', str(APP / 'config.toml')]
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    server = subprocess.Popen(argv, cwd=APP, env=environment, stdin=subprocess.DEVNULL)
    try:
        wait_health(server, time.monotonic() + 110)
        need((APP / 'r/ublk-daemon.sock').is_socket(), 'AENV recovered but ublk daemon is not ready')
        # systemd receives only stdout from this namespace. The key stays in the app's normal secret store.
        report('MN_AENV_SERVER_READY', node=host, pid=server.pid, apiPort=API_PORT, netnsPid=os.getpid())
        server.wait()
    except InterruptedError:
        pass
    finally:
        if server.poll() is None:
            server.terminate()
        server.wait(timeout=45)
    need(server.returncode == 0, 'AENV Server exited with code ' + str(server.returncode))


def supervise(args, host, root):
    chain(args, host, root)
    pinned(SERVER, SERVER_SHA)
    pinned(DAEMON, DAEMON_SHA)
    need((APP / 'config.toml').is_file() and (APP / 'config.toml').stat().st_uid == 1204,
         'Private runtime config differs')
    need(not os.path.lexists(APP / 'r/ublk-daemon.sock') and not (
         match_process(SERVER) or match_process(DAEMON)), 'Existing private runtime requires reconciliation')
    device = identity()
    need(acl() == ACL_BEFORE, 'Existing ublk ACL differs; retain it')
    host_forward = FORWARD.read_text().strip()
    host_net = os.readlink('/proc/self/ns/net')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        subprocess.run(['/usr/bin/setfacl', '-m', 'u:1204:rw-,m::rw-', '--', str(CONTROL)],
                       env=ENV, check=True, timeout=8)
        need(identity() == device and acl() == ACL_DURING, 'Unexpected device ACL after the runtime grant')
        with scoped_udev():
            child = subprocess.Popen(['/usr/bin/unshare', '--net', '--', *runtime_argv(args, 'inside', host_net)],
                                     env=ENV, stdin=subprocess.DEVNULL)
            try:
                rc = child.wait()
            except InterruptedError:
                if child.poll() is None:
                    child.terminate()
                rc = child.wait(timeout=55)
            need(rc == 0, 'Private AENV runtime exited with code ' + str(rc))
    finally:
        need(identity() == device, 'Ublk control device replaced; leave new ACL untouched')
        if acl() == ACL_DURING:
            restore = '\n'.join(ACL_BEFORE) + '\n'
            subprocess.run(['/usr/bin/setfacl', '--set-file=-', '--', str(CONTROL)], input=restore,
                           env=ENV, text=True, check=True, timeout=8)
        need(acl() == ACL_BEFORE and FORWARD.read_text().strip() == host_forward,
             'Host device ACL or forwarding needs reconciliation')
        report('MN_AENV_RUNTIME_SCOPE_RESTORED', node=host, hostForwarding=host_forward)


def readiness(pid):
    argv = ['/usr/bin/nsenter', '--target', str(pid), '--net', '--',
            '/usr/bin/curl', '--noproxy', '*', '--silent', '--fail', '--max-time', '2',
            '--output', '/dev/null', f'http://127.0.0.1:{API_PORT}/health']
    return subprocess.run(argv, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4).returncode == 0


def dispatch(args, host, root):
    platform, sdk_pid = chain(args, host, root)
    initial = service_status(UNIT)
    need(initial['ActiveState'] == 'inactive' and initial['LoadState'] == 'not-found',
         'The retained runtime unit already exists')
    need(all(service_status(unit)['ActiveState'] not in ('active', 'activating')
             for unit in ('aenv.service', 'agentenv.service')), 'Another AENV unit is active')
    command = ['/usr/bin/systemd-run', '--unit=' + UNIT, '--description=AgentENV M/N Titanic runtime',
               '--property=Type=exec', '--property=KillMode=mixed', '--property=TimeoutStopSec=100s',
               '--property=UMask=0077', '--', *runtime_argv(args, 'supervise')]
    subprocess.run(command, env=ENV, check=True, timeout=20)
    deadline = time.monotonic() + 170
    while time.monotonic() < deadline:
        status = service_status(UNIT)
        if status['ActiveState'] in ('failed', 'inactive'):
            break
        servers, daemons = match_process(SERVER), match_process(DAEMON)
        if len(servers) == len(daemons) == 1 and readiness(servers[0]):
            need(status['ActiveState'] == 'active' and (APP / 'r/ublk-daemon.sock').is_socket(),
                 'AENV API answered but the private unit or ublk daemon is unavailable')
            report('MN_TITANIC_RUNTIME_RETAINED', node=host, run=args.run, unit=UNIT,
                   providerRootPid=args.provider_pid, providerSdkPid=sdk_pid,
                   aenvServerPid=servers[0], ublkDaemonPid=daemons[0], ubServices=platform,
                   serverEndpoint=f'127.0.0.1:{API_PORT}', hostForwarding=FORWARD.read_text().strip())
            return
        time.sleep(0.8)
    info = subprocess.run(['/usr/bin/journalctl', '-u', UNIT, '-n', '32', '--no-pager', '-o', 'cat'],
                          env=ENV, text=True, capture_output=True, timeout=8)
    for line in info.stdout.splitlines():
        if not re.search(r'(?i)password|authorization|private.key|token|api.key|e2b_', line):
            print(line, flush=True)
    # If still starting, stop only this task's transient service and let the supervisor restore permissions.
    if service_status(UNIT)['ActiveState'] in ('active', 'activating'):
        subprocess.run([SYSTEMCTL, 'stop', UNIT], env=ENV, check=True, timeout=105)
    raise RuntimeError('Retained AgentENV service did not reach readiness')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--manifest-sha', required=True)
    parser.add_argument('--provider-pid', type=int, required=True)
    parser.add_argument('--mode', choices=['dispatch', 'supervise', 'inside'], default='dispatch')
    parser.add_argument('--host-net')
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2')
         and re.fullmatch('[0-9a-f]{32}', args.run) and re.fullmatch('[0-9a-f]{64}', args.manifest_sha),
         'Use the M/N root entry for the existing Provider run')
    os.umask(0o077)
    root, _ = checked_generation(args.run, args.manifest_sha, host, args.provider_pid)
    if args.mode == 'inside':
        run_inside(args, host)
    elif args.mode == 'supervise':
        supervise(args, host, root)
    else:
        dispatch(args, host, root)
