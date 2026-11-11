"""Repeat identical lifecycle test with readonly host/netns counter sampling."""
import base64,fcntl,hashlib,http.client,io,json,os,pathlib,pwd,re,signal,stat,subprocess,tarfile,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');UNIT='jwk-aenv-y-clean-20261111.service'
WORKER='IiIiUHJvdmlzaW9uIG9uZSBuYXRpdmUgYW1kNjQgdGVtcGxhdGUgYW5kIHJ1biB0aGUgZXhpc3RpbmcgbmFtZXNwYWNlIGJlbmNobWFyay4iIiIKaW1wb3J0IGJhc2U2NCxmY250bCxoYXNobGliLGh0dHAuY2xpZW50LGlvLGpzb24sb3MscGF0aGxpYixyZSxzb2NrZXQsc3NsLHN1YnByb2Nlc3MsdGFyZmlsZSx0aW1lLHVybGxpYi5lcnJvcix1cmxsaWIucGFyc2UsdXJsbGliLnJlcXVlc3QsemxpYgpQPXBhdGhsaWIuUGF0aDtCQVNFPVAoJy9ob21lL2p3ay9hZW52LXktY2xlYW4tMjAyNjExMTEnKTtXT1JLPUJBU0UvJ3dpa2lkYXRhMDIzJwpSRUc9J3N3ci5jbi1ub3J0aC00Lm15aHVhd2VpY2xvdWQuY29tJztSRVBPPSdrdW5wZW5nLWFpL3N3ZXJlYmVuY2gteDg2LXdpa2lkYXRhLXdpa2lkYXRhLXRvb2xraXQnO1RBRz0nNzE3LWU5OWYxOTYnCk5BTUU9J3N3Yi13aWtpZGF0YS13aWtpZGF0YS10b29sa2l0LTcxNy1yZXRyeTAxNyc7U1RBVEU9e307S0VZPU5vbmU7VE9LRU49Tm9uZQpkZWYgc2F2ZShwaGFzZSwqKnZhbHVlcyk6CiAgICBTVEFURS51cGRhdGUocGhhc2U9cGhhc2UsdXBkYXRlZFVuaXg9dGltZS50aW1lKCksKip2YWx1ZXMpCiAgICB0ZW1wPVdPUksvJ3N0YXRlLm5leHQnO3RlbXAud3JpdGVfdGV4dChqc29uLmR1bXBzKFNUQVRFLGluZGVudD0yKSsnXG4nKTt0ZW1wLnJlcGxhY2UoV09SSy8nc3RhdGUuanNvbicpCiAgICBwcmludCgnV0lLSURBVEFfUEhBU0U9JytwaGFzZSxmbHVzaD1UcnVlKQpkZWYgYXBpKG1ldGhvZCxwYXRoLGJvZHk9Tm9uZSk6CiAgICBjb25uPWh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKCcxMjcuMC4wLjEnLDE4MDgwLHRpbWVvdXQ9OTApCiAgICB0cnk6CiAgICAgICAgY29ubi5yZXF1ZXN0KG1ldGhvZCxwYXRoLGJvZHk9anNvbi5kdW1wcyhib2R5KSBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgTm9uZSxoZWFkZXJzPXsnWC1BUEktS2V5JzpLRVksJ0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfSkKICAgICAgICByZXNwb25zZT1jb25uLmdldHJlc3BvbnNlKCk7cmF3PXJlc3BvbnNlLnJlYWQoMioxMDI0KioyKQogICAgICAgIGFzc2VydCAyMDA8PXJlc3BvbnNlLnN0YXR1czwzMDAsJ0FQSSAnK21ldGhvZCsnICcrcGF0aCsnIEhUVFAgJytzdHIocmVzcG9uc2Uuc3RhdHVzKSsnICcrcmF3WzoxNTAwXS5kZWNvZGUoZXJyb3JzPSdyZXBsYWNlJykKICAgICAgICByZXR1cm4ganNvbi5sb2FkcyhyYXcpIGlmIHJhdyBlbHNlIE5vbmUKICAgIGZpbmFsbHk6Y29ubi5jbG9zZSgpCmRlZiByZWdpc3RyeShwYXRoLGFjY2VwdD1Ob25lKToKICAgIGdsb2JhbCBUT0tFTgogICAgaGVhZGVycz17J0FjY2VwdCc6YWNjZXB0fSBpZiBhY2NlcHQgZWxzZSB7fQogICAgaWYgVE9LRU46aGVhZGVyc1snQXV0aG9yaXphdGlvbiddPSdCZWFyZXIgJytUT0tFTgogICAgcmVxdWVzdD11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KCdodHRwczovLycrUkVHK3BhdGgsaGVhZGVycz1oZWFkZXJzKQogICAgdHJ5OgogICAgICAgIHdpdGggdXJsbGliLnJlcXVlc3QudXJsb3BlbihyZXF1ZXN0LHRpbWVvdXQ9MTIwKSBhcyByOnJldHVybiByLnJlYWQoOCoxMDI0KioyKSxkaWN0KHIuaGVhZGVycykKICAgIGV4Y2VwdCB1cmxsaWIuZXJyb3IuSFRUUEVycm9yIGFzIGVycm9yOgogICAgICAgIGlmIGVycm9yLmNvZGUhPTQwMTpyYWlzZSBSdW50aW1lRXJyb3IoJ1JlZ2lzdHJ5IEhUVFAgJytzdHIoZXJyb3IuY29kZSkpIGZyb20gTm9uZQogICAgICAgIGNoYWxsZW5nZT1lcnJvci5oZWFkZXJzLmdldCgnV1dXLUF1dGhlbnRpY2F0ZScsJycpCiAgICAgICAgYXNzZXJ0IGNoYWxsZW5nZS5sb3dlcigpLnN0YXJ0c3dpdGgoJ2JlYXJlciAnKSwnVW5zdXBwb3J0ZWQgYW5vbnltb3VzIHJlZ2lzdHJ5IGNoYWxsZW5nZScKICAgICAgICBmaWVsZHM9ZGljdChyZS5maW5kYWxsKHInKFx3Kyk9IihbXiJdKikiJyxjaGFsbGVuZ2UpKQogICAgICAgIHJlYWxtPXVybGxpYi5wYXJzZS51cmxzcGxpdChmaWVsZHNbJ3JlYWxtJ10pO2Fzc2VydCByZWFsbS5zY2hlbWU9PSdodHRwcycgYW5kIHJlYWxtLmhvc3RuYW1lPT1SRUcKICAgICAgICBzY29wZT0ncmVwb3NpdG9yeTonK1JFUE8rJzpwdWxsJzthc3NlcnQgZmllbGRzLmdldCgnc2NvcGUnLHNjb3BlKT09c2NvcGUKICAgICAgICBxdWVyeT11cmxsaWIucGFyc2UucGFyc2VfcXNsKHJlYWxtLnF1ZXJ5KStbKCdzZXJ2aWNlJyxmaWVsZHMuZ2V0KCdzZXJ2aWNlJyxSRUcpKSwoJ3Njb3BlJyxzY29wZSldCiAgICAgICAgdXJsPXVybGxpYi5wYXJzZS51cmx1bnNwbGl0KHJlYWxtLl9yZXBsYWNlKHF1ZXJ5PXVybGxpYi5wYXJzZS51cmxlbmNvZGUocXVlcnkpKSkKICAgICAgICB3aXRoIHVybGxpYi5yZXF1ZXN0LnVybG9wZW4odXJsLHRpbWVvdXQ9OTApIGFzIHI6dG9rZW49anNvbi5sb2FkKHIpCiAgICAgICAgVE9LRU49dG9rZW4uZ2V0KCd0b2tlbicpIG9yIHRva2VuLmdldCgnYWNjZXNzX3Rva2VuJyk7YXNzZXJ0IFRPS0VOCiAgICAgICAgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddPSdCZWFyZXIgJytUT0tFTgogICAgICAgIHdpdGggdXJsbGliLnJlcXVlc3QudXJsb3Blbih1cmxsaWIucmVxdWVzdC5SZXF1ZXN0KHJlcXVlc3QuZnVsbF91cmwsaGVhZGVycz1oZWFkZXJzKSx0aW1lb3V0PTEyMCkgYXMgcjpyZXR1cm4gci5yZWFkKDgqMTAyNCoqMiksZGljdChyLmhlYWRlcnMpCmRlZiBwaW5uZWRfaW1hZ2UoKToKICAgIGFjY2VwdD0nLCcuam9pbihbJ2FwcGxpY2F0aW9uL3ZuZC5vY2kuaW1hZ2UuaW5kZXgudjEranNvbicsJ2FwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuZGlzdHJpYnV0aW9uLm1hbmlmZXN0Lmxpc3QudjIranNvbicsJ2FwcGxpY2F0aW9uL3ZuZC5vY2kuaW1hZ2UubWFuaWZlc3QudjEranNvbicsJ2FwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuZGlzdHJpYnV0aW9uLm1hbmlmZXN0LnYyK2pzb24nXSkKICAgIHJhdyxfPXJlZ2lzdHJ5KCcvdjIvJytSRVBPKycvbWFuaWZlc3RzL3NoYTI1NjphMjg1NzRkNzhjNTFhZjJiMzQxZjc2OWI0ODRhZWQwMjM0MDYwMTVjYjJhMjQ5ZTk4NWEwYmJkY2QwMjI3NzViJyxhY2NlcHQpO2RvYz1qc29uLmxvYWRzKHJhdykKICAgIGlmICdtYW5pZmVzdHMnIGluIGRvYzoKICAgICAgICBzZWxlY3RlZD1beCBmb3IgeCBpbiBkb2NbJ21hbmlmZXN0cyddIGlmIHguZ2V0KCdwbGF0Zm9ybScse30pLmdldCgnYXJjaGl0ZWN0dXJlJyk9PSdhbWQ2NCcgYW5kIHguZ2V0KCdwbGF0Zm9ybScse30pLmdldCgnb3MnKT09J2xpbnV4J10KICAgICAgICBhc3NlcnQgbGVuKHNlbGVjdGVkKT09MSwnQW1iaWd1b3VzIG5hdGl2ZSBhbWQ2NCBpbWFnZScKICAgICAgICBleHBlY3RlZD1zZWxlY3RlZFswXVsnZGlnZXN0J107cmF3LF89cmVnaXN0cnkoJy92Mi8nK1JFUE8rJy9tYW5pZmVzdHMvJytleHBlY3RlZCxhY2NlcHQpCiAgICAgICAgYXNzZXJ0ICdzaGEyNTY6JytoYXNobGliLnNoYTI1NihyYXcpLmhleGRpZ2VzdCgpPT1leHBlY3RlZAogICAgICAgIGRvYz1qc29uLmxvYWRzKHJhdykKICAgIGRpZ2VzdD0nc2hhMjU2OicraGFzaGxpYi5zaGEyNTYocmF3KS5oZXhkaWdlc3QoKTtjb25maWdfZGlnZXN0PWRvY1snY29uZmlnJ11bJ2RpZ2VzdCddCiAgICBjb25maWdfcmF3LF89cmVnaXN0cnkoJy92Mi8nK1JFUE8rJy9ibG9icy8nK2NvbmZpZ19kaWdlc3QpCiAgICBhc3NlcnQgJ3NoYTI1NjonK2hhc2hsaWIuc2hhMjU2KGNvbmZpZ19yYXcpLmhleGRpZ2VzdCgpPT1jb25maWdfZGlnZXN0CiAgICBjb25maWc9anNvbi5sb2Fkcyhjb25maWdfcmF3KTthc3NlcnQgY29uZmlnWydhcmNoaXRlY3R1cmUnXT09J2FtZDY0JyBhbmQgY29uZmlnWydvcyddPT0nbGludXgnCiAgICAoV09SSy8nb2NpLW1hbmlmZXN0Lmpzb24nKS53cml0ZV9ieXRlcyhyYXcpOyhXT1JLLydvY2ktY29uZmlnLmpzb24nKS53cml0ZV9ieXRlcyhjb25maWdfcmF3KQogICAgYXNzZXJ0IGRpZ2VzdD09J3NoYTI1NjphMjg1NzRkNzhjNTFhZjJiMzQxZjc2OWI0ODRhZWQwMjM0MDYwMTVjYjJhMjQ5ZTk4NWEwYmJkY2QwMjI3NzViJwogICAgcmV0dXJuIFJFRysnLycrUkVQTysnQCcrZGlnZXN0LHsndGFnJzpSRUcrJy8nK1JFUE8rJzonK1RBRywnZGlnZXN0JzpkaWdlc3QsJ2FyY2hpdGVjdHVyZSc6J2FtZDY0Jywnb3MnOidsaW51eCcsJ2NvbmZpZ0RpZ2VzdCc6Y29uZmlnX2RpZ2VzdCwnbGF5ZXJDb3VudCc6bGVuKGRvY1snbGF5ZXJzJ10pfQpkZWYgbWFpbigpOgogICAgZ2xvYmFsIEtFWQogICAgYXNzZXJ0IG9zLmdldHVpZCgpPT1vcy5nZXRldWlkKCk9PTEwMDIKICAgIHN0YXR1cz1QKCcvcHJvYy9zZWxmL3N0YXR1cycpLnJlYWRfdGV4dCgpO2NhcHM9e2E6aW50KGIuc3RyaXAoKSwxNikgZm9yIGxpbmUgaW4gc3RhdHVzLnNwbGl0bGluZXMoKSBpZiAnOicgaW4gbGluZSBmb3IgYSxiIGluIFtsaW5lLnNwbGl0KCc6JywxKV0gaWYgYS5zdGFydHN3aXRoKCdDYXAnKX0KICAgIGFzc2VydCBhbGwoY2Fwc1tuXT09MCBmb3IgbiBpbiAoJ0NhcEVmZicsJ0NhcFBybScsJ0NhcEluaCcsJ0NhcEFtYicpKQogICAgbG9jaz0oQkFTRS8nci93aWtpZGF0YTAyMy5sb2NrJykub3BlbignYScpO2ZjbnRsLmZsb2NrKGxvY2ssZmNudGwuTE9DS19FWHxmY250bC5MT0NLX05CKQogICAgYXNzZXJ0IG5vdCBXT1JLLmV4aXN0cygpLCdFeGlzdGluZyBleHBlcmltZW50IHByZXNlcnZlZDsgcmVjb25jaWxlIGJlZm9yZSByZXRyeScKICAgIFdPUksubWtkaXIobW9kZT0wbzcwMCk7S0VZPShCQVNFLydjb25maWcvYXBpLWtleScpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIHRyeToKICAgICAgICBzYXZlKCdhZG1pdHRlZCcsdWlkPW9zLmdldHVpZCgpLGNhcHM9Y2FwcyxuZXRucz1vcy5zdGF0KCcvcHJvYy9zZWxmL25zL25ldCcpLnN0X2lubyxiZW5jaG1hcmtSdW49RmFsc2UpCiAgICAgICAgY29ubj1odHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbignMTI3LjAuMC4xJywxODA4MCx0aW1lb3V0PTEwKTtjb25uLnJlcXVlc3QoJ0dFVCcsJy9oZWFsdGgnKTthc3NlcnQgY29ubi5nZXRyZXNwb25zZSgpLnN0YXR1cz09MjA0O2Nvbm4uY2xvc2UoKQogICAgICAgIGFzc2VydCBhcGkoJ0dFVCcsJy92Mi9zYW5kYm94ZXM/bGltaXQ9MTAwJyk9PVtdLCdSdW50aW1lIGlzIG5vdCBlbXB0eScKICAgICAgICBwcmV2aW91cz1qc29uLmxvYWRzKChCQVNFLyd3aWtpZGF0YTAxNy9yZXN1bHQuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIHNpZD1wcmV2aW91c1sndGVtcGxhdGVJZCddO2JpZD1wcmV2aW91c1snYnVpbGRJZCddCiAgICAgICAgYXNzZXJ0IHByZXZpb3VzWydidWlsZFN0YXR1cyddWydzdGF0dXMnXT09J3JlYWR5JwogICAgICAgIHJvdz1uZXh0KHIgZm9yIHIgaW4gYXBpKCdHRVQnLCcvdGVtcGxhdGVzJykgaWYgclsndGVtcGxhdGVJRCddPT1zaWQpCiAgICAgICAgYXNzZXJ0IHJvd1snY3B1Q291bnQnXT09MiBhbmQgcm93WydtZW1vcnlNQiddPT00MDk2IGFuZCByb3cuZ2V0KCdidWlsZFN0YXR1cycsJ3JlYWR5Jyk9PSdyZWFkeScKICAgICAgICBhc3NlcnQganNvbi5sb2FkcygoQkFTRS8nY29uZmlnL2JlbmNoX2ltYWdlX21hcC5qc29uJykucmVhZF90ZXh0KCkpPT17TkFNRTpzaWR9CiAgICAgICAgc2F2ZSgnZXhpc3RpbmdfdGVtcGxhdGVfcmVhZHknLHRlbXBsYXRlSWQ9c2lkLGJ1aWxkSWQ9YmlkLHRlbXBsYXRlPXJvdyxpbWFnZT1wcmV2aW91c1snaW1hZ2UnXSxpbWFnZVByb29mPXByZXZpb3VzWydpbWFnZVByb29mJ10pCiAgICAgICAgYXNzZXJ0IGFwaSgnR0VUJywnL3YyL3NhbmRib3hlcz9saW1pdD0xMDAnKT09W10KICAgICAgICBhdmFpbGFibGU9bmV4dChpbnQobGluZS5zcGxpdCgpWzFdKSoxMDI0IGZvciBsaW5lIGluIFAoJy9wcm9jL21lbWluZm8nKS5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCkgaWYgbGluZS5zdGFydHN3aXRoKCdNZW1BdmFpbGFibGU6JykpCiAgICAgICAgYXNzZXJ0IGF2YWlsYWJsZT4xMjgqMioqMzAsJ0luc3VmZmljaWVudCBtZW1vcnkgcmVzZXJ2ZScKICAgICAgICByZXN1bHQ9QkFTRS8ncmVzdWx0cy93aWtpZGF0YTAyMyc7cmVzdWx0Lm1rZGlyKG1vZGU9MG83MDApCiAgICAgICAgZW52aXJvbm1lbnQ9ZGljdChvcy5lbnZpcm9uKQogICAgICAgIGZvciBuYW1lIGluICgnSFRUUF9QUk9YWScsJ0hUVFBTX1BST1hZJywnQUxMX1BST1hZJywnaHR0cF9wcm94eScsJ2h0dHBzX3Byb3h5JywnYWxsX3Byb3h5JywnUFlUSE9OUEFUSCcsJ1BZVEhPTkhPTUUnKTplbnZpcm9ubWVudC5wb3AobmFtZSxOb25lKQogICAgICAgIGVudmlyb25tZW50LnVwZGF0ZShFMkJfQVBJX0tFWT1LRVksRTJCX0FDQ0VTU19UT0tFTj0nZHVtbXknLE5PX1BST1hZPSdsb2NhbGhvc3QsMTI3LjAuMC4xJyxub19wcm94eT0nbG9jYWxob3N0LDEyNy4wLjAuMScsUFlUSE9OTk9VU0VSU0lURT0nMScsUFlUSE9OVU5CVUZGRVJFRD0nMScpCiAgICAgICAgdHJhbnNwb3J0PXsndWlkJzpvcy5nZXR1aWQoKSwnY2Fwcyc6Y2FwcywnbmV0bnMnOm9zLnN0YXQoJy9wcm9jL3NlbGYvbnMvbmV0Jykuc3RfaW5vLCdhcGknOidkaXJlY3QgUnVzdCAxMjcuMC4wLjE6MTgwODAnfQogICAgICAgIChyZXN1bHQvJ3RyYW5zcG9ydC5qc29uJykud3JpdGVfdGV4dChqc29uLmR1bXBzKHRyYW5zcG9ydCkrJ1xuJykKICAgICAgICBmb3IgbGFiZWwscm91bmRzIGluIFsoJ3ByZXdhcm0xMDAnLDEpLCgnZm9ybWFsJyw1KV06CiAgICAgICAgICAgIHBvb2w9W10KICAgICAgICAgICAgZm9yIHByb2MgaW4gUCgnL3Byb2MnKS5pdGVyZGlyKCk6CiAgICAgICAgICAgICAgICBpZiBub3QgcHJvYy5uYW1lLmlzZGlnaXQoKTpjb250aW51ZQogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIGlmIHByb2Muc3RhdCgpLnN0X3VpZD09MTAwMiBhbmQgKHByb2MvJ2NvbW0nKS5yZWFkX3RleHQoKS5zdHJpcCgpPT0nZmlyZWNyYWNrZXInIGFuZCBQKG9zLnJlYWRsaW5rKHByb2MvJ2N3ZCcpKS5pc19yZWxhdGl2ZV90byhCQVNFLydmYycpOnBvb2wuYXBwZW5kKGludChwcm9jLm5hbWUpKQogICAgICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6cGFzcwogICAgICAgICAgICBzYXZlKGxhYmVsKydfcnVubmluZycscm91bmRzPXJvdW5kcyx0b3RhbD0xMDAsYmF0Y2hTaXplPTEwMCxiZW5jaG1hcmtSdW49VHJ1ZSxyZXN1bHREaXI9c3RyKHJlc3VsdCksKip7bGFiZWwrJ0luaXRpYWxGQ0NvdW50JzpsZW4ocG9vbCl9KQogICAgICAgICAgICBjb21tYW5kPVtzdHIoQkFTRS8nc2RrL2c0LWUyYjI0Ni9iaW4vcHl0aG9uJyksJy1CJyxzdHIoQkFTRS8nZzQtYmVuY2htYXJrX3NhbmRib3hfbGlmZWN5Y2xlLnB5JyksCiAgICAgICAgICAgICAgICAnLS1hcGktdXJsJywnaHR0cDovLzEyNy4wLjAuMToxODA4MCcsJy0tdG90YWwnLCcxMDAnLCctLWJhdGNoLXNpemUnLCcxMDAnLCctLXJvdW5kcycsc3RyKHJvdW5kcyksCiAgICAgICAgICAgICAgICAnLS1pbWFnZS1tYXAnLHN0cihCQVNFLydjb25maWcvYmVuY2hfaW1hZ2VfbWFwLmpzb24nKSwnLS1vdXRwdXQtZGlyJyxzdHIocmVzdWx0L2xhYmVsKV0KICAgICAgICAgICAgd2l0aCAocmVzdWx0LyhsYWJlbCsnLmxvZycpKS5vcGVuKCd4YicpIGFzIGxvZzoKICAgICAgICAgICAgICAgIHByb2Nlc3M9c3VicHJvY2Vzcy5ydW4oY29tbWFuZCxlbnY9ZW52aXJvbm1lbnQsc3Rkb3V0PWxvZyxzdGRlcnI9c3VicHJvY2Vzcy5TVERPVVQsdGltZW91dD02OTAwKQogICAgICAgICAgICBhc3NlcnQgcHJvY2Vzcy5yZXR1cm5jb2RlPT0wLGxhYmVsKycgYmVuY2htYXJrIGZhaWxlZCwgaW5zcGVjdCBwZXJzaXN0ZWQgbG9nJwogICAgICAgICAgICBzdW1tYXJ5PWpzb24ubG9hZHMoKHJlc3VsdC9sYWJlbC8nc3VtbWFyeS5qc29uJykucmVhZF90ZXh0KCkpO2Fzc2VydCBzdW1tYXJ5LmdldCgndmFsaWQnKSxsYWJlbCsnIHN1bW1hcnkgaW52YWxpZCcKICAgICAgICBmaW5pc2hlZD1UcnVlCiAgICAgICAgc3VtbWFyaWVzPXtsYWJlbDpqc29uLmxvYWRzKChyZXN1bHQvbGFiZWwvJ3N1bW1hcnkuanNvbicpLnJlYWRfdGV4dCgpKSBmb3IgbGFiZWwgaW4gKCdwcmV3YXJtMTAwJywnZm9ybWFsJyl9CiAgICAgICAgaW52ZW50b3J5PWFwaSgnR0VUJywnL3YyL3NhbmRib3hlcz9saW1pdD0xMDAnKQogICAgICAgIHNhdmUoJ2JlbmNobWFya19maW5pc2hlZCcsYmVuY2htYXJrRXhpdFplcm89ZmluaXNoZWQsc3VtbWFyaWVzPXN1bW1hcmllcyxmaW5hbEludmVudG9yeUNvdW50PWxlbihpbnZlbnRvcnkpKQogICAgICAgIGFyY2hpdmU9aW8uQnl0ZXNJTygpCiAgICAgICAgd2l0aCB0YXJmaWxlLm9wZW4oZmlsZW9iaj1hcmNoaXZlLG1vZGU9J3c6Z3onKSBhcyB0YXI6CiAgICAgICAgICAgIGZvciBwYXRoIGluIHNvcnRlZChyZXN1bHQucmdsb2IoJyonKSk6CiAgICAgICAgICAgICAgICBpZiBwYXRoLmlzX2ZpbGUoKSBhbmQgcGF0aC5zdWZmaXggaW4gKCcuanNvbicsJy5qc29ubCcsJy5jc3YnLCcubG9nJyk6CiAgICAgICAgICAgICAgICAgICAgYXNzZXJ0IHBhdGguc3RhdCgpLnN0X3NpemU8OCoxMDI0KioyCiAgICAgICAgICAgICAgICAgICAgdGFyLmFkZChwYXRoLGFyY25hbWU9c3RyKHBhdGgucmVsYXRpdmVfdG8ocmVzdWx0KSkscmVjdXJzaXZlPUZhbHNlKQogICAgICAgIGJsb2I9YXJjaGl2ZS5nZXR2YWx1ZSgpO2Fzc2VydCBsZW4oYmxvYik8MTIwMDAwMCwnQmVuY2htYXJrIGFyY2hpdmUgdG9vIGxhcmdlOyBwcmVzZXJ2ZSBmdWxsIGxvY2FsIHJlc3VsdHMnCiAgICAgICAgU1RBVEVbJ2FyY2hpdmUnXT17J3NoYTI1Nic6aGFzaGxpYi5zaGEyNTYoYmxvYikuaGV4ZGlnZXN0KCksJ2J5dGVzJzpsZW4oYmxvYiksJ2Jhc2U2NCc6YmFzZTY0LmI2NGVuY29kZShibG9iKS5kZWNvZGUoKX0KICAgICAgICBhc3NlcnQgZmluaXNoZWQgYW5kIGFsbChzLmdldCgndmFsaWQnKSBmb3IgcyBpbiBzdW1tYXJpZXMudmFsdWVzKCkpIGFuZCBub3QgaW52ZW50b3J5LCdCZW5jaG1hcmsgaW52YWxpZCBvciBjbGVhbnVwIGluY29tcGxldGUnCiAgICAgICAgU1RBVEVbJ3N1Y2Nlc3MnXT1UcnVlCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbiBhcyBlcnJvcjoKICAgICAgICBTVEFURS51cGRhdGUoc3VjY2Vzcz1GYWxzZSxlcnJvclR5cGU9dHlwZShlcnJvcikuX19uYW1lX18sZXJyb3I9c3RyKGVycm9yKVs6MjAwMF0pO3JhaXNlCiAgICBmaW5hbGx5OgogICAgICAgIChXT1JLLydyZXN1bHQuanNvbicpLndyaXRlX3RleHQoanNvbi5kdW1wcyhTVEFURSxpbmRlbnQ9MikrJ1xuJykKICAgICAgICBwcmludCgnV0lLSURBVEFfUkVTVUxUPScranNvbi5kdW1wcyhTVEFURSxzZXBhcmF0b3JzPSgnLCcsJzonKSksZmx1c2g9VHJ1ZSkKaWYgX19uYW1lX189PSdfX21haW5fXyc6bWFpbigpCg==';WORKER_SHA='8c5cc8bbeca8daa15d8ccd130f48d2962cd6bcb6aa32ff34772c4278c562210c'
TARGET={'1': '4096', '2': '8192', '3': '16384'}
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 assert os.getuid()==os.geteuid()==0;os.umask(0o077)
 previous=json.loads((BASE/'deployment014/result.json').read_text());pid=previous['serverPid'];inputs=json.loads((BASE/'runtime-prep005/result.json').read_text())
 props=dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',UNIT,'-p','MainPID','-p','ActiveState'],text=True).splitlines())
 assert props['ActiveState']=='active' and int(props['MainPID'])==pid
 assert sha(P('/proc',str(pid),'exe'))==inputs['native_inputs']['server']['sha256']
 assert sha(BASE/'config/runtime005.toml')==inputs['service_configuration']['sha256']
 assert sha(BASE/'g4-benchmark_sandbox_lifecycle.py')=='7c26ea29fe8a117859365be18bd8893b1145b3e8c7bf9cdaaeb094a2d0e13263'
 assert P('/proc/sys/kernel/random/boot_id').read_text().strip()==previous['runtime_attestation']['boot_id']
 directory=BASE/'deployment023';assert not directory.exists();directory.mkdir(mode=0o700);os.chown(directory,1002,1002)
 raw=base64.b64decode(WORKER,validate=True);assert hashlib.sha256(raw).hexdigest()==WORKER_SHA;compile(raw,'worker023','exec')
 worker=directory/'wikidata023_worker.py';worker.write_bytes(raw);os.chown(worker,1002,1002);worker.chmod(0o700)
 ca=json.loads((BASE/'config/egress-proxy.json').read_text())['ca'];key=(BASE/'config/api-key').read_text().strip()
 env={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','HOME':pwd.getpwnam('jwk').pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','SSL_CERT_FILE':ca,'NO_PROXY':'localhost,127.0.0.1','no_proxy':'localhost,127.0.0.1'}
 command=['nsenter','--target',str(pid),'--net','--mount','--','setpriv','--reuid=1002','--regid=1002','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/usr/bin/python3','-I','-B',str(worker)]
 outcome={'parameterChanges':True,'serviceRestarted':False,'templateRebuilt':False,'serverPid':pid,'persistentFilesModified':False,'comparisonReference':'unchanged low-threshold run018'}
 def read(path,limit=40000):
  try:return P(path).read_text()[:limit]
  except OSError:return None
 def arp_stats():
  raw=read('/proc/net/stat/arp_cache',200000)
  if not raw:return {'available':False}
  lines=raw.splitlines();names=lines[0].split();rows=[[int(x,16) for x in line.split()] for line in lines[1:] if line.strip()]
  assert rows and all(len(row)==len(names) for row in rows)
  return {'available':True,'entries':rows[0][names.index('entries')],'cpuRows':len(rows),
   'counters':{name:sum(row[i] for row in rows) for i,name in enumerate(names) if name!='entries'}}
 def threshold_values():return {str(i):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).read_text().strip() for i in (1,2,3)}
 def empty_inventory():
  for state in ('running','paused'):
   conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
   try:
    conn.request('GET','/v2/sandboxes?limit=1&state='+state,headers={'X-API-Key':key});response=conn.getresponse()
    assert response.status==200 and json.loads(response.read())==[],'Runtime has existing '+state+' sandboxes'
   finally:conn.close()
 def sample():
  proc=P('/proc',str(pid));row={'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),
   'cpuStat':read('/proc/stat',3000),'meminfo':read('/proc/meminfo',5000),'loadavg':read('/proc/loadavg',300),
   'cpuPressure':read('/proc/pressure/cpu',1500),'memoryPressure':read('/proc/pressure/memory',1500),
   'serverStatus':read(proc/'status',4000),'netstat':read(proc/'net/netstat',16000),'snmp':read(proc/'net/snmp',4000),
   'sockstat':read(proc/'net/sockstat',2000),'netdev':read(proc/'net/dev',4000),'arp':arp_stats()}
  for label,name in [('tcpListen','tcp'),('tcp6Listen','tcp6')]:
   table=read(proc/('net/'+name),300000) or ''
   row[label]=[line for line in table.splitlines()[1:] if ':46A0 ' in line and ' 0A ' in line]
  cg=P('/sys/fs/cgroup/system.slice')/UNIT
  row['cgroup']={name:read(cg/name,4000) for name in ('cpu.stat','cpu.max','cpu.pressure','memory.current','memory.events','memory.pressure','pids.current','pids.max')}
  return row
 try:
  empty_inventory()
  lock_path=BASE/'scripts/.run.lock'
  if lock_path.exists():
   st=lock_path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==1002
  lockfd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  os.fchown(lockfd,1002,1002);fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for proc in P('/proc').iterdir():
   if not proc.name.isdigit():continue
   try:
    if proc.stat().st_uid!=1002:continue
    args=(proc/'cmdline').read_bytes().split(b'\0')
    assert not any(P(a.decode(errors='replace')).name in ('benchmark_sandbox_lifecycle.py','g4-benchmark_sandbox_lifecycle.py') for a in args if a),'Another jwk benchmark is active'
   except (FileNotFoundError,PermissionError,ProcessLookupError):continue
  before=threshold_values();assert before in ({'1':'128','2':'512','3':'1024'},TARGET),'Thresholds changed since reviewed inventory'
  outcome.update(thresholdsBefore=before,thresholdsTarget=TARGET,arpBefore=arp_stats(),startUnix=time.time())
  record=directory/'threshold-change.json';record.write_text(json.dumps({'before':before,'target':TARGET,'persistentFilesModified':False,'applied':False},indent=2)+'\n');os.chown(record,1002,1002)
  try:
   for i in (3,2,1):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).write_text(TARGET[str(i)]+'\n')
   assert threshold_values()==TARGET
  except BaseException:
   for i in (1,2,3):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).write_text(before[str(i)]+'\n')
   raise
  record.write_text(json.dumps({'before':before,'target':TARGET,'persistentFilesModified':False,'applied':True,'restoredAfterBenchmark':False},indent=2)+'\n')
  probe=subprocess.run(['nsenter','--target',str(pid),'--net','--','ip','-j','-s','ntable','show'],env=env,capture_output=True,text=True,timeout=30)
  assert probe.returncode==0,'Cannot verify threshold visibility in service netns'
  tables=json.loads(probe.stdout);rows=[r for r in tables if r.get('name')=='arp_cache' and 'thresh1' in r]
  assert rows and all([r['thresh1'],r['thresh2'],r['thresh3']]==[int(TARGET[str(i)]) for i in (1,2,3)] for r in rows)
  outcome['runtimeThresholdVerification']={k:rows[0].get(k) for k in ('thresh1','thresh2','thresh3','table_fulls','forced_gc_runs','res_failed','entries')}
  with (directory/'worker.log').open('xb') as log,(directory/'samples.jsonl').open('x') as samples:
   process=subprocess.Popen(command,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   deadline=time.monotonic()+10000
   while process.poll() is None:
    samples.write(json.dumps(sample())+'\n');samples.flush()
    if time.monotonic()>deadline:
     os.killpg(process.pid,signal.SIGTERM);raise TimeoutError('Own experiment deadline exceeded; preserve results')
    time.sleep(1)
   outcome['workerExitCode']=process.returncode
  text=(directory/'worker.log').read_text(errors='replace')
  entry=next((json.loads(line.split('=',1)[1]) for line in text.splitlines() if line.startswith('WIKIDATA_RESULT=')),{})
  outcome['worker']={k:v for k,v in entry.items() if k!='archive'}
  assert process.returncode==0,'Repeated benchmark failed; raw data and counters returned'
  outcome['success']=True
 except BaseException as error:
  outcome.update(success=False,errorType=type(error).__name__,error=str(error)[-2000:]);raise
 finally:
  outcome['thresholdsAfter']=threshold_values();outcome['arpAfter']=arp_stats()
  outcome['newThresholdsRetained']=outcome['thresholdsAfter']==TARGET
  kernel=subprocess.run(['journalctl','-k','--since','@'+str(int(outcome.get('startUnix',time.time()))),'--no-pager','-o','short-iso'],env=env,capture_output=True,text=True,timeout=30)
  outcome['neighborKernelLogs']=[line for line in kernel.stdout.splitlines() if re.search(r'(arp_cache|ndisc_cache).*overflow|net_ratelimit',line,re.I)][-100:]
  archive=io.BytesIO()
  with tarfile.open(fileobj=archive,mode='w:gz') as tar:
   result=BASE/'results/wikidata023'
   if result.exists():
    for path in result.rglob('*'):
     if path.is_file() and not path.is_symlink() and path.stat().st_size<8*1024**2:tar.add(path,arcname='result/'+str(path.relative_to(result)),recursive=False)
   for name in ('samples.jsonl','worker.log','threshold-change.json'):
    path=directory/name
    if path.exists() and path.stat().st_size<12*1024**2:tar.add(path,arcname='observer/'+name,recursive=False)
  blob=archive.getvalue();assert len(blob)<1200000,'Returned archive exceeds bound; preserved on Y'
  outcome['archive']={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),'base64':base64.b64encode(blob).decode()}
  outcome['serverLogTail']=((BASE/'logs/server.log').read_text(errors='replace')[-20000:]).replace(key,'[REDACTED_API_KEY]')
  (directory/'result.json').write_text(json.dumps(outcome,indent=2)+'\n');os.chown(directory/'result.json',1002,1002)
  print('NEIGHBOR023_RESULT='+json.dumps(outcome,separators=(',',':')),flush=True)
if __name__=='__main__':main()
