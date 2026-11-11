"""Resume after an optional systemd version-probe failure; start an isolated jwk unit."""
import base64,grp,hashlib,json,os,pathlib,pwd,re,shutil,socket,stat,subprocess,time,tomllib,urllib.request
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');ROOT=P('/run/jwk-aenv-y-clean-20261111')
UNIT='jwk-aenv-y-clean-20261111.service';BROKER='jwk-aenv-y-devices-20261111.service';RELAYS='jwk-aenv-y-relays-20261111.service'
BUNDLE={'runtime_supervisor008.py': {'base64': 'IiIiSW5kZXBlbmRlbnQgandrIHJ1bnRpbWUgYW5kIHVucHJpdmlsZWdlZCBuYW1lc3BhY2UgcmVsYXlzL2JlbmNobWFyayBydW5uZXIuIiIiCmltcG9ydCBhc3luY2lvLGN0eXBlcyxqc29uLG9zLHBhdGhsaWIscHdkLHNodXRpbCxzb2NrZXQsc3RydWN0LHN1YnByb2Nlc3Msc3lzLHRpbWUsc3NsCmZyb20gdXJsbGliLnBhcnNlIGltcG9ydCB1cmxzcGxpdApCQVNFPXBhdGhsaWIuUGF0aCgnL2hvbWUvandrL2FlbnYteS1jbGVhbi0yMDI2MTExMScpO0lQQz1CQVNFLydyJwpDQVBTPSgxPDwyMSl8KDE8PDEyKQpBTExPV0VEPSgnZ2l0aHViLmNvbScsJ2dpdGh1YnVzZXJjb250ZW50LmNvbScsJ2doY3IuaW8nLCdkb2NrZXIuaW8nLCdkb2NrZXIuY29tJywnYW1hem9uYXdzLmNvbScsJ2Nsb3VkZnJvbnQubmV0JywKICdteWh1YXdlaWNsb3VkLmNvbScsJ2h1YXdlaWNsb3VkLmNvbScsJ3F1YXkuaW8nLCdnY3IuaW8nLCdwa2cuZGV2JywnZ29vZ2xlYXBpcy5jb20nKQpkZWYgcmVxdWlyZShvayxtZXNzYWdlKToKICAgIGlmIG5vdCBvazpyYWlzZSBSdW50aW1lRXJyb3IobWVzc2FnZSkKZGVmIGNhcHMoKToKICAgIHJldHVybiB7YTppbnQoYi5zdHJpcCgpLDE2KSBmb3IgbGluZSBpbiBwYXRobGliLlBhdGgoJy9wcm9jL3NlbGYvc3RhdHVzJykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpIGlmICc6JyBpbiBsaW5lCiAgICAgIGZvciBhLGIgaW4gW2xpbmUuc3BsaXQoJzonLDEpXSBpZiBhIGluICgnQ2FwRWZmJywnQ2FwUHJtJywnQ2FwSW5oJywnQ2FwQW1iJyl9CmRlZiBkcm9wX2NhcHMoKToKICAgIGNsYXNzIEhlYWRlcihjdHlwZXMuU3RydWN0dXJlKTpfZmllbGRzXz1bKCd2ZXJzaW9uJyxjdHlwZXMuY191aW50MzIpLCgncGlkJyxjdHlwZXMuY19pbnQpXQogICAgY2xhc3MgRGF0YShjdHlwZXMuU3RydWN0dXJlKTpfZmllbGRzXz1bKCdlZmZlY3RpdmUnLGN0eXBlcy5jX3VpbnQzMiksKCdwZXJtaXR0ZWQnLGN0eXBlcy5jX3VpbnQzMiksKCdpbmhlcml0YWJsZScsY3R5cGVzLmNfdWludDMyKV0KICAgIGxpYmM9Y3R5cGVzLkNETEwoTm9uZSx1c2VfZXJybm89VHJ1ZSkKICAgIHJlcXVpcmUobGliYy5wcmN0bCg0Nyw0LDAsMCwwKT09MCwnQ2Fubm90IGNsZWFyIGFtYmllbnQgY2FwYWJpbGl0aWVzJykKICAgIHJlcXVpcmUobGliYy5jYXBzZXQoY3R5cGVzLmJ5cmVmKEhlYWRlcigweDIwMDgwNTIyLDApKSxjdHlwZXMuYnlyZWYoKERhdGEqMikoKSkpPT0wLCdDYW5ub3QgY2xlYXIgcmVsYXkgY2FwYWJpbGl0aWVzJykKICAgIHJlcXVpcmUobm90IGFueShjYXBzKCkudmFsdWVzKCkpLCdSZWxheSBjYXBhYmlsaXR5IGRyb3AgZmFpbGVkJykKZGVmIGlkZW50aXR5KCk6CiAgICByZXF1aXJlKG9zLmdldGV1aWQoKSE9MCBhbmQgcHdkLmdldHB3dWlkKG9zLmdldGV1aWQoKSkucHdfbmFtZT09J2p3aycsJ011c3QgcnVuIGFzIGp3aycpCiAgICByZXF1aXJlKEJBU0UucmVzb2x2ZSgpPT1CQVNFIGFuZCBCQVNFLnN0YXQoKS5zdF91aWQ9PW9zLmdldGV1aWQoKSwnVW5leHBlY3RlZCBwcml2YXRlIGRlcGxveW1lbnQgcGF0aCcpO29zLnVtYXNrKDBvMDc3KQpkZWYgcGVlcl9pc19qd2sod3JpdGVyKToKICAgIHZhbHVlPXdyaXRlci5nZXRfZXh0cmFfaW5mbygnc29ja2V0JykuZ2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCxzb2NrZXQuU09fUEVFUkNSRUQsMTIpCiAgICByZXR1cm4gc3RydWN0LnVucGFjaygnM2knLHZhbHVlKVsxXT09b3MuZ2V0ZXVpZCgpCmRlZiBwcmVwYXJlX3NvY2tldChwYXRoKToKICAgIGlmIG5vdCBwYXRoLmV4aXN0cygpIGFuZCBub3QgcGF0aC5pc19zeW1saW5rKCk6cmV0dXJuCiAgICByZXF1aXJlKG5vdCBwYXRoLmlzX3N5bWxpbmsoKSBhbmQgcGF0aC5pc19zb2NrZXQoKSBhbmQgcGF0aC5zdGF0KCkuc3RfdWlkPT1vcy5nZXRldWlkKCksJ1VuZXhwZWN0ZWQgSVBDIG9iamVjdCBwcmVzZXJ2ZWQnKQogICAgc2lnbmF0dXJlPShwYXRoLnN0YXQoKS5zdF9kZXYscGF0aC5zdGF0KCkuc3RfaW5vKQogICAgd2l0aCBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9VTklYLHNvY2tldC5TT0NLX1NUUkVBTSkgYXMgcHJvYmU6CiAgICAgICAgcHJvYmUuc2V0dGltZW91dCgxKQogICAgICAgIHRyeTpwcm9iZS5jb25uZWN0KHN0cihwYXRoKSkKICAgICAgICBleGNlcHQgQ29ubmVjdGlvblJlZnVzZWRFcnJvcjoKICAgICAgICAgICAgcmVxdWlyZSgocGF0aC5zdGF0KCkuc3RfZGV2LHBhdGguc3RhdCgpLnN0X2lubyk9PXNpZ25hdHVyZSwnSVBDIG9iamVjdCBjaGFuZ2VkIGR1cmluZyBjaGVjaycpO3BhdGgudW5saW5rKCkKICAgICAgICBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcignRXhpc3RpbmcgbGl2ZSBJUEMgZW5kcG9pbnQgcHJlc2VydmVkJykKYXN5bmMgZGVmIHJlbGF5KHJlYWRlcix3cml0ZXIsb3RoZXJfcmVhZGVyLG90aGVyX3dyaXRlcik6CiAgICBhc3luYyBkZWYgcHVtcChzb3VyY2UsZGVzdCk6CiAgICAgICAgd2hpbGUgZGF0YTo9YXdhaXQgc291cmNlLnJlYWQoNjU1MzYpOmRlc3Qud3JpdGUoZGF0YSk7YXdhaXQgZGVzdC5kcmFpbigpCiAgICAgICAgaWYgZGVzdC5jYW5fd3JpdGVfZW9mKCk6ZGVzdC53cml0ZV9lb2YoKQogICAgdHJ5OmF3YWl0IGFzeW5jaW8ud2FpdF9mb3IoYXN5bmNpby5nYXRoZXIocHVtcChyZWFkZXIsb3RoZXJfd3JpdGVyKSxwdW1wKG90aGVyX3JlYWRlcix3cml0ZXIpKSw3MjAwKQogICAgZXhjZXB0IChPU0Vycm9yLENvbm5lY3Rpb25FcnJvcixhc3luY2lvLlRpbWVvdXRFcnJvcik6cGFzcwogICAgZmluYWxseTp3cml0ZXIuY2xvc2UoKTtvdGhlcl93cml0ZXIuY2xvc2UoKQphc3luYyBkZWYgZW5kcG9pbnQobW9kZSk6CiAgICBpZGVudGl0eSgpO3JlcXVpcmUobm90IGFueShjYXBzKCkudmFsdWVzKCkpLCdSZWxheXMgbXVzdCBiZSB1bnByaXZpbGVnZWQnKQogICAgcHJveHk9anNvbi5sb2FkcygoQkFTRS8nY29uZmlnL2VncmVzcy1wcm94eS5qc29uJykucmVhZF90ZXh0KCkpCiAgICBhc3luYyBkZWYgYWNjZXB0KHJlYWRlcix3cml0ZXIpOgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgbW9kZSBpbiAoJ2FwaS1pbnNpZGUnLCdlZ3Jlc3MtaG9zdCcpOnJlcXVpcmUocGVlcl9pc19qd2sod3JpdGVyKSwnVW5leHBlY3RlZCBVTklYIHBlZXInKQogICAgICAgICAgICBpZiBtb2RlPT0nYXBpLWhvc3QnOm90aGVyX3JlYWRlcixvdGhlcl93cml0ZXI9YXdhaXQgYXN5bmNpby5vcGVuX3VuaXhfY29ubmVjdGlvbihzdHIoSVBDLydhcGkuc29jaycpKQogICAgICAgICAgICBlbGlmIG1vZGU9PSdhcGktaW5zaWRlJzpvdGhlcl9yZWFkZXIsb3RoZXJfd3JpdGVyPWF3YWl0IGFzeW5jaW8ub3Blbl9jb25uZWN0aW9uKCcxMjcuMC4wLjEnLDE4MDgwKQogICAgICAgICAgICBlbGlmIG1vZGU9PSdlZ3Jlc3MtaW5zaWRlJzpvdGhlcl9yZWFkZXIsb3RoZXJfd3JpdGVyPWF3YWl0IGFzeW5jaW8ub3Blbl91bml4X2Nvbm5lY3Rpb24oc3RyKElQQy8nZWdyZXNzLnNvY2snKSkKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGhlYWRlcj1hd2FpdCBhc3luY2lvLndhaXRfZm9yKHJlYWRlci5yZWFkdW50aWwoYidcclxuXHJcbicpLDMwKTtyZXF1aXJlKGxlbihoZWFkZXIpPDY1NTM2LCdPdmVyc2l6ZWQgcHJveHkgcmVxdWVzdCcpCiAgICAgICAgICAgICAgICBtZXRob2QsdGFyZ2V0LHZlcnNpb249aGVhZGVyLnNwbGl0KGInXHJcbicsMSlbMF0uZGVjb2RlKCdhc2NpaScpLnNwbGl0KCcgJywyKQogICAgICAgICAgICAgICAgcGFyc2VkPXVybHNwbGl0KCcvLycrdGFyZ2V0IGlmIG1ldGhvZD09J0NPTk5FQ1QnIGVsc2UgdGFyZ2V0KTtob3N0PXBhcnNlZC5ob3N0bmFtZSBvciAnJztwb3J0PXBhcnNlZC5wb3J0IG9yICg0NDMgaWYgbWV0aG9kPT0nQ09OTkVDVCcgZWxzZSA4MCkKICAgICAgICAgICAgICAgIHJlcXVpcmUoYW55KGhvc3Q9PXMgb3IgaG9zdC5lbmRzd2l0aCgnLicrcykgZm9yIHMgaW4gQUxMT1dFRCkgYW5kIHBvcnQgaW4gKDgwLDQ0MyksJ0Rlc3RpbmF0aW9uIG91dHNpZGUgcmVnaXN0cnkgYWxsb3dsaXN0JykKICAgICAgICAgICAgICAgIHVwc3RyZWFtPXByb3h5LmdldCgnaHR0cHMnIGlmIG1ldGhvZD09J0NPTk5FQ1QnIGVsc2UgJ2h0dHAnKQogICAgICAgICAgICAgICAgaWYgdXBzdHJlYW06CiAgICAgICAgICAgICAgICAgICAgcmVtb3RlPXVybHNwbGl0KHVwc3RyZWFtKTtyZXF1aXJlKHJlbW90ZS5zY2hlbWUgaW4gKCdodHRwJywnaHR0cHMnKSBhbmQgcmVtb3RlLmhvc3RuYW1lLCdVbnN1cHBvcnRlZCB1cHN0cmVhbSBwcm94eScpCiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZShyZW1vdGUudXNlcm5hbWUgaXMgTm9uZSBhbmQgcmVtb3RlLnBhc3N3b3JkIGlzIE5vbmUsJ0F1dGhlbnRpY2F0ZWQgdXBzdHJlYW0gcHJveHkgcmVxdWlyZXMgYSBzZXBhcmF0ZSBqd2sgY3JlZGVudGlhbCcpCiAgICAgICAgICAgICAgICAgICAgY29udGV4dD1zc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWZpbGU9cHJveHlbJ2NhJ10pIGlmIHJlbW90ZS5zY2hlbWU9PSdodHRwcycgZWxzZSBOb25lCiAgICAgICAgICAgICAgICAgICAgb3RoZXJfcmVhZGVyLG90aGVyX3dyaXRlcj1hd2FpdCBhc3luY2lvLndhaXRfZm9yKGFzeW5jaW8ub3Blbl9jb25uZWN0aW9uKHJlbW90ZS5ob3N0bmFtZSxyZW1vdGUucG9ydCBvciAoNDQzIGlmIGNvbnRleHQgZWxzZSA4MCksc3NsPWNvbnRleHQpLDMwKQogICAgICAgICAgICAgICAgICAgIG90aGVyX3dyaXRlci53cml0ZShoZWFkZXIpO2F3YWl0IG90aGVyX3dyaXRlci5kcmFpbigpCiAgICAgICAgICAgICAgICAgICAgaWYgbWV0aG9kPT0nQ09OTkVDVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3BvbnNlPWF3YWl0IGFzeW5jaW8ud2FpdF9mb3Iob3RoZXJfcmVhZGVyLnJlYWR1bnRpbChiJ1xyXG5cclxuJyksMzApCiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUocmVzcG9uc2Uuc3BsaXQoYidcclxuJywxKVswXS5zcGxpdCgpWzFdPT1iJzIwMCcsJ1Vwc3RyZWFtIHByb3h5IHJlamVjdGVkIHR1bm5lbCcpCiAgICAgICAgICAgICAgICAgICAgICAgIHdyaXRlci53cml0ZShiJ0hUVFAvMS4xIDIwMCBDb25uZWN0aW9uIEVzdGFibGlzaGVkXHJcblxyXG4nKTthd2FpdCB3cml0ZXIuZHJhaW4oKQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBvdGhlcl9yZWFkZXIsb3RoZXJfd3JpdGVyPWF3YWl0IGFzeW5jaW8ud2FpdF9mb3IoYXN5bmNpby5vcGVuX2Nvbm5lY3Rpb24oaG9zdCxwb3J0KSwzMCkKICAgICAgICAgICAgICAgICAgICBpZiBtZXRob2Q9PSdDT05ORUNUJzp3cml0ZXIud3JpdGUoYidIVFRQLzEuMSAyMDAgQ29ubmVjdGlvbiBFc3RhYmxpc2hlZFxyXG5cclxuJyk7YXdhaXQgd3JpdGVyLmRyYWluKCkKICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKHBhcnNlZC5zY2hlbWU9PSdodHRwJywnRXhwZWN0ZWQgSFRUUCBVUkwnKQogICAgICAgICAgICAgICAgICAgICAgICBwYXRoPShwYXJzZWQucGF0aCBvciAnLycpKygnPycgKyBwYXJzZWQucXVlcnkgaWYgcGFyc2VkLnF1ZXJ5IGVsc2UgJycpCiAgICAgICAgICAgICAgICAgICAgICAgIG90aGVyX3dyaXRlci53cml0ZSgobWV0aG9kKycgJytwYXRoKycgJyt2ZXJzaW9uKS5lbmNvZGUoKStiJ1xyXG4nK2hlYWRlci5zcGxpdChiJ1xyXG4nLDEpWzFdKTthd2FpdCBvdGhlcl93cml0ZXIuZHJhaW4oKQogICAgICAgICAgICBhd2FpdCByZWxheShyZWFkZXIsd3JpdGVyLG90aGVyX3JlYWRlcixvdGhlcl93cml0ZXIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlcnJvcjoKICAgICAgICAgICAgcHJpbnQoanNvbi5kdW1wcyh7J21vZGUnOm1vZGUsJ2Vycm9yJzp0eXBlKGVycm9yKS5fX25hbWVfXywnZGV0YWlsJzpzdHIoZXJyb3IpWzoyMDBdfSksZmx1c2g9VHJ1ZSk7d3JpdGVyLmNsb3NlKCkKICAgIGlmIG1vZGUgaW4gKCdhcGktaW5zaWRlJywnZWdyZXNzLWhvc3QnKToKICAgICAgICBwYXRoPUlQQy8oJ2FwaS5zb2NrJyBpZiBtb2RlPT0nYXBpLWluc2lkZScgZWxzZSAnZWdyZXNzLnNvY2snKTtwcmVwYXJlX3NvY2tldChwYXRoKQogICAgICAgIHNlcnZlcj1hd2FpdCBhc3luY2lvLnN0YXJ0X3VuaXhfc2VydmVyKGFjY2VwdCxzdHIocGF0aCkpO3BhdGguY2htb2QoMG82MDApCiAgICBlbHNlOnNlcnZlcj1hd2FpdCBhc3luY2lvLnN0YXJ0X3NlcnZlcihhY2NlcHQsJzEyNy4wLjAuMScsMTgwODAgaWYgbW9kZT09J2FwaS1ob3N0JyBlbHNlIDE4MDg5LHJldXNlX2FkZHJlc3M9RmFsc2UpCiAgICAoSVBDLyhtb2RlKycuanNvbicpKS53cml0ZV90ZXh0KGpzb24uZHVtcHMoeydwaWQnOm9zLmdldHBpZCgpLCd1aWQnOm9zLmdldGV1aWQoKSwnbmV0bnMnOm9zLnN0YXQoJy9wcm9jL3NlbGYvbnMvbmV0Jykuc3RfaW5vLCdjYXBzJzpjYXBzKCl9KSsnXG4nKQogICAgYXN5bmMgd2l0aCBzZXJ2ZXI6YXdhaXQgc2VydmVyLnNlcnZlX2ZvcmV2ZXIoKQphc3luYyBkZWYgYmVuY2htYXJrKCk6CiAgICBpZGVudGl0eSgpO3JlcXVpcmUobm90IGFueShjYXBzKCkudmFsdWVzKCkpLCdCZW5jaG1hcmsgcnVubmVyIG11c3QgaGF2ZSBubyBjYXBhYmlsaXRpZXMnKQogICAgbG9jaz1hc3luY2lvLkxvY2soKTtwYXRoPUlQQy8nYmVuY2htYXJrLnNvY2snO3ByZXBhcmVfc29ja2V0KHBhdGgpCiAgICBhc3luYyBkZWYgYWNjZXB0KHJlYWRlcix3cml0ZXIpOgogICAgICAgIGRpc2Nvbm5lY3RlZD1GYWxzZQogICAgICAgIGFzeW5jIGRlZiBzZW5kKGRhdGEpOgogICAgICAgICAgICBub25sb2NhbCBkaXNjb25uZWN0ZWQKICAgICAgICAgICAgaWYgZGlzY29ubmVjdGVkOnJldHVybgogICAgICAgICAgICB0cnk6d3JpdGVyLndyaXRlKGRhdGEpO2F3YWl0IHdyaXRlci5kcmFpbigpCiAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvcixDb25uZWN0aW9uRXJyb3IpOmRpc2Nvbm5lY3RlZD1UcnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICByZXF1aXJlKHBlZXJfaXNfandrKHdyaXRlciksJ1VuZXhwZWN0ZWQgYmVuY2htYXJrIHBlZXInKQogICAgICAgICAgICByYXc9YXdhaXQgYXN5bmNpby53YWl0X2ZvcihyZWFkZXIucmVhZGxpbmUoKSwxMCk7cmVxdWlyZShsZW4ocmF3KTw0MDk2LCdPdmVyc2l6ZWQgYmVuY2htYXJrIHJlcXVlc3QnKQogICAgICAgICAgICByZXF1ZXN0PWpzb24ubG9hZHMocmF3KTtyb3VuZHM9cmVxdWVzdC5nZXQoJ3JvdW5kcycsNSkKICAgICAgICAgICAgcmVxdWlyZSh0eXBlKHJvdW5kcykgaXMgaW50IGFuZCAxPD1yb3VuZHM8PTEwLCdSb3VuZHMgbXVzdCBiZTEuLjEwJyk7cmVxdWlyZShub3QgbG9jay5sb2NrZWQoKSwnQSBiZW5jaG1hcmsgaXMgYWxyZWFkeSBydW5uaW5nJykKICAgICAgICAgICAgaW1hZ2VfbWFwPUJBU0UvJ2NvbmZpZy9iZW5jaF9pbWFnZV9tYXAuanNvbic7cmVxdWlyZShpbWFnZV9tYXAuaXNfZmlsZSgpLCdOYXRpdmUgV2lraWRhdGE3MTcgdGVtcGxhdGUgaXMgbm90IHByb3Zpc2lvbmVkIHlldCcpCiAgICAgICAgICAgIGFzeW5jIHdpdGggbG9jazoKICAgICAgICAgICAgICAgIHJlc3VsdD1CQVNFLydyZXN1bHRzJy8oJ2xpZmVjeWNsZS0nK3RpbWUuc3RyZnRpbWUoJyVZJW0lZC0lSCVNJVMnKSsnLScrb3MudXJhbmRvbSgzKS5oZXgoKSk7cmVzdWx0Lm1rZGlyKHBhcmVudHM9VHJ1ZSxtb2RlPTBvNzAwKQogICAgICAgICAgICAgICAgZW52aXJvbm1lbnQ9ZGljdChvcy5lbnZpcm9uKQogICAgICAgICAgICAgICAgZm9yIG5hbWUgaW4gKCdodHRwX3Byb3h5JywnaHR0cHNfcHJveHknLCdhbGxfcHJveHknLCdmdHBfcHJveHknLCdIVFRQX1BST1hZJywnSFRUUFNfUFJPWFknLCdBTExfUFJPWFknLCdGVFBfUFJPWFknLCdQWVRIT05QQVRIJywnUFlUSE9OSE9NRScpOmVudmlyb25tZW50LnBvcChuYW1lLE5vbmUpCiAgICAgICAgICAgICAgICBlbnZpcm9ubWVudC51cGRhdGUoRTJCX0FQSV9LRVk9KEJBU0UvJ2NvbmZpZy9hcGkta2V5JykucmVhZF90ZXh0KCkuc3RyaXAoKSxFMkJfQUNDRVNTX1RPS0VOPSdkdW1teScsCiAgICAgICAgICAgICAgICAgIE5PX1BST1hZPSdsb2NhbGhvc3QsMTI3LjAuMC4xJyxub19wcm94eT0nbG9jYWxob3N0LDEyNy4wLjAuMScsUFlUSE9OTk9VU0VSU0lURT0nMScsUFlUSE9OVU5CVUZGRVJFRD0nMScpCiAgICAgICAgICAgICAgICBwcm9vZj17J3VpZCc6b3MuZ2V0ZXVpZCgpLCdjYXBzJzpjYXBzKCksJ25ldG5zJzpvcy5zdGF0KCcvcHJvYy9zZWxmL25zL25ldCcpLnN0X2lubywnYXBpJzonZGlyZWN0IFJ1c3QgMTI3LjAuMC4xOjE4MDgwJywncm91bmRzJzpyb3VuZHN9CiAgICAgICAgICAgICAgICAocmVzdWx0Lyd0cmFuc3BvcnQuanNvbicpLndyaXRlX3RleHQoanNvbi5kdW1wcyhwcm9vZikrJ1xuJykKICAgICAgICAgICAgICAgIGF3YWl0IHNlbmQoKCdSRVNVTFRfRElSPScrc3RyKHJlc3VsdCkrJ1xuJykuZW5jb2RlKCkpCiAgICAgICAgICAgICAgICBmb3IgbGFiZWwsY291bnQgaW4gWygncHJld2FybTEwMCcsMSksKCdmb3JtYWwnLHJvdW5kcyldOgogICAgICAgICAgICAgICAgICAgIGFyZ3M9W3N0cihCQVNFLydzZGsvZzQtZTJiMjQ2L2Jpbi9weXRob24nKSwnLUInLHN0cihCQVNFLydnNC1iZW5jaG1hcmtfc2FuZGJveF9saWZlY3ljbGUucHknKSwKICAgICAgICAgICAgICAgICAgICAgICctLWFwaS11cmwnLCdodHRwOi8vMTI3LjAuMC4xOjE4MDgwJywnLS10b3RhbCcsJzEwMCcsJy0tYmF0Y2gtc2l6ZScsJzEwMCcsJy0tcm91bmRzJyxzdHIoY291bnQpLAogICAgICAgICAgICAgICAgICAgICAgJy0taW1hZ2UtbWFwJyxzdHIoaW1hZ2VfbWFwKSwnLS1vdXRwdXQtZGlyJyxzdHIocmVzdWx0L2xhYmVsKV0KICAgICAgICAgICAgICAgICAgICBwcm9jZXNzPWF3YWl0IGFzeW5jaW8uY3JlYXRlX3N1YnByb2Nlc3NfZXhlYygqYXJncyxlbnY9ZW52aXJvbm1lbnQsc3RkaW49YXN5bmNpby5zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9YXN5bmNpby5zdWJwcm9jZXNzLlBJUEUsc3RkZXJyPWFzeW5jaW8uc3VicHJvY2Vzcy5TVERPVVQpCiAgICAgICAgICAgICAgICAgICAgd2l0aCAocmVzdWx0LyhsYWJlbCsnLmxvZycpKS5vcGVuKCd4YicpIGFzIGxvZzoKICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgZGF0YTo9YXdhaXQgcHJvY2Vzcy5zdGRvdXQucmVhZGxpbmUoKTpsb2cud3JpdGUoZGF0YSk7bG9nLmZsdXNoKCk7YXdhaXQgc2VuZChkYXRhKQogICAgICAgICAgICAgICAgICAgIGNvZGU9YXdhaXQgcHJvY2Vzcy53YWl0KCk7cmVxdWlyZShjb2RlPT0wLGxhYmVsKycgYmVuY2htYXJrIGZhaWxlZCwgZXhpdD0nK3N0cihjb2RlKSkKICAgICAgICAgICAgICAgIGF3YWl0IHNlbmQoYidCRU5DSE1BUktfRVhJVD0wXG4nKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXJyb3I6CiAgICAgICAgICAgIGF3YWl0IHNlbmQoKCdCRU5DSE1BUktfRVJST1I9JytzdHIoZXJyb3IpKydcbicpLmVuY29kZSgpKQogICAgICAgIGZpbmFsbHk6d3JpdGVyLmNsb3NlKCkKICAgIHNlcnZlcj1hd2FpdCBhc3luY2lvLnN0YXJ0X3VuaXhfc2VydmVyKGFjY2VwdCxzdHIocGF0aCkpO3BhdGguY2htb2QoMG82MDApCiAgICBhc3luYyB3aXRoIHNlcnZlcjphd2FpdCBzZXJ2ZXIuc2VydmVfZm9yZXZlcigpCmRlZiBzdGFydF9jaGlsZChtb2RlLGVudj1Ob25lLGRyb3A9RmFsc2UpOgogICAgbG9nPShCQVNFLydsb2dzJy8obW9kZSsnLmxvZycpKS5vcGVuKCdhYicsYnVmZmVyaW5nPTApCiAgICBjaGlsZD1zdWJwcm9jZXNzLlBvcGVuKFsnL3Vzci9iaW4vcHl0aG9uMycsJy1JJywnLUInLF9fZmlsZV9fLG1vZGVdLGVudj1lbnYsc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLHN0ZG91dD1sb2csc3RkZXJyPWxvZyxwcmVleGVjX2ZuPWRyb3BfY2FwcyBpZiBkcm9wIGVsc2UgTm9uZSkKICAgIHRpbWUuc2xlZXAoLjI1KTtyZXF1aXJlKGNoaWxkLnBvbGwoKSBpcyBOb25lLCdSdW50aW1lIGhlbHBlciBmYWlsZWQ6ICcrbW9kZSk7cmV0dXJuIGNoaWxkCmRlZiBpbnNpZGUoKToKICAgIGlkZW50aXR5KCk7Y29udGV4dD1qc29uLmxvYWRzKChCQVNFLydjb25maWcvaG9zdC1jb250ZXh0MDA4Lmpzb24nKS5yZWFkX3RleHQoKSkKICAgIHJlcXVpcmUocGF0aGxpYi5QYXRoKCcvcHJvYy9zeXMva2VybmVsL3JhbmRvbS9ib290X2lkJykucmVhZF90ZXh0KCkuc3RyaXAoKT09Y29udGV4dFsnYm9vdF9pZCddLCdCb290IGRpZmZlcnMnKQogICAgcmVxdWlyZShvcy5zdGF0KCcvcHJvYy9zZWxmL25zL25ldCcpLnN0X2lubyE9Y29udGV4dFsnbmV0bnMnXSBhbmQgb3Muc3RhdCgnL3Byb2Mvc2VsZi9ucy9tbnQnKS5zdF9pbm8hPWNvbnRleHRbJ21udG5zJ10sJ1JlZnVzZSBob3N0IG5hbWVzcGFjZSBleGVjdXRpb24nKQogICAgcmVxdWlyZShhbGwodj09Q0FQUyBmb3IgdiBpbiBjYXBzKCkudmFsdWVzKCkpLCdVbmV4cGVjdGVkIHJ1bnRpbWUgY2FwYWJpbGl0eSBzZXQnKQogICAgZm9yIGRldmljZSBpbiAoJy9kZXYva3ZtJywnL2Rldi91YmxrLWNvbnRyb2wnLCcvZGV2L25ldC90dW4nKToKICAgICAgICBmZD1vcy5vcGVuKGRldmljZSxvcy5PX1JEV1J8b3MuT19DTE9FWEVDKTtvcy5jbG9zZShmZCkKICAgIHN1YnByb2Nlc3MucnVuKFtzaHV0aWwud2hpY2goJ2lwJyksJ2xpbmsnLCdzZXQnLCdkZXYnLCdsbycsJ3VwJ10sY2hlY2s9VHJ1ZSkKICAgIHBhdGhsaWIuUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS53cml0ZV90ZXh0KCcxXG4nKQogICAgY2E9anNvbi5sb2FkcygoQkFTRS8nY29uZmlnL2VncmVzcy1wcm94eS5qc29uJykucmVhZF90ZXh0KCkpWydjYSddCiAgICBlbnZpcm9ubWVudD17J0hPTUUnOnB3ZC5nZXRwd3VpZChvcy5nZXRldWlkKCkpLnB3X2RpciwnVVNFUic6J2p3aycsJ0xPR05BTUUnOidqd2snLCdMQU5HJzonQy5VVEYtOCcsCiAgICAgICdQQVRIJzpzdHIoQkFTRS8nYmluJykrJzovdXNyL2xvY2FsL2JpbjovdXNyL2xvY2FsL3NiaW46L3Vzci9iaW46L3Vzci9zYmluOi9iaW46L3NiaW4nLCdUTVBESVInOnN0cihCQVNFLyd0bXAnKSwKICAgICAgJ1hER19DQUNIRV9IT01FJzpzdHIoQkFTRS8nY2FjaGUnKSwnRE9DS0VSX0NPTkZJRyc6c3RyKEJBU0UvJ2NvbmZpZy9kb2NrZXInKSwnU1NMX0NFUlRfRklMRSc6Y2EsJ0NVUkxfQ0FfQlVORExFJzpjYSwKICAgICAgJ0FFTlZfSE9NRV9QQVRIJzpzdHIoQkFTRS8nc3RhdGUnKSwnQUVOVl9SVU5USU1FX1BBVEgnOnN0cihJUEMpLCdBRU5WX0RFUFNfUEFUSCc6c3RyKEJBU0UvJ3J1bnRpbWUtYXNzZXRzJyksCiAgICAgICdBUElfQUREUic6JzEyNy4wLjAuMToxODA4MCcsJ0FFTlZfTE9HX0ZPUk1BVCc6J2NvbXBhY3QnLCdSVVNUX0xPRyc6J2FnZW50ZW52PXdhcm4nLAogICAgICAnSFRUUF9QUk9YWSc6J2h0dHA6Ly8xMjcuMC4wLjE6MTgwODknLCdIVFRQU19QUk9YWSc6J2h0dHA6Ly8xMjcuMC4wLjE6MTgwODknLAogICAgICAnaHR0cF9wcm94eSc6J2h0dHA6Ly8xMjcuMC4wLjE6MTgwODknLCdodHRwc19wcm94eSc6J2h0dHA6Ly8xMjcuMC4wLjE6MTgwODknLAogICAgICAnTk9fUFJPWFknOidsb2NhbGhvc3QsMTI3LjAuMC4xLDEwLjExLjAuMC8xNiwxMC4xMi4wLjAvMTYsMTY5LjI1NC4wLjAvMTYnLAogICAgICAnbm9fcHJveHknOidsb2NhbGhvc3QsMTI3LjAuMC4xLDEwLjExLjAuMC8xNiwxMC4xMi4wLjAvMTYsMTY5LjI1NC4wLjAvMTYnfQogICAgZm9yIG1vZGUgaW4gKCdhcGktaW5zaWRlJywnZWdyZXNzLWluc2lkZScsJ2JlbmNobWFyaycpOnN0YXJ0X2NoaWxkKG1vZGUsZW52aXJvbm1lbnQsZHJvcD1UcnVlKQogICAgZW52aXJvbm1lbnRbJ0FFTlZfQVBJX0tFWSddPShCQVNFLydjb25maWcvYXBpLWtleScpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIChJUEMvJ3J1bnRpbWUtYXR0ZXN0YXRpb24wMDguanNvbicpLndyaXRlX3RleHQoanNvbi5kdW1wcyh7J3BpZCc6b3MuZ2V0cGlkKCksJ3VpZCc6b3MuZ2V0ZXVpZCgpLCduZXRucyc6b3Muc3RhdCgnL3Byb2Mvc2VsZi9ucy9uZXQnKS5zdF9pbm8sCiAgICAgICdtbnRucyc6b3Muc3RhdCgnL3Byb2Mvc2VsZi9ucy9tbnQnKS5zdF9pbm8sJ2NhcHMnOmNhcHMoKSwnYm9vdF9pZCc6Y29udGV4dFsnYm9vdF9pZCddfSkrJ1xuJykKICAgIGZkPW9zLm9wZW4oQkFTRS8nbG9ncy9zZXJ2ZXIubG9nJyxvcy5PX1dST05MWXxvcy5PX0NSRUFUfG9zLk9fQVBQRU5ELDBvNjAwKTtvcy5kdXAyKGZkLDEpO29zLmR1cDIoZmQsMik7b3MuY2xvc2UoZmQpCiAgICBvcy5jaGRpcihCQVNFKTtiaW5hcnk9QkFTRS8nYmluL3NlcnZlcic7b3MuZXhlY3ZlKGJpbmFyeSxbc3RyKGJpbmFyeSksJy0tY29uZmlnJyxzdHIoQkFTRS8nY29uZmlnL3J1bnRpbWUwMDUudG9tbCcpXSxlbnZpcm9ubWVudCkKaWYgX19uYW1lX189PSdfX21haW5fXyc6CiAgICBtb2RlPXN5cy5hcmd2WzFdCiAgICBpZiBtb2RlPT0naW5zaWRlJzppbnNpZGUoKQogICAgZWxpZiBtb2RlPT0naG9zdCc6CiAgICAgICAgaWRlbnRpdHkoKTtjaGlsZHJlbj1bc3RhcnRfY2hpbGQobmFtZSkgZm9yIG5hbWUgaW4gKCdhcGktaG9zdCcsJ2VncmVzcy1ob3N0JyldCiAgICAgICAgd2hpbGUgYWxsKHAucG9sbCgpIGlzIE5vbmUgZm9yIHAgaW4gY2hpbGRyZW4pOnRpbWUuc2xlZXAoMSkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCdIb3N0IHJlbGF5IGV4aXRlZCcpCiAgICBlbGlmIG1vZGU9PSdiZW5jaG1hcmsnOmFzeW5jaW8ucnVuKGJlbmNobWFyaygpKQogICAgZWxpZiBtb2RlIGluICgnYXBpLWhvc3QnLCdhcGktaW5zaWRlJywnZWdyZXNzLWhvc3QnLCdlZ3Jlc3MtaW5zaWRlJyk6YXN5bmNpby5ydW4oZW5kcG9pbnQobW9kZSkpCiAgICBlbHNlOnJhaXNlIFN5c3RlbUV4aXQoJ1Vua25vd24gbW9kZScpCg==', 'sha256': '783e9d002bff48de55b3f9bc7b9ee9370aada8e4b5823ebf380eb3ae63ea8531'}, 'device_broker008.py': {'base64': 'IiIiR3JhbnQgb25seSBuZXdseSBjcmVhdGVkIHVibGsgZGV2aWNlIGlub2RlcyBwcm92ZW4gdG8gYmVsb25nIHRvIHRoaXMgdW5pdC4iIiIKaW1wb3J0IGN0eXBlcyxoYXNobGliLGpzb24sb3MscGF0aGxpYixyZSxzZWxlY3Qsc3RhdCxzdHJ1Y3Qsc3VicHJvY2Vzcyx0aW1lClJPT1Q9cGF0aGxpYi5QYXRoKCcvcnVuL2p3ay1hZW52LXktY2xlYW4tMjAyNjExMTEnKQpDT05GSUc9anNvbi5sb2FkcygoUk9PVC8nYnJva2VyLWNvbmZpZy5qc29uJykucmVhZF90ZXh0KCkpClVJRD1DT05GSUdbJ3VpZCddO0NHUk9VUD0nL3N5c3RlbS5zbGljZS8nK0NPTkZJR1sndW5pdCddO0RBRU1PTl9TSEE9Q09ORklHWydkYWVtb25fc2hhMjU2J10KVkVSSUZJRUQ9e30KZGVmIHNpZ25hdHVyZShzdCk6cmV0dXJuIChzdC5zdF9kZXYsc3Quc3RfaW5vLHN0LnN0X3JkZXYpCmRlZiBwcm9jZXNzKHBpZCk6CiAgICBwYXRoPXBhdGhsaWIuUGF0aCgnL3Byb2MnLHN0cihwaWQpKTtzdGF0dXM9e2E6Yi5zdHJpcCgpIGZvciBsaW5lIGluIChwYXRoLydzdGF0dXMnKS5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCkgaWYgJzonIGluIGxpbmUgZm9yIGEsYiBpbiBbbGluZS5zcGxpdCgnOicsMSldfQogICAgYXNzZXJ0IFtpbnQodikgZm9yIHYgaW4gc3RhdHVzWydVaWQnXS5zcGxpdCgpXT09W1VJRF0qNAogICAgZ3JvdXBzPVt4LnNwbGl0KCc6JywyKVsyXSBmb3IgeCBpbiAocGF0aC8nY2dyb3VwJykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpXQogICAgYXNzZXJ0IGFueSh4PT1DR1JPVVAgb3IgeC5zdGFydHN3aXRoKENHUk9VUCsnLycpIGZvciB4IGluIGdyb3VwcykKICAgIHN0YXJ0PShwYXRoLydzdGF0JykucmVhZF90ZXh0KCkucnNwbGl0KCcpJywxKVsxXS5zcGxpdCgpWzE5XQogICAgZXhlY3V0YWJsZT1wYXRoLydleGUnO3N0PWV4ZWN1dGFibGUuc3RhdCgpO2tleT0ocGlkLHN0YXJ0LHN0LnN0X2RldixzdC5zdF9pbm8sc3Quc3Rfc2l6ZSxzdC5zdF9tdGltZV9ucykKICAgIGlmIGtleSBub3QgaW4gVkVSSUZJRUQ6CiAgICAgICAgd2l0aCBleGVjdXRhYmxlLm9wZW4oJ3JiJykgYXMgZjphc3NlcnQgaGFzaGxpYi5maWxlX2RpZ2VzdChmLCdzaGEyNTYnKS5oZXhkaWdlc3QoKT09REFFTU9OX1NIQQogICAgICAgIFZFUklGSUVEW2tleV09VHJ1ZQogICAgcmV0dXJuIHN0YXJ0CmRlZiBncmFudChwYXRoLGV4Y2x1ZGVkKToKICAgIG1hdGNoPXJlLmZ1bGxtYXRjaChyJ3VibGsoW2NiXSkoXGQrKScscGF0aC5uYW1lKQogICAgaWYgbm90IG1hdGNoOnJldHVybiBGYWxzZQogICAgYmVmb3JlPXBhdGgubHN0YXQoKQogICAgaWYgc2lnbmF0dXJlKGJlZm9yZSkgaW4gZXhjbHVkZWQgb3IgYmVmb3JlLnN0X3VpZD09VUlEOnJldHVybiBGYWxzZQogICAgYXNzZXJ0IChzdGF0LlNfSVNDSFIoYmVmb3JlLnN0X21vZGUpIGlmIG1hdGNoWzFdPT0nYycgZWxzZSBzdGF0LlNfSVNCTEsoYmVmb3JlLnN0X21vZGUpKQogICAgZmQ9b3Mub3BlbihwYXRoLG9zLk9fUEFUSHxvcy5PX05PRk9MTE9XfG9zLk9fQ0xPRVhFQykKICAgIHRyeToKICAgICAgICBoZWxkPW9zLmZzdGF0KGZkKTthc3NlcnQgc2lnbmF0dXJlKGhlbGQpPT1zaWduYXR1cmUoYmVmb3JlKQogICAgICAgIHF1ZXJ5PXN1YnByb2Nlc3MucnVuKFtzdHIoUk9PVC8nandrLXVibGstcXVlcnknKSxtYXRjaFsyXV0sZW52PXsnUEFUSCc6Jy91c3IvYmluOi9iaW4nfSxjYXB0dXJlX291dHB1dD1UcnVlLHRleHQ9VHJ1ZSx0aW1lb3V0PTMpCiAgICAgICAgaWYgcXVlcnkucmV0dXJuY29kZTpyZXR1cm4gRmFsc2UKICAgICAgICBpbmZvPWpzb24ubG9hZHMocXVlcnkuc3Rkb3V0KTtwaWQ9aW50KGluZm9bJ3BpZCddKTthc3NlcnQgcGlkPjAgYW5kIGluZm9bJ2lkJ109PWludChtYXRjaFsyXSkKICAgICAgICBzdGFydD1wcm9jZXNzKHBpZCk7YXNzZXJ0IHNpZ25hdHVyZShwYXRoLmxzdGF0KCkpPT1zaWduYXR1cmUoaGVsZCkKICAgICAgICBhc3NlcnQgcHJvY2VzcyhwaWQpPT1zdGFydAogICAgICAgICMgSG9sZCB0aGUgdmVyaWZpZWQgaW5vZGUsIHNvIGRldmljZSBJRCByZXVzZSBjYW5ub3QgcmVkaXJlY3QgY2hvd24uCiAgICAgICAgbGliYz1jdHlwZXMuQ0RMTChOb25lLHVzZV9lcnJubz1UcnVlKQogICAgICAgIHJlc3VsdD1saWJjLmZjaG93bmF0KGZkLGInJyxjdHlwZXMuY191aW50KFVJRCksY3R5cGVzLmNfdWludCgweGZmZmZmZmZmKSwweDEwMDApCiAgICAgICAgYXNzZXJ0IHJlc3VsdD09MCxjdHlwZXMuZ2V0X2Vycm5vKCkKICAgICAgICBwcmludChqc29uLmR1bXBzKHsnZ3JhbnRlZCc6cGF0aC5uYW1lLCd1aWQnOlVJRCwnZGFlbW9uUGlkJzpwaWR9KSxmbHVzaD1UcnVlKQogICAgICAgIHJldHVybiBUcnVlCiAgICBmaW5hbGx5Om9zLmNsb3NlKGZkKQpkZWYgbWFpbigpOgogICAgYXNzZXJ0IG9zLmdldHVpZCgpPT1vcy5nZXRldWlkKCk9PTAKICAgIGV4Y2x1ZGVkPXNldCh0dXBsZShyb3cpIGZvciByb3cgaW4gQ09ORklHWydleGNsdWRlZCddKQogICAgbGliYz1jdHlwZXMuQ0RMTChOb25lLHVzZV9lcnJubz1UcnVlKQogICAgZmQ9bGliYy5pbm90aWZ5X2luaXQxKG9zLk9fTk9OQkxPQ0t8b3MuT19DTE9FWEVDKTthc3NlcnQgZmQ+PTAKICAgIGFzc2VydCBsaWJjLmlub3RpZnlfYWRkX3dhdGNoKGZkLGInL2RldicsMHgxMDB8MHg4MHwweDR8MHgyMDApPj0wCiAgICAoUk9PVC8nYnJva2VyLXJlYWR5Lmpzb24nKS53cml0ZV90ZXh0KGpzb24uZHVtcHMoeydwaWQnOm9zLmdldHBpZCgpLCd1aWQnOjB9KSsnXG4nKQogICAgcGVuZGluZz17fQogICAgd2hpbGUgVHJ1ZToKICAgICAgICBpZiBzZWxlY3Quc2VsZWN0KFtmZF0sW10sW10sLjAyKVswXToKICAgICAgICAgICAgZGF0YT1vcy5yZWFkKGZkLDY1NTM2KTtvZmZzZXQ9MAogICAgICAgICAgICB3aGlsZSBvZmZzZXQrMTY8PWxlbihkYXRhKToKICAgICAgICAgICAgICAgIF8sbWFzayxfLHNpemU9c3RydWN0LnVucGFja19mcm9tKCdpSUlJJyxkYXRhLG9mZnNldCkKICAgICAgICAgICAgICAgIG5hbWU9ZGF0YVtvZmZzZXQrMTY6b2Zmc2V0KzE2K3NpemVdLnNwbGl0KGInXDAnLDEpWzBdLmRlY29kZShlcnJvcnM9J3JlcGxhY2UnKTtvZmZzZXQrPTE2K3NpemUKICAgICAgICAgICAgICAgIGlmIHJlLmZ1bGxtYXRjaChyJ3VibGtbY2JdXGQrJyxuYW1lKToKICAgICAgICAgICAgICAgICAgICBpZiBtYXNrJjB4MjAwOnBlbmRpbmcucG9wKG5hbWUsTm9uZSkKICAgICAgICAgICAgICAgICAgICBlbHNlOnBlbmRpbmdbbmFtZV09KHRpbWUubW9ub3RvbmljKCksdGltZS5tb25vdG9uaWMoKSszKQogICAgICAgIGZvciBuYW1lLChuZXh0X3RpbWUsZGVhZGxpbmUpIGluIGxpc3QocGVuZGluZy5pdGVtcygpKToKICAgICAgICAgICAgaWYgdGltZS5tb25vdG9uaWMoKTxuZXh0X3RpbWU6Y29udGludWUKICAgICAgICAgICAgaWYgdGltZS5tb25vdG9uaWMoKT5kZWFkbGluZTpwZW5kaW5nLnBvcChuYW1lLE5vbmUpO2NvbnRpbnVlCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBhdGg9cGF0aGxpYi5QYXRoKCcvZGV2JykvbmFtZQogICAgICAgICAgICAgICAgc3Q9cGF0aC5sc3RhdCgpO2tleT1zaWduYXR1cmUoc3QpCiAgICAgICAgICAgICAgICBpZiBrZXkgaW4gZXhjbHVkZWQgb3Igc3Quc3RfdWlkPT1VSUQgb3IgZ3JhbnQocGF0aCxleGNsdWRlZCk6cGVuZGluZy5wb3AobmFtZSxOb25lKTtjb250aW51ZQogICAgICAgICAgICBleGNlcHQgKEFzc2VydGlvbkVycm9yLE9TRXJyb3IsVmFsdWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICAgICAgcGVuZGluZ1tuYW1lXT0odGltZS5tb25vdG9uaWMoKSsuMDIsZGVhZGxpbmUpCmlmIF9fbmFtZV9fPT0nX19tYWluX18nOm1haW4oKQo=', 'sha256': '94a43849b4fc045776d33d0b9b59825a6d73ca69f480be2418923394a2be7ea1'}, 'benchmark_client008.py': {'base64': 'IiIiU3VibWl0IGEgYm91bmRlZCBiZW5jaG1hcmsgdG8gdGhlIGNhcGFiaWxpdHktZnJlZSBydW5uZXIgaW5zaWRlIHRoZSBuYW1lc3BhY2UuIiIiCmltcG9ydCBhcmdwYXJzZSxqc29uLHBhdGhsaWIsc29ja2V0LHN5cwpkZWYgbWFpbigpOgogICAgcGFyc2VyPWFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKCk7cGFyc2VyLmFkZF9hcmd1bWVudCgnLS1yb3VuZHMnLHR5cGU9aW50LGRlZmF1bHQ9NSk7YXJncz1wYXJzZXIucGFyc2VfYXJncygpCiAgICBpZiBub3QgMTw9YXJncy5yb3VuZHM8PTEwOnBhcnNlci5lcnJvcignLS1yb3VuZHMgbXVzdCBiZTEuLjEwJykKICAgIHBhdGg9Jy9ob21lL2p3ay9hZW52LXktY2xlYW4tMjAyNjExMTEvci9iZW5jaG1hcmsuc29jayc7c3VjY2Vzcz1GYWxzZQogICAgd2l0aCBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9VTklYLHNvY2tldC5TT0NLX1NUUkVBTSkgYXMgY2xpZW50OgogICAgICAgIGNsaWVudC5zZXR0aW1lb3V0KDcyMDApO2NsaWVudC5jb25uZWN0KHBhdGgpO2NsaWVudC5zZW5kYWxsKChqc29uLmR1bXBzKHsncm91bmRzJzphcmdzLnJvdW5kc30pKydcbicpLmVuY29kZSgpKQogICAgICAgIHdpdGggY2xpZW50Lm1ha2VmaWxlKCdyYicpIGFzIHN0cmVhbToKICAgICAgICAgICAgZm9yIGxpbmUgaW4gc3RyZWFtOgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC5idWZmZXIud3JpdGUobGluZSk7c3lzLnN0ZG91dC5idWZmZXIuZmx1c2goKQogICAgICAgICAgICAgICAgaWYgbGluZS5zdHJpcCgpPT1iJ0JFTkNITUFSS19FWElUPTAnOnN1Y2Nlc3M9VHJ1ZQogICAgcmV0dXJuIDAgaWYgc3VjY2VzcyBlbHNlIDEKaWYgX19uYW1lX189PSdfX21haW5fXyc6cmFpc2UgU3lzdGVtRXhpdChtYWluKCkpCg==', 'sha256': 'e34029c5859e492e75d3ff1ac020b5b6331814fabf5ca9203087a5dc430fe9fa'}}
def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    assert os.getuid()==os.geteuid()==0;os.umask(0o077)
    user=pwd.getpwnam('jwk');assert user.pw_uid==1002 and user.pw_gid==1002
    assert BASE.resolve()==BASE and BASE.stat().st_uid==user.pw_uid
    previous=json.loads((BASE/'runtime-prep005/result.json').read_text())
    assert previous['sdk']['installed'] and previous['sdk']['proof']['e2b']=='2.46.0' and previous['sdk']['proof']['pyqwest']=='0.10.0'
    assert previous['error']=="[Errno 2] No such file or directory: 'systemd'",'Unexpected earlier failure; preserve and inspect'
    state=json.loads((BASE/'status.json').read_text());helper=json.loads((BASE/'runtime-prep004/result.json').read_text())['query_helper']
    for name,row in previous['native_inputs'].items():assert digest(P(row['path']))==row['sha256'],name+' changed'
    assert digest(P(helper['path']))==helper['sha256']
    config=BASE/'config/runtime005.toml';assert digest(config)==previous['service_configuration']['sha256']
    settings=tomllib.loads(config.read_text());assert settings['pool']['low_watermark']==300 and settings['pool']['high_watermark']==1000
    runuser=shutil.which('runuser') or '/usr/sbin/runuser'
    environment={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C.UTF-8'}
    def command(args,seconds=30,as_user=False):
        r=subprocess.run(([runuser,'-u','jwk','--'] if as_user else [])+list(map(str,args)),env=environment,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':r.stdout[-30000:],'stderr':r.stderr[-6000:]}
    def checked(args,seconds=30):
        row=command(args,seconds);assert row['code']==0,row;return row
    def own_dir(path):
        assert path.parent.resolve()==path.parent
        if not path.exists():path.mkdir(mode=0o700);os.chown(path,user.pw_uid,user.pw_gid)
        assert path.resolve()==path and path.stat().st_uid==user.pw_uid
    def own_file(path,raw,mode=0o600):
        assert not path.exists() and not path.is_symlink()
        with path.open('xb') as f:f.write(raw.encode() if isinstance(raw,str) else raw)
        os.chown(path,user.pw_uid,user.pw_gid);os.chmod(path,mode)
    def root_file(path,raw,mode=0o600):
        assert path.parent.resolve()==path.parent and path.parent.stat().st_uid==0
        with path.open('xb') as f:f.write(raw.encode() if isinstance(raw,str) else raw)
        os.chmod(path,mode)
    def host_parameters():
        paths=['/proc/sys/net/ipv4/ip_forward','/proc/sys/kernel/numa_balancing','/sys/kernel/mm/transparent_hugepage/enabled']
        paths+=['/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i) for i in (1,2,3)]
        return {p:P(p).read_text().strip() for p in paths if P(p).exists()}
    def unit_state(name):return command(['systemctl','show',name,'-p','LoadState','--value'])['stdout'].strip()
    def launch(name,properties,args):
        return checked(['systemd-run','--unit='+name,'--description=Independent jwk AgentENV Y',
          '--service-type=exec',*['--property='+k+'='+v for k,v in properties.items()],*args],60)
    output=BASE/'deployment008';assert not output.exists();own_dir(output)
    result={'action':'INDEPENDENT_JWK_SERVICE_START','serviceStarted':False,'sdkReinstalled':False,'sourcePatched':False,
      'kernelPatched':False,'hostOptimizationSettingsChanged':False,'unitsCreated':[],'state':'STARTED'}
    before=host_parameters();result['host_parameters_before']=before
    try:
        result['systemd_version']=checked(['systemctl','--version'])
        source=BASE/'source/AgentENV'
        head=command(['git','-C',source,'rev-parse','HEAD'],as_user=True);clean=command(['git','-C',source,'status','--porcelain'],as_user=True)
        assert head['code']==0 and head['stdout'].strip()=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
        assert clean['code']==0 and not clean['stdout'].strip()
        sdk_proof=command([BASE/'sdk/g4-e2b246/bin/python','-I','-c',
          "import importlib.metadata as m,json;print(json.dumps({'e2b':m.version('e2b'),'pyqwest':m.version('pyqwest')}))"],as_user=True)
        assert sdk_proof['code']==0 and json.loads(sdk_proof['stdout'])=={'e2b':'2.46.0','pyqwest':'0.10.0'}
        result['sdk_verified']=json.loads(sdk_proof['stdout'])
        for name in (UNIT,BROKER,RELAYS):assert unit_state(name)=='not-found','Existing unit preserved: '+name
        for port in (18080,18089):
            with socket.socket() as s:s.bind(('127.0.0.1',port))
        assert not ROOT.exists() and not ROOT.is_symlink(),'Previous root preparation preserved'
        ROOT.mkdir(mode=0o711);(ROOT/'dev').mkdir(mode=0o711)
        # The module is a runtime prerequisite from the currently running kernel,
        # never an old/openEuler/external module or a kernel optimization patch.
        kernel=os.uname().release;module=checked(['modinfo','-F','filename','ublk_drv'])['stdout'].strip()
        assert P(module).resolve().is_relative_to(P('/lib/modules',kernel).resolve())
        assert checked(['modinfo','-F','vermagic','ublk_drv'])['stdout'].startswith(kernel+' ')
        if not P('/sys/module/ublk_drv').exists():
            checked(['modprobe','ublk_drv','ublks_max=10240']);result['standard_driver_loaded_by_task']=True
        else:result['standard_driver_loaded_by_task']=False
        limit=int(P('/sys/module/ublk_drv/parameters/ublks_max').read_text());assert limit>=4096,'Existing ublk capacity is insufficient; no module reload performed'
        result['standard_driver']={'path':module,'sha256':digest(P(module)),'ublks_max':limit}
        if shutil.which('udevadm',path=environment['PATH']):checked(['udevadm','settle','--timeout=15'],20)
        control=P('/dev/ublk-control')
        for _ in range(100):
            if control.exists():break
            time.sleep(.05)
        original_control=control.stat();assert stat.S_ISCHR(original_control.st_mode)
        private=ROOT/'dev/ublk-control';os.mknod(private,stat.S_IFCHR|0o600,original_control.st_rdev);os.chown(private,user.pw_uid,user.pw_gid)
        result['control_access']='Private character-device inode bound only inside the service mount namespace; host control permissions unchanged'
        excluded=[];existing=[]
        for path in P('/dev').glob('ublk[cb]*'):
            if not re.fullmatch(r'ublk[cb]\d+',path.name):continue
            st=path.lstat();excluded.append([st.st_dev,st.st_ino,st.st_rdev]);existing.append({'path':str(path),'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)})
        result['existing_devices']=existing
        root_file(ROOT/'jwk-ublk-query',P(helper['path']).read_bytes(),0o700)
        assert digest(ROOT/'jwk-ublk-query')==helper['sha256']
        source={}
        for name,row in BUNDLE.items():
            raw=base64.b64decode(row['base64'],validate=True);assert hashlib.sha256(raw).hexdigest()==row['sha256'];compile(raw,name,'exec');source[name]=raw
        root_file(ROOT/'device_broker008.py',source['device_broker008.py'],0o700)
        root_file(ROOT/'broker-config.json',json.dumps({'uid':user.pw_uid,'unit':UNIT,'daemon_sha256':previous['native_inputs']['daemon']['sha256'],'excluded':excluded})+'\n')
        own_dir(BASE/'runtime-code008')
        for name in ('runtime_supervisor008.py','benchmark_client008.py'):own_file(BASE/'runtime-code008'/name,source[name],0o700)
        own_dir(BASE/'results');own_dir(BASE/'state/image-cache');own_dir(BASE/'state/image-cache/convert-blocks')
        private_etc=BASE/'config/private-etc008';own_dir(private_etc)
        for name in ('passwd','group','nsswitch.conf','hosts','resolv.conf','ld.so.cache','localtime','hostname'):
            origin=P('/etc')/name
            if origin.is_file():own_file(private_etc/name,origin.read_bytes(),0o600)
        own_dir(private_etc/'ssl')
        if P('/etc/ssl/openssl.cnf').is_file():own_file(private_etc/'ssl/openssl.cnf',P('/etc/ssl/openssl.cnf').read_bytes())
        shutil.copytree('/etc/ssl/certs',private_etc/'ssl/certs',symlinks=True)
        for directory,dirs,files in os.walk(private_etc/'ssl/certs',followlinks=False):
            os.chown(directory,user.pw_uid,user.pw_gid)
            for name in dirs+files:os.lchown(P(directory)/name,user.pw_uid,user.pw_gid)
        own_dir(private_etc/'overlaybd')
        native={'logConfig':{'logLevel':1,'logPath':str(BASE/'logs/overlaybd-native.log')},
          'cacheConfig':{'cacheType':'file','cacheDir':str(BASE/'state/image-cache/convert-blocks'),'cacheSizeGB':10,'refillSize':262144},
          'credentialConfig':{'mode':'file','path':str(BASE/'config/docker/config.json')}}
        own_file(private_etc/'overlaybd/overlaybd.json',json.dumps(native)+'\n')
        proxy={'ca':state['private_ca005']['path']}
        from urllib.parse import urlsplit
        for scheme in ('http','https'):
            value=os.environ.get(scheme.upper()+'_PROXY') or os.environ.get(scheme+'_proxy')
            if value:
                parsed=urlsplit(value);assert parsed.scheme in ('http','https') and parsed.hostname
                assert parsed.username is None and parsed.password is None,'Authenticated root proxy credentials were not copied'
                proxy[scheme]=value
        own_file(BASE/'config/egress-proxy.json',json.dumps(proxy)+'\n')
        own_file(BASE/'config/host-context008.json',json.dumps({'boot_id':P('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'netns':os.stat('/proc/self/ns/net').st_ino,'mntns':os.stat('/proc/self/ns/mnt').st_ino,'uid':user.pw_uid})+'\n')
        own_file(BASE/'run.sh','#!/bin/bash\nset -euo pipefail\nexec '+str(BASE/'sdk/g4-e2b246/bin/python')+' -I -B '+str(BASE/'runtime-code008/benchmark_client008.py')+' "$@"\n',0o700)
        broker_properties={'User':'root','UMask':'0077','NoNewPrivileges':'yes','ProtectSystem':'strict','ProtectControlGroups':'yes',
          'ProtectKernelTunables':'yes','ProtectKernelModules':'yes','CapabilityBoundingSet':'CAP_SYS_ADMIN CAP_CHOWN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH',
          'ReadWritePaths':str(ROOT),'MemoryMax':'268435456','TasksMax':'128','LimitNOFILE':'1024',
          'StandardOutput':'append:'+str(ROOT/'broker.log'),'StandardError':'append:'+str(ROOT/'broker.log')}
        result['unitsCreated'].append(BROKER)
        result['broker_launch']=launch(BROKER,broker_properties,['/usr/bin/python3','-I','-B',str(ROOT/'device_broker008.py')])
        for _ in range(50):
            if (ROOT/'broker-ready.json').is_file():break
            time.sleep(.1)
        assert (ROOT/'broker-ready.json').is_file(),'Device broker failed readiness'
        relay_properties={'User':'jwk','Group':'jwk','UMask':'0077','NoNewPrivileges':'yes','ProtectSystem':'strict',
          'ReadWritePaths':str(BASE),'InaccessiblePaths':'/root /data/aenv','CapabilityBoundingSet':'','MemoryMax':'536870912','TasksMax':'128',
          'WorkingDirectory':str(BASE),'StandardOutput':'append:'+str(BASE/'logs/host-relays.log'),'StandardError':'append:'+str(BASE/'logs/host-relays.log')}
        result['unitsCreated'].append(RELAYS)
        result['relay_launch']=launch(RELAYS,relay_properties,['/usr/bin/python3','-I','-B',str(BASE/'runtime-code008/runtime_supervisor008.py'),'host'])
        available=next(int(x.split()[1])*1024 for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        memory_max=min(512*2**30,(available-128*2**30)//2**20*2**20);assert memory_max>128*2**30,'Insufficient free memory with128GiB reserve'
        kvm_group=grp.getgrgid(P('/dev/kvm').stat().st_gid).gr_name
        runtime_properties={'User':'jwk','Group':'jwk','SupplementaryGroups':kvm_group,
          'PrivateNetwork':'yes','PrivateMounts':'yes','PrivateTmp':'yes','NoNewPrivileges':'yes','ProtectSystem':'strict',
          'CapabilityBoundingSet':'CAP_NET_ADMIN CAP_SYS_ADMIN','AmbientCapabilities':'CAP_NET_ADMIN CAP_SYS_ADMIN',
          'ReadWritePaths':str(BASE),'InaccessiblePaths':'/root /data/aenv','BindReadOnlyPaths':str(private_etc)+':/etc',
          'BindPaths':str(private)+':/dev/ublk-control','LimitNOFILE':'1048576','LimitMEMLOCK':'infinity','TasksMax':'200000',
          'MemoryMax':str(memory_max),'MemorySwapMax':'0','WorkingDirectory':str(BASE),'UMask':'0077',
          'StandardOutput':'append:'+str(BASE/'logs/launcher.log'),'StandardError':'append:'+str(BASE/'logs/launcher.log')}
        result['runtime_properties']=runtime_properties
        result['unitsCreated'].append(UNIT)
        result['runtime_launch']=launch(UNIT,runtime_properties,['/usr/bin/python3','-I','-B',str(BASE/'runtime-code008/runtime_supervisor008.py'),'inside'])
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));ready=False
        for _ in range(240):
            pid=int(command(['systemctl','show',UNIT,'-p','MainPID','--value'])['stdout'].strip() or 0)
            if pid:
                try:
                    proc=P('/proc',str(pid))
                    if proc.stat().st_uid==user.pw_uid and digest(proc/'exe')==previous['native_inputs']['server']['sha256']:
                        with opener.open('http://127.0.0.1:18080/health',timeout=2) as response:
                            if response.status==204:ready=True;break
                except (OSError,ValueError):pass
            if command(['systemctl','is-failed',UNIT])['stdout'].strip()=='failed':break
            time.sleep(1)
        assert ready,'Runtime did not reach Rust health204'
        result['serviceStarted']=True;result['serverPid']=pid;result['rust_health']=204
        expected=None;stable=0;rows=[]
        for _ in range(180):
            rows=[]
            for proc in P('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    if proc.stat().st_uid!=user.pw_uid or (proc/'comm').read_text().strip()!='firecracker':continue
                    if not P(os.readlink(proc/'cwd')).is_relative_to(BASE/'fc'):continue
                    limits=next(x for x in (proc/'limits').read_text().splitlines() if x.startswith('Max open files')).split()
                    rows.append({'pid':int(proc.name),'soft':int(limits[3]),'hard':int(limits[4]),'cgroup':(proc/'cgroup').read_text().strip()})
                except (OSError,StopIteration):pass
            count=len(rows);stable=stable+1 if count==expected and count>=300 else 0;expected=count
            if stable>=4:break
            time.sleep(1)
        assert stable>=4 and all(x['soft']==x['hard']==1048576 for x in rows),'FC warm pool failed readiness'
        result['initial_fc_pool']={'count':len(rows),'nofile':1048576,'sample':rows[:8]}
        key=(BASE/'config/api-key').read_text().strip()
        request=urllib.request.Request('http://127.0.0.1:18080/v2/sandboxes?limit=1&state=running',headers={'X-API-Key':key})
        with opener.open(request,timeout=15) as response:sandboxes=json.load(response)
        assert sandboxes==[],'Unexpected sandboxes before template provisioning'
        result['authenticated_inventory_count']=0
        current=control.stat();assert (current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode))==(original_control.st_uid,original_control.st_gid,stat.S_IMODE(original_control.st_mode))
        for row in existing:
            path=P(row['path'])
            if path.exists() and path.lstat().st_ino==row['inode']:
                st=path.lstat();assert (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(row['uid'],row['gid'],row['mode'])
        result['host_parameters_after']=host_parameters();assert result['host_parameters_after']==before,'Host tuning unexpectedly changed'
        result['runtime_attestation']=json.loads((BASE/'r/runtime-attestation008.json').read_text())
        result['units']={name:command(['systemctl','show',name,'-p','ActiveState','-p','SubState','-p','MainPID','-p','User']) for name in (UNIT,BROKER,RELAYS)}
        result['templateProvisioned']=False;result['benchmarkRun']=False
        result['state']='JWK_RUST_SERVICE_HEALTHY_POOL_READY_TEMPLATE_PROVISIONING_PENDING'
    except BaseException as error:
        result['state']='STARTUP_FAILED_PRESERVE_OWN_ARTIFACTS';result['error']=str(error)[-10000:]
        # Stop only units created by this exact invocation, never a preexisting unit.
        for name in reversed(result['unitsCreated']):
            result.setdefault('failure_cleanup',{})[name]=command(['systemctl','stop',name],60)
        result['serviceStarted']=False
        result['diagnostics']={}
        for path in [BASE/'logs/server.log',BASE/'logs/launcher.log',BASE/'logs/ublk-daemon.log',BASE/'logs/host-relays.log',ROOT/'broker.log']:
            if path.is_file():
                with path.open('rb') as f:f.seek(max(0,path.stat().st_size-22000));result['diagnostics'][str(path)]=f.read().decode(errors='replace')
        raise
    finally:
        own_file(output/'result.json',json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(result,ensure_ascii=False),flush=True)
if __name__=='__main__':main()
