"""Confirm the retired object is absent and stage only the next Provider configuration."""

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import types
import uuid
from pathlib import Path


AUDIT = 'IiIiUmVjb25jaWxlIHRoZSBleGFjdCBmYWlsZWQgZGVtYW5kIHJ1biBiZWZvcmUgc3dpdGNoaW5nIG9wZXJhdG9ycy4iIiIKCmltcG9ydCBhcmdwYXJzZQppbXBvcnQgZXJybm8KaW1wb3J0IGZjbnRsCmltcG9ydCBqc29uCmltcG9ydCBvcwppbXBvcnQgc3RhdAppbXBvcnQgc3RydWN0CmltcG9ydCB1dWlkCmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aAoKCk9CTU1fREVWSUNFID0gUGF0aCgnL2Rldi9vYm1tX3BtZW0nKQpQQVRDSF9TUkNWRVJTSU9OID0gJzI5RjEwNjY0QzFFRTU5RDcxMjdGOEM3JwpWT0xVTUVfTEFZT1VUID0gc3RydWN0LlN0cnVjdCgnPElJMTZzSUlJSTdRJykKU0xPVF9MQVlPVVQgPSBzdHJ1Y3QuU3RydWN0KCc8SUkxNnNRSUkzMnMnKQpQUk9WSURFUiA9ICdhZ2VudGVudi11Yi1wcm92aWRlcicKUk9PVFMgPSB0dXBsZShtYXAoUGF0aCwgKCcvcm9vdC9hZW52LXBtZW0nLCAnL2V0Yy9hZW52L3ViJywgJy92YXIvbGliL2FlbnYtdWItc2RrJykpKQoKCmRlZiByZWFkX3RleHQocGF0aCwgbGltaXQ9MTI4ICogMTAyNCk6CiAgICByZXR1cm4gcmVhZF9ieXRlcyhwYXRoLCBsaW1pdCkuZGVjb2RlKCd1dGYtOCcsICdyZXBsYWNlJykKCgpkZWYgcmVhZF9ieXRlcyhwYXRoLCBsaW1pdCk6CiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PTkJMT0NLIHwgb3MuT19OT0ZPTExPVyB8IG9zLk9fQ0xPRVhFQykKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAncmInKSBhcyBzdHJlYW06CiAgICAgICAgaWYgbm90IHN0YXQuU19JU1JFRyhvcy5mc3RhdChzdHJlYW0uZmlsZW5vKCkpLnN0X21vZGUpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCdleHBlY3RlZCBhIHJlZ3VsYXIgZmlsZScpCiAgICAgICAgcmF3ID0gc3RyZWFtLnJlYWQobGltaXQgKyAxKQogICAgaWYgbGVuKHJhdykgPiBsaW1pdDoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCdmaWxlIGV4Y2VlZHMgY29sbGVjdGlvbiBib3VuZCcpCiAgICByZXR1cm4gcmF3CgoKZGVmIGluc3BlY3RfZGV2aWNlKHBhdGgpOgogICAgdHJ5OgogICAgICAgIGluZm8gPSBwYXRoLmxzdGF0KCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICByZXR1cm4geydwcmVzZW50JzogRmFsc2V9CiAgICByZXR1cm4geydwcmVzZW50JzogVHJ1ZSwgJ2NoYXJhY3Rlcic6IHN0YXQuU19JU0NIUihpbmZvLnN0X21vZGUpLAogICAgICAgICAgICAnZGV2aWNlJzogW29zLm1ham9yKGluZm8uc3RfcmRldiksIG9zLm1pbm9yKGluZm8uc3RfcmRldildLAogICAgICAgICAgICAndWlkJzogaW5mby5zdF91aWQsICdnaWQnOiBpbmZvLnN0X2dpZCwgJ21vZGUnOiBvY3Qoc3RhdC5TX0lNT0RFKGluZm8uc3RfbW9kZSkpfQoKCmRlZiBxdWVyeV9vYm1tKHZvbHVtZSwgc2VnbWVudCk6CiAgICByZXN1bHQgPSB7fQogICAgdHJ5OgogICAgICAgIHJlc3VsdFsnc3JjdmVyc2lvbiddID0gcmVhZF90ZXh0KFBhdGgoJy9zeXMvbW9kdWxlL29ibW0vc3JjdmVyc2lvbicpLCAxMjgpLnN0cmlwKCkKICAgICAgICBpZiByZXN1bHRbJ3NyY3ZlcnNpb24nXSAhPSBQQVRDSF9TUkNWRVJTSU9OIG9yIG9zLnVuYW1lKCkubWFjaGluZSAhPSAnYWFyY2g2NCc6CiAgICAgICAgICAgIHJldHVybiB7KipyZXN1bHQsICdxdWVyeSc6ICd1bnZlcmlmaWVkX2FiaSd9CiAgICAgICAgZmQgPSBvcy5vcGVuKE9CTU1fREVWSUNFLCBvcy5PX1JET05MWSB8IG9zLk9fQ0xPRVhFQyB8IG9zLk9fTk9GT0xMT1cpCiAgICBleGNlcHQgT1NFcnJvciBhcyBlcnJvcjoKICAgICAgICByZXR1cm4geyoqcmVzdWx0LCAncXVlcnknOiAndW5hdmFpbGFibGUnLCAnZXJybm8nOiBlcnJvci5lcnJub30KICAgIHRyeToKICAgICAgICBpZiBub3Qgc3RhdC5TX0lTQ0hSKG9zLmZzdGF0KGZkKS5zdF9tb2RlKToKICAgICAgICAgICAgcmV0dXJuIHsqKnJlc3VsdCwgJ3F1ZXJ5JzogJ2ludmFsaWRfZGV2aWNlX3R5cGUnfQogICAgICAgIGZvciBuYW1lLCBpZGVudCwgb3Bjb2RlLCBsYXlvdXQsIGZpZWxkcyBpbiAoCiAgICAgICAgICAgICgndm9sdW1lJywgdm9sdW1lLCAweGMwNjBiODAxLCBWT0xVTUVfTEFZT1VULAogICAgICAgICAgICAgKCd2ZXJzaW9uJywgJ3Jlc2VydmVkJywgJ3V1aWQnLCAnaWQnLCAnc3RhdGUnLCAnbWFqb3InLCAnbWlub3InLCAnYnl0ZXMnLAogICAgICAgICAgICAgICdvcGVuZXJzJywgJ2FjdGl2ZUlvJywgJ2Jsb2NrUmVhZHMnLCAnYmxvY2tCeXRlcycsICdkYXhBY2Nlc3NlcycsICdkYXhTcGFuQnl0ZXMnKSksCiAgICAgICAgICAgICgnc2VnbWVudCcsIHNlZ21lbnQsIDB4YzA0OGI4MGIsIFNMT1RfTEFZT1VULAogICAgICAgICAgICAgKCd2ZXJzaW9uJywgJ3N0YXRlJywgJ3V1aWQnLCAnc2xvdE9mZnNldCcsICdieXRlcycsICdyZXNlcnZlZCcsICdzaGEyNTYnKSksCiAgICAgICAgKToKICAgICAgICAgICAgd2lyZSA9IGJ5dGVhcnJheShsYXlvdXQuc2l6ZSkKICAgICAgICAgICAgc3RydWN0LnBhY2tfaW50bygnPElJMTZzJywgd2lyZSwgMCwgMSwgMCwgaWRlbnQuYnl0ZXMpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIGZjbnRsLmlvY3RsKGZkLCBvcGNvZGUsIHdpcmUsIFRydWUpCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGVycm9yOgogICAgICAgICAgICAgICAgcmVzdWx0W25hbWVdID0geyd1dWlkJzogc3RyKGlkZW50KSwgJ2Vycm5vJzogZXJyb3IuZXJybm8sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3N0YXR1cyc6ICdhYnNlbnQnIGlmIGVycm9yLmVycm5vID09IGVycm5vLkVOT0VOVCBlbHNlICdxdWVyeV9mYWlsZWQnfQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgcm93ID0gZGljdCh6aXAoZmllbGRzLCBsYXlvdXQudW5wYWNrKHdpcmUpKSkKICAgICAgICAgICAgaWYgcm93Wyd1dWlkJ10gIT0gaWRlbnQuYnl0ZXMgb3Igcm93Wyd2ZXJzaW9uJ10gIT0gMSBvciByb3dbJ3Jlc2VydmVkJ10gIT0gMDoKICAgICAgICAgICAgICAgIHJlc3VsdFtuYW1lXSA9IHsndXVpZCc6IHN0cihpZGVudCksICdzdGF0dXMnOiAndW5leHBlY3RlZF9yZXBseSd9CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICByb3dbJ3V1aWQnXSA9IHN0cihpZGVudCkKICAgICAgICAgICAgaWYgJ3NoYTI1NicgaW4gcm93OgogICAgICAgICAgICAgICAgcm93WydzaGEyNTYnXSA9IHJvd1snc2hhMjU2J10uaGV4KCkKICAgICAgICAgICAgcmVzdWx0W25hbWVdID0geyoqcm93LCAnc3RhdHVzJzogJ3ByZXNlbnQnfQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShmZCkKICAgIHJldHVybiByZXN1bHQKCgpkZWYgbmFtZWRfc2htZGV2cyhuYW1lKToKICAgIG1hdGNoZXMsIHVucmVhZGFibGUgPSBbXSwgMAogICAgcGF0aHMgPSBzb3J0ZWQoUGF0aCgnL3N5cy9kZXZpY2VzL29ibW0nKS5nbG9iKCdvYm1tX3NobWRldionKSkKICAgIGZvciBwYXRoIGluIHBhdGhzWzoyNTZdOgogICAgICAgIHRyeToKICAgICAgICAgICAgc2l6ZSA9IGludChyZWFkX3RleHQocGF0aCAvICdwcml2X2xlbicsIDMyKSkKICAgICAgICAgICAgcmF3ID0gcmVhZF9ieXRlcyhwYXRoIC8gJ3ByaXYnLCA1MTIpCiAgICAgICAgICAgIGlmIDIwNCA8PSBzaXplIDw9IGxlbihyYXcpIGFuZCByYXdbMTUyOjIwNF0ucGFydGl0aW9uKGInXHgwMCcpWzBdID09IG5hbWUuZW5jb2RlKCdhc2NpaScpOgogICAgICAgICAgICAgICAgbWF0Y2hlcy5hcHBlbmQoeyduYW1lJzogcGF0aC5uYW1lLCAndHlwZSc6IHJlYWRfdGV4dChwYXRoIC8gJ3R5cGUnLCAxMjgpLnN0cmlwKCksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3ByaXZCeXRlcyc6IHNpemV9KQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHVucmVhZGFibGUgKz0gMQogICAgcmV0dXJuIHsnbWF0Y2hlcyc6IG1hdGNoZXMsICd1bnJlYWRhYmxlJzogdW5yZWFkYWJsZSwgJ3RydW5jYXRlZCc6IGxlbihwYXRocykgPiAyNTZ9CgoKZGVmIG5lYXJieV9maWxlcyhyb290cyk6CiAgICBzZWVuID0gc2V0KCkKICAgIGZvciBkaXJlY3RvcnkgaW4gcm9vdHM6CiAgICAgICAgZm9yIGZvbGRlciwgZGlycywgZmlsZXMgaW4gb3Mud2FsayhkaXJlY3RvcnksIGZvbGxvd2xpbmtzPUZhbHNlKToKICAgICAgICAgICAgaGVyZSA9IFBhdGgoZm9sZGVyKQogICAgICAgICAgICBpZiBoZXJlIGluIHNlZW46CiAgICAgICAgICAgICAgICBkaXJzWzpdID0gW10KICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHNlZW4uYWRkKGhlcmUpCiAgICAgICAgICAgIGRpcnNbOl0gPSBzb3J0ZWQobmFtZSBmb3IgbmFtZSBpbiBkaXJzIGlmIG5vdCBuYW1lLnN0YXJ0c3dpdGgoJy4nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuZCBuYW1lIG5vdCBpbiAoJ2V2aWRlbmNlJywgJ3ZpZXcnLCAndGFyZ2V0JywgJ3JlZ2lzdHJ5JykpCiAgICAgICAgICAgIGlmIGxlbihoZXJlLnJlbGF0aXZlX3RvKGRpcmVjdG9yeSkucGFydHMpID49IDM6CiAgICAgICAgICAgICAgICBkaXJzWzpdID0gW10KICAgICAgICAgICAgZm9yIG5hbWUgaW4gc29ydGVkKGZpbGVzKToKICAgICAgICAgICAgICAgIHlpZWxkIGhlcmUgLyBuYW1lCiAgICAgICAgICAgIGlmIGxlbihzZWVuKSA+PSAxMjg6CiAgICAgICAgICAgICAgICByZXR1cm4KCgpkZWYgY29sbGVjdF9ydW5zKHJ1bik6CiAgICBkb2N1bWVudHMsIHNvdXJjZXMgPSBbXSwgW10KICAgIGZvciBwYXRoIGluIG5lYXJieV9maWxlcyhST09UUyk6CiAgICAgICAgaWYgcGF0aC5zdWZmaXggPT0gJy5leHQ0JyBhbmQgcGF0aC5uYW1lID09ICdsb3dlcnMuZXh0NCcgYW5kIG5vdCBwYXRoLmlzX3N5bWxpbmsoKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc291cmNlcy5hcHBlbmQoeydwYXRoJzogc3RyKHBhdGgpLCAnYnl0ZXMnOiBwYXRoLnN0YXQoKS5zdF9zaXplLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdtYW5pZmVzdFByZXNlbnQnOiBwYXRoLndpdGhfbmFtZSgnbWFuaWZlc3QuanNvbicpLmlzX2ZpbGUoKX0pCiAgICAgICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICBpZiBwYXRoLnN1ZmZpeCAhPSAnLmpzb24nIG9yIHBhdGguaXNfc3ltbGluaygpIG9yIGxlbihkb2N1bWVudHMpID49IDY0OgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHRyeToKICAgICAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMocmVhZF9ieXRlcyhwYXRoLCAzODQgKiAxMDI0KSkKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGRhdGEsIGRpY3QpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIGRhdGEuZ2V0KCdzdGF0ZScpID09ICdtZXRhZGF0YV9yZWFkeScgYW5kIGlzaW5zdGFuY2UoZGF0YS5nZXQoJ3JlcGxpY2FzJyksIGxpc3QpOgogICAgICAgICAgICBnZW5lcmF0aW9ucyA9IFtlbnRyeS5nZXQoJ2dlbmVyYXRpb24nKSBmb3IgZW50cnkgaW4gZGF0YVsncmVwbGljYXMnXSBpZiBpc2luc3RhbmNlKGVudHJ5LCBkaWN0KV0KICAgICAgICAgICAgZG9jdW1lbnRzLmFwcGVuZCh7J3BhdGgnOiBzdHIocGF0aCksICdpbmRleFN0YXRlJzogZGF0YVsnc3RhdGUnXSwgJ2dlbmVyYXRpb25zJzogZ2VuZXJhdGlvbnN9KQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGRhdGEuZ2V0KCdydW4nKSwgc3RyKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBrZXlzID0gKCdydW4nLCAnbm9kZScsICdwaGFzZScsICd2b2x1bWUnLCAnY2xvc2VkJywgJ2ZhdWx0ZWQnLCAncmVhZHknLCAncmVsZWFzZWQnLAogICAgICAgICAgICAgICAgJ2ZpbmFsaXplQWNrbm93bGVkZ2VkJywgJ2luaXRpYWxpemVBY2tub3dsZWRnZWQnLCAnYmluZGluZ3MnKQogICAgICAgIHJvdyA9IHtrZXk6IGRhdGFba2V5XSBmb3Iga2V5IGluIGtleXMgaWYga2V5IGluIGRhdGF9CiAgICAgICAgaWYgJ2RldmljZScgaW4gZGF0YSBhbmQgaXNpbnN0YW5jZShkYXRhWydkZXZpY2UnXSwgZGljdCk6CiAgICAgICAgICAgIHJvd1snZGV2aWNlJ10gPSB7a2V5OiBkYXRhWydkZXZpY2UnXS5nZXQoa2V5KSBmb3Iga2V5IGluICgnc291cmNlSW1hZ2UnLCAnc3RhdGVEaXInLCAnaW5kZXgnKX0KICAgICAgICBpZiBkYXRhWydydW4nXSA9PSBydW46CiAgICAgICAgICAgIHJvd1sncG9vbElkcyddID0gbGlzdChkYXRhWydwb29scyddKSBpZiBpc2luc3RhbmNlKGRhdGEuZ2V0KCdwb29scycpLCBkaWN0KSBlbHNlIE5vbmUKICAgICAgICBkb2N1bWVudHMuYXBwZW5kKHsncGF0aCc6IHN0cihwYXRoKSwgKipyb3d9KQogICAgcmVjZWlwdCA9IFJPT1RTWzBdIC8gJ2V2aWRlbmNlJyAvICgncmVjb3ZlcnktcmVjZWlwdC0nICsgcnVuWzo4XSArICcuanNvbicpCiAgICByZXR1cm4geydkb2N1bWVudHMnOiBkb2N1bWVudHMsICdvdXRlckltYWdlcyc6IHNvdXJjZXMsCiAgICAgICAgICAgICdleHBlY3RlZFJlY292ZXJ5UmVjZWlwdFByZXNlbnQnOiByZWNlaXB0LmlzX2ZpbGUoKX0KCgpkZWYgaW5zcGVjdF9wcm9jZXNzZXMoc2htZGV2cyk6CiAgICByb2xlcywgcmVmZXJlbmNlcyA9IFtdLCBbXQogICAgdW5yZWFkYWJsZV9yZWZzID0gMAogICAgZGV2aWNlcyA9IHsnL2Rldi8nICsgaXRlbVsnbmFtZSddIGZvciBpdGVtIGluIHNobWRldnN9CiAgICBmb3IgcHJvY2VzcyBpbiBQYXRoKCcvcHJvYycpLml0ZXJkaXIoKToKICAgICAgICBpZiBub3QgcHJvY2Vzcy5uYW1lLmlzZGVjaW1hbCgpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHRyeToKICAgICAgICAgICAgZXhlID0gb3MucmVhZGxpbmsocHJvY2VzcyAvICdleGUnKQogICAgICAgICAgICBuYW1lID0gUGF0aChleGUpLm5hbWUKICAgICAgICAgICAgaWYgbmFtZS5zdGFydHN3aXRoKChQUk9WSURFUiwgJ3V2bS11YmxrLWRhZW1vbicsICdmaXJlY3JhY2tlcicpKSBvciBuYW1lIGluICgnc2VydmVyJywgJ2FlbnYnKToKICAgICAgICAgICAgICAgIHJvdyA9IHsncGlkJzogaW50KHByb2Nlc3MubmFtZSksICdleGUnOiBleGUsICd1aWQnOiBwcm9jZXNzLnN0YXQoKS5zdF91aWR9CiAgICAgICAgICAgICAgICBpZiBuYW1lLnN0YXJ0c3dpdGgoUFJPVklERVIpOgogICAgICAgICAgICAgICAgICAgIGNtZCA9IHJlYWRfYnl0ZXMocHJvY2VzcyAvICdjbWRsaW5lJywgMTYgKiAxMDI0KS5zcGxpdChiJ1x4MDAnKQogICAgICAgICAgICAgICAgICAgIGlmIGxlbihjbWQpID49IDMgYW5kIGNtZFsxXSBpbiAoYidzZGsnLCBiJ3Jvb3QnKToKICAgICAgICAgICAgICAgICAgICAgICAgcm93Wydyb2xlJ10gPSBjbWRbMV0uZGVjb2RlKCkKICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnID0gUGF0aChvcy5mc2RlY29kZShjbWRbMl0pKS5yZXNvbHZlKHN0cmljdD1UcnVlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgY29uZmlnLnN1ZmZpeCA9PSAnLmpzb24nIGFuZCBhbnkoY29uZmlnLmlzX3JlbGF0aXZlX3RvKHJvb3QpIGZvciByb290IGluIFJPT1RTKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmcm9tX2NvbmZpZyA9IGpzb24ubG9hZHMocmVhZF9ieXRlcyhjb25maWcsIDI1NiAqIDEwMjQpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvd1sncnVuJ10gPSBmcm9tX2NvbmZpZy5nZXQoJ3J1bicpIGlmIGlzaW5zdGFuY2UoZnJvbV9jb25maWcsIGRpY3QpIGVsc2UgTm9uZQogICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIFJ1bnRpbWVFcnJvcik6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgICAgICByb2xlcy5hcHBlbmQocm93KQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHBhc3MKICAgICAgICBpZiBub3QgZGV2aWNlczoKICAgICAgICAgICAgY29udGludWUKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZkcyA9IFtdCiAgICAgICAgICAgIGZvciBmZCBpbiAocHJvY2VzcyAvICdmZCcpLml0ZXJkaXIoKToKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICB0YXJnZXQgPSBvcy5yZWFkbGluayhmZCkKICAgICAgICAgICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgaWYgdGFyZ2V0IGluIGRldmljZXM6CiAgICAgICAgICAgICAgICAgICAgZmRzLmFwcGVuZCh7J2ZkJzogZmQubmFtZSwgJ2RldmljZSc6IHRhcmdldH0pCiAgICAgICAgICAgIGlmIGZkczoKICAgICAgICAgICAgICAgIHJlZmVyZW5jZXMuYXBwZW5kKHsncGlkJzogaW50KHByb2Nlc3MubmFtZSksICdmZHMnOiBmZHN9KQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgcGFzcwogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICB1bnJlYWRhYmxlX3JlZnMgKz0gMQogICAgcmV0dXJuIHsncm9sZXMnOiByb2xlcywgJ21hdGNoaW5nU2htZGV2RmRzJzogcmVmZXJlbmNlcywgJ3VucmVhZGFibGVGZERpcmVjdG9yaWVzJzogdW5yZWFkYWJsZV9yZWZzfQoKCmRlZiBtYWluKCk6CiAgICBwYXJzZXIgPSBhcmdwYXJzZS5Bcmd1bWVudFBhcnNlcihkZXNjcmlwdGlvbj1fX2RvY19fKQogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgnLS12b2x1bWUnLCB0eXBlPXV1aWQuVVVJRCwgcmVxdWlyZWQ9VHJ1ZSkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoJy0tc2VnbWVudCcsIHR5cGU9dXVpZC5VVUlELCByZXF1aXJlZD1UcnVlKQogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgnLS1ydW4nLCB0eXBlPXV1aWQuVVVJRCwgcmVxdWlyZWQ9VHJ1ZSkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoJy0tb2JqZWN0JywgdHlwZT11dWlkLlVVSUQsIHJlcXVpcmVkPVRydWUpCiAgICBhcmdzID0gcGFyc2VyLnBhcnNlX2FyZ3MoKQogICAgYXNzZXJ0IFZPTFVNRV9MQVlPVVQuc2l6ZSA9PSA5NiBhbmQgU0xPVF9MQVlPVVQuc2l6ZSA9PSA3MgogICAgc2htZGV2cyA9IG5hbWVkX3NobWRldnMoJ2FlbnZfJyArIGFyZ3Mub2JqZWN0LmhleCkKICAgIHJlcG9ydCA9IHsnc3RhdHVzJzogJ01OX1RBS0VPVkVSX1JFQURPTkxZJywgJ2hvc3QnOiBvcy51bmFtZSgpLm5vZGVuYW1lLAogICAgICAgICAgICAgICdib290SWQnOiByZWFkX3RleHQoUGF0aCgnL3Byb2Mvc3lzL2tlcm5lbC9yYW5kb20vYm9vdF9pZCcpLCAxMjgpLnN0cmlwKCksCiAgICAgICAgICAgICAgJ3J1bic6IGFyZ3MucnVuLmhleCwgJ29ibW0nOiBxdWVyeV9vYm1tKGFyZ3Mudm9sdW1lLCBhcmdzLnNlZ21lbnQpLAogICAgICAgICAgICAgICdzaG1kZXZzJzogc2htZGV2cywgJ3Byb2Nlc3Nlcyc6IGluc3BlY3RfcHJvY2Vzc2VzKHNobWRldnNbJ21hdGNoZXMnXSksCiAgICAgICAgICAgICAgJ3N0YXRlJzogY29sbGVjdF9ydW5zKGFyZ3MucnVuLmhleCksICd1YmxrJzogaW5zcGVjdF9kZXZpY2UoUGF0aCgnL2Rldi91YmxrLWNvbnRyb2wnKSl9CiAgICBwcmludChqc29uLmR1bXBzKHJlcG9ydCwgc2VwYXJhdG9ycz0oJywnLCAnOicpLCBlbnN1cmVfYXNjaWk9VHJ1ZSksIGZsdXNoPVRydWUpCgoKaWYgX19uYW1lX18gPT0gJ19fbWFpbl9fJzoKICAgIG1haW4oKQo='
PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
PROVIDER_SHA = '5ecfe105521b583e3e419bdf6da09258144a5a4e63834de6612b4bcf880647d8'
LOWER_SHA = '42d2db6070a949f224fc2df0219d0bba969488dc57d1dba84aa39b45e65e4799'
UID, GID = 1204, 1205


def need(value, message):
    if not value:
        raise RuntimeError(message)


def direct_directory(path, owner=0):
    need(path.resolve(strict=True) == path, 'Redirected directory: ' + str(path))
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
         'Unexpected directory metadata: ' + str(path))


def create_directory(path, owner, group, mode):
    path.mkdir(mode=mode)
    os.chown(path, owner, group)
    path.chmod(mode)


def write_new(path, raw, uid, gid, mode):
    with path.open('xb') as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'old-run', 'pool', 'volume', 'segment'):
        parser.add_argument('--' + name, type=uuid.UUID, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--file-sha', required=True)
    parser.add_argument('--manifest-sha', required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    owner = host == 'agent1'
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use the M/N unified root entry')
    need(args.run != args.old_run, 'A fresh Provider run is required')
    audit = types.ModuleType('takeover_readonly')
    exec(compile(base64.b64decode(AUDIT, validate=True), audit.__name__, 'exec'), audit.__dict__)
    old = audit.query_obmm(args.volume, args.segment)
    need(all(old.get(key, {}).get('status') == 'absent' for key in ('volume', 'segment')),
         'Old volume or registered segment was not confirmed absent')
    regions = audit.named_shmdevs('aenv_' + args.pool.hex)
    print('MN_OLD_SDK_OBJECT=' + json.dumps(regions, sort_keys=True), flush=True)
    need(Path('/sys/devices/obmm').is_dir() and not regions['matches'] and
         not regions['truncated'] and not regions['unreadable'], 'Old shared SDK object remains or scan was incomplete')
    need(not audit.inspect_processes([])['roles'], 'Another runtime or Provider is active')

    manifest = args.manifest
    need(manifest.resolve(strict=True) == manifest and manifest.is_absolute()
         and manifest.name == 'manifest.json' and manifest.is_relative_to(Path('/root/aenv-pmem')),
         'Expected the fixed manifest under /root/aenv-pmem')
    raw = audit.read_bytes(manifest, 2 * 1024 * 1024)
    document = json.loads(raw)
    need(hashlib.sha256(raw).hexdigest() == args.file_sha and document['sha256'] == args.manifest_sha
         and document['document']['fileBytes'] == (1 << 30), 'Manifest file or document digest differs')
    if owner:
        image = manifest.with_name('lowers.ext4')
        need(image.is_file() and image.resolve() == image and image.stat().st_size == (1 << 30),
             'Prepared outer image unavailable')
    need(hashlib.sha256(audit.read_bytes(PROVIDER, 32 * 1024 * 1024)).hexdigest() == PROVIDER_SHA,
         'Provider binary differs from the verified build')
    engine_pid = int(subprocess.check_output(['/usr/bin/systemctl', 'show', 'ubse.service',
                                              '--property=MainPID', '--value'], text=True).strip())
    need(engine_pid > 1 and Path(f'/proc/{engine_pid}/exe').resolve().name == 'ubse', 'UBSE service not active')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    root_parent, sdk_parent = Path('/etc/aenv/ub'), Path('/var/lib/aenv-ub-sdk')
    direct_directory(root_parent)
    sdk_info = sdk_parent.lstat()
    need(sdk_info.st_uid in (0, UID), 'Unexpected SDK home owner')
    direct_directory(sdk_parent, sdk_info.st_uid)
    root_seed = root_parent / 'device-root.json'
    sdk_seed = sdk_parent / 'conf/device-sdk.json'
    seeds = [json.loads(audit.read_bytes(path, 256 * 1024)) for path in (root_seed, sdk_seed)]
    for cfg in seeds:
        need(cfg['node'] == host and cfg['ownerNode'] == 'agent1' and cfg['run'] == args.old_run.hex
             and (cfg['sdk']['uid'], cfg['sdk']['gid']) == (UID, GID), 'Old role configuration differs')

    suffix = 'relay-' + args.run.hex
    root_dir, sdk_dir = root_parent / suffix, sdk_parent / suffix
    need(not os.path.lexists(root_dir) and not os.path.lexists(sdk_dir), 'New generation directory already exists')
    reader_gid = seeds[0]['device']['readerGid']
    need(reader_gid == seeds[1]['device']['readerGid'], 'Reader group differs by role')
    create_directory(root_dir, 0, 0, 0o755)
    create_directory(sdk_dir, UID, GID, 0o700)
    for leaf, group, mode in (('rootctl', GID, 0o750), ('broker', reader_gid, 0o750),
                              ('index', reader_gid, 0o750), ('device-state', 0, 0o700),
                              ('mount', 0, 0o700)):
        create_directory(root_dir / leaf, 0, group, mode)
    local_manifest = root_dir / 'manifest.json'
    write_new(local_manifest, raw, 0, 0, 0o644)
    root_cfg, sdk_cfg = root_dir / 'device-root.json', sdk_dir / 'device-sdk.json'
    for cfg, target, uid, gid in ((seeds[0], root_cfg, 0, 0), (seeds[1], sdk_cfg, UID, GID)):
        cfg.update(run=args.run.hex, manifest=str(local_manifest), manifestSha256=args.manifest_sha,
                   rootSocket=str(root_dir / 'rootctl/root.sock'), sdkSocket=str(sdk_dir / 'sdk.sock'))
        cfg['sdk']['stateDir'] = str(sdk_dir / 'state')
        cfg['device'].update(stateDir=str(root_dir / 'device-state'), mountDir=str(root_dir / 'mount'),
                             brokerSocket=str(root_dir / 'broker/broker.sock'),
                             index=str(root_dir / 'index/stable-index.json'), bootId=boot,
                             kernelRelease=os.uname().release, moduleSrcversion=old['srcversion'],
                             enginePid=engine_pid, sourceImage=str(image) if owner else None,
                             lowers=[{'name': 'aenv-template.ext4', 'digest': 'sha256:' + LOWER_SHA,
                                      'bytes': 536870912}])
        write_new(target, (json.dumps(cfg, indent=2) + '\n').encode(), uid, gid, 0o600)
    subprocess.run([str(PROVIDER), 'validate', str(root_cfg)], check=True, timeout=15)
    subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER), 'validate', str(sdk_cfg)],
                   check=True, timeout=15)
    print(json.dumps({'status': 'MN_PROVIDER_CONFIG_STAGED', 'run': args.run.hex, 'node': host,
                      'rootConfig': str(root_cfg), 'sdkConfig': str(sdk_cfg),
                      'manifestDigest': args.manifest_sha}), flush=True)


if __name__ == '__main__':
    main()
