import base64,hashlib,json,pathlib,sys
p=pathlib.Path('/home/jwk/aenv-y-clean-20261111/g7-20261112/evidence.tar.gz');index=int(sys.argv[1]);assert index in range(3)
blob=p.read_bytes();part=blob[index*400000:(index+1)*400000]
result={'group':'G7','index':index,'chunkSize':400000,'totalBytes':len(blob),'sha256':hashlib.sha256(blob).hexdigest(),'partSha256':hashlib.sha256(part).hexdigest(),'base64':base64.b64encode(part).decode(),'chunksNeeded':(len(blob)+399999)//400000}
text=json.dumps(result,separators=(',',':'));assert len(text)<600000;print(text)
