"""Submit a bounded benchmark to the capability-free runner inside the namespace."""
import argparse,json,pathlib,socket,sys
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--rounds',type=int,default=5);args=parser.parse_args()
    if not 1<=args.rounds<=10:parser.error('--rounds must be1..10')
    path='/home/jwk/aenv-y-clean-20261111/r/benchmark.sock';success=False
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(7200);client.connect(path);client.sendall((json.dumps({'rounds':args.rounds})+'\n').encode())
        with client.makefile('rb') as stream:
            for line in stream:
                sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
                if line.strip()==b'BENCHMARK_EXIT=0':success=True
    return 0 if success else 1
if __name__=='__main__':raise SystemExit(main())
