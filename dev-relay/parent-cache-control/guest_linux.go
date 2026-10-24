//go:build linux

// Guest-only cache observer and bounded read barrier. No global cache eviction.
package main

import (
 "bufio"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "runtime"
 "strconv"
 "strings"
 "syscall"
 "time"
 "unsafe"
)

const targetBytes = 8 * 1024 * 1024
var readCount int
var mode, expected string

func emit(v map[string]interface{}) { b,_:=json.Marshal(v);fmt.Printf("PCC_EVENT %s\n",b) }
func dax(path string) (bool,error) {
 var nr uintptr
 if runtime.GOARCH=="arm64" { nr=291 } else if runtime.GOARCH=="amd64" {nr=332} else {return false,fmt.Errorf("unsupported statx architecture")}
 p,e:=syscall.BytePtrFromString(path);if e!=nil{return false,e}
 var buf [256]byte
 _,_,err:=syscall.Syscall6(nr,^uintptr(99),uintptr(unsafe.Pointer(p)),0,0x7ff,uintptr(unsafe.Pointer(&buf[0])),0)
 if err!=0{return false,err}
 if binary.LittleEndian.Uint64(buf[56:64])&0x200000==0{return false,fmt.Errorf("S_DAX observation unsupported")}
 return binary.LittleEndian.Uint64(buf[8:16])&0x200000!=0,nil
}

// PROT_NONE mapping and mincore inspect cache state without touching file data.
// Prove file-owner/CAP_FOWNER authority: Linux can otherwise return all ones.
func inspect(path string) (map[string]interface{},error) {
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 info,e:=f.Stat();if e!=nil{return nil,e}
 st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok || !info.Mode().IsRegular() || info.Size()!=targetBytes {return nil,fmt.Errorf("target type/size differs")}
 authority:="owner"
 if st.Uid!=uint32(os.Geteuid()) {
  status,e:=os.ReadFile("/proc/self/status");if e!=nil{return nil,e};allowed:=false
  for _,line:=range strings.Split(string(status),"\n") {fields:=strings.Fields(line);if len(fields)==2 && fields[0]=="CapEff:" {caps,e:=strconv.ParseUint(fields[1],16,64);allowed=e==nil && caps&(1<<3)!=0}}
  if !allowed{return nil,fmt.Errorf("mincore owner/CAP_FOWNER authority absent")};authority="CAP_FOWNER"
 }
 isDax,e:=dax(path);if e!=nil{return nil,e}
 if isDax!=(mode=="pmem") {return nil,fmt.Errorf("unexpected actual DAX state")}
 r:=map[string]interface{}{"path":path,"bytes":info.Size(),"dax":isDax,"uid":st.Uid,"inode":st.Ino,"dev":st.Dev,"fileDataReadByCheck":false,"cacheObservationAuthority":authority,"ordinaryPageCacheApplicable":!isDax}
 if !isDax {
  data,e:=syscall.Mmap(int(f.Fd()),0,targetBytes,syscall.PROT_NONE,syscall.MAP_SHARED);if e!=nil{return nil,e}
  defer syscall.Munmap(data)
  pages:=(targetBytes+os.Getpagesize()-1)/os.Getpagesize();bits:=make([]byte,pages)
  _,_,err:=syscall.Syscall(syscall.SYS_MINCORE,uintptr(unsafe.Pointer(&data[0])),uintptr(len(data)),uintptr(unsafe.Pointer(&bits[0])))
  if err!=0{return nil,err};n:=0;for _,v:=range bits {if v&1!=0{n++}}
  r["residentPages"]=n;r["totalPages"]=pages;r["pageSize"]=os.Getpagesize()
 }
 return r,nil
}
func facts() (map[string]interface{},error) {
 lower,e:=inspect("/mnt/ro0/common-data.bin");if e!=nil{return nil,e}
 visible,e:=inspect("/mnt/user/common-data.bin");if e!=nil{return nil,e}
 b,e:=os.ReadFile("/proc/meminfo");if e!=nil{return nil,e};mem:=map[string]uint64{}
 for _,line:=range strings.Split(string(b),"\n") {
  f:=strings.Fields(line);if len(f)==3 && f[2]=="kB" {n,e:=strconv.ParseUint(f[1],10,64);if e==nil{mem[strings.TrimSuffix(f[0],":")]=n*1024}}
 }
 return map[string]interface{}{"lower":lower,"visible":visible,"meminfoBytes":mem,"readCount":readCount,"bufferBytes":65536},nil
}
func readTarget() (map[string]interface{},error) {
 f,e:=os.Open("/mnt/user/common-data.bin");if e!=nil{return nil,e};defer f.Close()
 h:=sha256.New();buf:=make([]byte,65536);total:=0;begin:=time.Now()
 for {n,e:=f.Read(buf);if n>0{total+=n;if total>targetBytes{return nil,fmt.Errorf("oversize")};h.Write(buf[:n])};if e==io.EOF{break};if e!=nil{return nil,e}}
 digest:=hex.EncodeToString(h.Sum(nil));if total!=targetBytes || digest!=expected{return nil,fmt.Errorf("target digest/length differs")}
 readCount++
 return map[string]interface{}{"sha256":digest,"bytes":total,"seconds":time.Since(begin).Seconds(),"readCount":readCount},nil
}
func main() {
 if len(os.Args)!=3 {panic("expected mode and hash")};mode,expected=os.Args[1],os.Args[2]
 if (mode!="block" && mode!="pmem") || len(expected)!=64 {panic("invalid arguments")}
 if _,e:=hex.DecodeString(expected);e!=nil{panic(e)}
 // Startup is metadata-only. Target hashing must never occur on this path.
 f,e:=facts();if e!=nil{emit(map[string]interface{}{"event":"error","error":e.Error()});return}
 emit(map[string]interface{}{"event":"boot_ready","facts":f})
 scanner:=bufio.NewScanner(os.Stdin);scanner.Buffer(make([]byte,512),1024)
 for scanner.Scan() {
  fields:=strings.Fields(scanner.Text());if len(fields)!=2{emit(map[string]interface{}{"event":"error","error":"invalid command"});return}
  command,token:=fields[0],fields[1];if len(token)!=32{emit(map[string]interface{}{"event":"error","error":"invalid token"});return}
  if _,e:=hex.DecodeString(token);e!=nil{emit(map[string]interface{}{"event":"error","error":"invalid token"});return}
  var reading map[string]interface{}
  switch command {
  case "CHECK":
  case "BARRIER":syscall.Sync()
  case "READ":reading,e=readTarget()
  case "EXIT":
   emit(map[string]interface{}{"event":"reply","command":command,"token":token,"readCount":readCount});syscall.Sync();syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF);return
  default:e=fmt.Errorf("unknown command")
  }
  if e!=nil{emit(map[string]interface{}{"event":"error","token":token,"error":e.Error()});return}
  f,e=facts();if e!=nil{emit(map[string]interface{}{"event":"error","token":token,"error":e.Error()});return}
  emit(map[string]interface{}{"event":"reply","command":command,"token":token,"facts":f,"read":reading})
 }
}
