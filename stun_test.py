import socket,struct,random,os
def stun(srv,pt):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.settimeout(3)
    s.bind(("0.0.0.0",pt))
    s.sendto(struct.pack(">HHI",1,0,0x2112A442)+os.urandom(12),srv)
    d,_=s.recvfrom(1024)
    s.close()
    p=20
    while p<len(d):
        t,l=struct.unpack(">HH",d[p:p+4])
        if t==0x0020:
            xi=struct.unpack(">I",d[p+8:p+12])[0]^0x2112A442
            xp=struct.unpack(">H",d[p+6:p+8])[0]^0x2112
            return socket.inet_ntoa(struct.pack(">I",xi)),xp
        p+=4+l+(4-l%4)%4
    return None,None
p=random.randint(40000,50000)
i1,p1=stun(("stun.l.google.com",19302),p)
i2,p2=stun(("stun1.l.google.com",19302),p)
print(i1,p1,i2,p2,"CONE" if p1==p2 else "SYMMETRIC")
