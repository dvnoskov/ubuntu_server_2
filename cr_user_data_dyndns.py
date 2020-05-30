from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from cr_dyndns_db import DynDNS,User
import time
import binascii
from config import route_DB,host_DNS


def hex2str(h):
    return binascii.unhexlify(h)


def str2hex1(s):
    return binascii.hexlify(bytes(bytearray(s)))


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def Qname(name):
    name_hex = str2hex(name).decode('utf-8')
    return name_hex

def Ipdata(myip):
    ip = myip.split(".")
    s=[int(ip[0]),int(ip[1]),int(ip[2]),int(ip[3])]
    return (str(str2hex1(s))[2:10])


engine = create_engine(route_DB)
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

#-----------------------------------------
# Add host DynDNS


name_ip = "checkip.dyndns.com" #test ip adres dyndns
DynDNS_add_ip = DynDNS(NAME=Qname(name_ip),
                 USER= "DNS",
                 TYPE="0001",# default
                 CLASS="0001",# default
                 TTL="00000e10",# default 3600 c ???
                 ANCOUNT="0001",# default
                 RDLENGTH="0004",# default
                 RDATA=Ipdata(host_DNS),
 #                Time=time.time(),
                 STATUS="DynDNS")
#session.add(DynDNS_add_ip)
#session.commit()
#-------------------------------------------------------
#update dynhost.ml
name_ip = "dynhost.ml"
new_host = "192.0.0.0"
query = session.query(DynDNS)
sys = query.filter(DynDNS.NAME == Qname(name_ip))
sys.update({DynDNS.RDATA: Ipdata(new_host)})
#session.commit()
#------------------------------------------------------

#name_dyndns = "members.dyndns.org" # name update ip adres
name_dyndns = "dimon49.ml" # name update ip adres
DynDNS_add_dyndns = DynDNS(NAME=Qname(name_dyndns),
                 USER= "DNS",
                 TYPE="0001",# default
                 CLASS="0001",# default
                 TTL="00000384",# default 3600/4 c ???
               #  TTL="00000e10",# default 3600 c ???
                 ANCOUNT="0001",# default
                 RDLENGTH="0004",# default
                 RDATA=Ipdata(host_DNS),
#                 Time=time.time(),
                 STATUS="DynDNS")
#session.add(DynDNS_add_dyndns)
#session.commit()

#-------------------------------------------------


#-----------------------------------------
# Add user for DynDNS
test_user = User(username='test',
                 password='')
KiK_user = User(username='dimon49',
                 password='')
admin_user = User(username='admin',
                 password='')
#session.add(test_user)
#session.add(KiK_user)
#session.add(admin_user)
#session.commit()

#----------------------------------------------
# Add name for DynDNS

Name =["ndv11.dynhost.ml",
      "ndv12.dynhost.ml",
      "ndv13.dynhost.ml",
      "ndv14.dynhost.ml",
      "ndv15.dynhost.ml",
      "ndv16.dynhost.ml",
      "ndv17.dynhost.ml",
      "ndv18.dynhost.ml",
      "ndv19.dynhost.ml"]


myip = "192.168.1.200"

user_add="dimon49"
for v in Name:
    DynDNS_add = DynDNS(NAME=Qname(v),
                 USER= user_add,
                 TYPE="0001",# default
                 CLASS="0001",# default
                 TTL="00000384",  # default 3600/4 c ???
              #   TTL="00000e10",# default 3600 c ???
                 ANCOUNT="0001",# default
                 RDLENGTH="0004",# default
                 RDATA=Ipdata(myip),
 #                Time=time.time(),
                 STATUS="USER")
  #  session.add(DynDNS_add)
  #  session.commit()

#---------------------------------------------------
#update time_stop
v="kik04.dynhost.ml"

query = session.query(DynDNS)
sys = query.filter(DynDNS.NAME == Qname(v))
sys.update({DynDNS.Time_stop: time.time()+float(60*60*24*1)}) #1 day
#session.commit()
#---------------------------------------------------
# can user
"""
user_del='KiK'
query = session.query(User)
query = query.filter(User.username == user_del)
dcc_cookie = query.one()
session.delete(dcc_cookie)
session.commit()
query = session.query(DynDNS)
while True:
    new = query.filter(DynDNS.STATUS == 'USER').count()
    print("new", new)
    if new >= 1:
        menu = session.query(DynDNS).filter(DynDNS.STATUS == 'USER', DynDNS.USER == None).first()
        print(menu.USER, menu.dyndns_id, menu.STATUS)
        new_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
        session.delete(menu)
        session.commit()
    else:
        session.close()
        break

#--------------------------------------------------
"""
session.close()










