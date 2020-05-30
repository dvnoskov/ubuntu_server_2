# -------------------------------------------------------------------
# v03.2020
# records- A,TXT,SOA,NS
# dir(Records/NS.txt SOA.txt TXT.txt)
# dynhost.ml (DNS area+host_dns)
# syn DNS_DB
# -------------------------------------------------------------------
import binascii
import shelve
import os
import re
from cr_dyndns_db import DynDNS
import time
from config import MINIMUM
import json
import socket
from config import host_DNS2, port_DNS, host_name


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def Qname(name):
    name_hex = str2hex(name).decode('utf-8')
    return name_hex


def hex2str(h):
    return binascii.unhexlify(h)


def INlend(inlen):
    strippedHex = lambda x: \
        x >= 0 and hex(x)[2:] or "-" + hex(x)[3:]
    a = strippedHex(inlen)
    if len(a) == 1:
        outlen = "000" + str(a)
    elif len(a) == 2:
        outlen = "00" + str(a)
    elif len(a) == 3:
        outlen = "0" + str(a)
    elif len(a) == 4:
        outlen = str(a)
    else:
        print("error")

    return outlen


def Rdlend(List_db_dns_out, List_db_dns_out_1):
    t = int(len(List_db_dns_out) / 2)
    strippedHex = lambda x: \
        x >= 0 and hex(x)[2:] or "-" + hex(x)[3:]
    a = strippedHex(t)
    if len(a) == 1:
        List_db_dns_out_1["RDLENGTH"] = "000" + str(a)
    elif len(a) == 2:
        List_db_dns_out_1["RDLENGTH"] = "00" + str(a)
    elif len(a) == 3:
        List_db_dns_out_1["RDLENGTH"] = "0" + str(a)
    elif len(a) == 4:
        List_db_dns_out_1["RDLENGTH"] = str(a)
    else:
        print("error")

    return List_db_dns_out_1["RDLENGTH"]


def UPDATE_DYNDNS_start(inses):

    session = inses
    update = {}
    namba = 0
    work = session.query(DynDNS).filter(DynDNS.STATUS == 'USER').count()
    while True:
        if work - 1 >= namba:
            menu = session.query(DynDNS).filter(DynDNS.STATUS == 'USER').all()
            update[menu[namba].NAME] = menu[namba].USER, menu[namba].RDATA, menu[namba].Time_stop
            namba = namba + 1
        else:
            break

    session.close()
    return update



def UPDATE_DYNDNS_finish(start, inses, lock):
    lock.acquire()
    session = inses

    for key, value in start.items():
        name = key
        user = value[0]
        ip = value[1]
        st_time = value[2]
        query = session.query(DynDNS)
        sys = query.filter(DynDNS.NAME == name and DynDNS.USER == user).first()
        if sys is not None:
            query.filter(DynDNS.NAME == name and DynDNS.USER == user).update({DynDNS.RDATA: ip})
            query.filter(DynDNS.NAME == name and DynDNS.USER == user).update({DynDNS.Time_stop: st_time})
        else:
            DynDNS_add = DynDNS(NAME=name,
                                USER=user,
                                TYPE="0001",  # default
                                CLASS="0001",  # default
                                TTL="00000384",  # default 3600/4 c
                                ANCOUNT="0001",  # default
                                RDLENGTH="0004",  # default
                                RDATA=ip,
                                STATUS="USER")
            session.add(DynDNS_add)

    session.commit()
    session.close()
    lock.release()
    f = open('update_DB_DNS.txt', 'a+')
    f.write('update DB_DNS in time =  ' + time.ctime() + '\n')
    return

def ServFail(List_db_dns_out):
    List_db_dns_out["RCODE"] = "0010"  # Code answer(0,1,2,3,4,5,6-15) Server fail(2)
    List_db_dns_out["ANCOUNT"] = "0001"  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") \
               + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))

    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS")
    #  print(message_db_dns_out)
    return message_db_dns_out


def answer_no_name_millenium(List_db_dns_out):
    List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) Server ok!
    List_db_dns_out["ANCOUNT"] = "0001"  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0001"
    List_db_dns_out["CLASS"] = "0001"
    List_db_dns_out["TTL"] = "00000384"  # 15 min
    List_db_dns_out["RDLENGTH"] = "0004"
    List_db_dns_out["RDATA"] = "c0a80164"  # 192.168.1.100!!!!!!! c0a80164
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")
    return message_db_dns_out


def answer_no_name(List_db_dns_out, List_db_dns_out_1):
    #  List_db_dns_out["RCODE"] = "0011"  # NXDomain (3)
    List_db_dns_out["ARCOUNT"] = "0000"
    List_db_dns_out["ANCOUNT"] = "0001"
    List_db_dns_out["NSCOUNT"] = "0000"  # numba write name servis available
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "c00c"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0006"  # soa(6)
    List_db_dns_out["CLASS"] = "0001"
    List_db_dns_out["TTL"] = MINIMUM
    NAME_err = "err.dynhost.ml"

    if os.path.isfile(os.path.abspath('./Records/SOA.txt')):
        infile = open(os.path.abspath('./Records/SOA.txt'), 'r')
        with infile as fil:
            for line in fil:
                if line.startswith('SOA record '):
                    r = re.compile(r'SOA record =(.*)#(.*)')
                    sep = r.search(line)
                    if str(str2hex(sep.group(1)))[2:-1] == str(str2hex(NAME_err))[2:-1]:
                        r1 = re.compile(r'MNAME =(.*)#(.*)')
                        sep1 = r1.search(fil.readline())
                        List_db_dns_out["MNAME"] = str(str2hex(sep1.group(1)))[2:-1] + "00"
                        r2 = re.compile(r'RNAME =(.*)#(.*)')
                        sep2 = r2.search(fil.readline())
                        List_db_dns_out["RNAME"] = str(str2hex(sep2.group(1)))[2:-1] + "0000"
                        r3 = re.compile(r'SERIAL =(.*)#(.*)')
                        sep3 = r3.search(fil.readline())
                        List_db_dns_out["SERIAL"] = sep3.group(1)
                        r4 = re.compile(r'REFRESH =(.*)#(.*)')
                        sep4 = r4.search(fil.readline())
                        List_db_dns_out["REFRESH"] = sep4.group(1)
                        r5 = re.compile(r'RETRY =(.*)#(.*)')
                        sep5 = r5.search(fil.readline())
                        List_db_dns_out["RETRY"] = sep5.group(1)
                        r6 = re.compile(r'EXPIRE =(.*)#(.*)')
                        sep6 = r6.search(fil.readline())
                        List_db_dns_out["EXPIRE"] = sep6.group(1)
                        r7 = re.compile(r'MINIMUM =(.*)#(.*)')
                        sep7 = r7.search(fil.readline())
                        List_db_dns_out["MINIMUM"] = sep7.group(1)
                        List_db_dns_out["SOA"] = List_db_dns_out.get("MNAME") + List_db_dns_out.get("RNAME") \
                                                 + List_db_dns_out.get("SERIAL") + List_db_dns_out.get(
                            "REFRESH") + List_db_dns_out.get("RETRY") \
                                                 + List_db_dns_out.get("EXPIRE") + List_db_dns_out.get("MINIMUM")
                        Rdlend(List_db_dns_out["SOA"], List_db_dns_out_1)
                        List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                    + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                    + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get("SOA")
                    else:
                        pass
                else:
                    pass
        infile.close()
        message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") \
                             + List_db_dns_out.get("QDCOUNT") + List_db_dns_out.get("ANCOUNT") \
                             + List_db_dns_out.get("NSCOUNT") + List_db_dns_out.get("ARCOUNT") \
                             + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                             + List_db_dns_out.get("QCLASS") + List_db_dns_out_1.get("DATA")

    else:
        ServFail(List_db_dns_out)  # ServFail (2)

        #  print(message_db_dns_out)
    return message_db_dns_out


def answer_A_name(requst, List_db_dns_out):
    # List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ANCOUNT"] = requst.ANCOUNT  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = requst.TYPE
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    List_db_dns_out["RDLENGTH"] = requst.RDLENGTH
    List_db_dns_out["RDATA"] = requst.RDATA
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")

    return message_db_dns_out

def answer_A_host_name(inses,requst, List_db_dns_out):  # yes host_name

    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    session = inses
    namba = 0
    List_db_dns_out["host_name"] = ""
    work_host = session.query(DynDNS).filter(DynDNS.NAME == Qname(host_name), DynDNS.STATUS == 'DynDNS').count()
    List_db_dns_out["ANCOUNT"] = "000" + str(work_host)
    while True:
        if work_host - 1 >= namba:
            host = session.query(DynDNS).filter(DynDNS.STATUS == 'DynDNS', DynDNS.USER == 'DNS').all()
            List_db_dns_out["host_name"] = List_db_dns_out["host_name"] + "C00C" + requst.TYPE + requst.CLASS \
            + host[namba].TTL + "0004" + host[namba].RDATA
            namba = namba + 1
        else:
            break


    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out["host_name"]

    return message_db_dns_out


def answer_SOA(requst, List_db_dns_out, List_db_dns_out_1):
    # List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ARCOUNT"] = "0000"
    List_db_dns_out["ANCOUNT"] = "0001"
    List_db_dns_out["NSCOUNT"] = "0000"  # numba write name servis available
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "c00c"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0006"  # soa(6)
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    soa = 0
    if os.path.isfile(os.path.abspath('./Records/SOA.txt')):
        infile = open(os.path.abspath('./Records/SOA.txt'), 'r')
        with infile as fil:
            for line in fil:
                soa_t = "default"
                if line.startswith('SOA record '):
                    r = re.compile(r'SOA record =(.*)#(.*)')
                    sep = r.search(line)
                    if str(str2hex(sep.group(1)))[2:-1] == requst.NAME:
                        # print(str(str2hex(sep.group(1)))[2:-1])

                        r1 = re.compile(r'MNAME =(.*)#(.*)')
                        sep1 = r1.search(fil.readline())
                        List_db_dns_out["MNAME"] = str(str2hex(sep1.group(1)))[2:-1] + "00"
                        r2 = re.compile(r'RNAME =(.*)#(.*)')
                        sep2 = r2.search(fil.readline())
                        List_db_dns_out["RNAME"] = str(str2hex(sep2.group(1)))[2:-1] + "0000"
                        r3 = re.compile(r'SERIAL =(.*)#(.*)')
                        sep3 = r3.search(fil.readline())
                        List_db_dns_out["SERIAL"] = sep3.group(1)
                        r4 = re.compile(r'REFRESH =(.*)#(.*)')
                        sep4 = r4.search(fil.readline())
                        List_db_dns_out["REFRESH"] = sep4.group(1)
                        r5 = re.compile(r'RETRY =(.*)#(.*)')
                        sep5 = r5.search(fil.readline())
                        List_db_dns_out["RETRY"] = sep5.group(1)
                        r6 = re.compile(r'EXPIRE =(.*)#(.*)')
                        sep6 = r6.search(fil.readline())
                        List_db_dns_out["EXPIRE"] = sep6.group(1)
                        r7 = re.compile(r'MINIMUM =(.*)#(.*)')
                        sep7 = r7.search(fil.readline())
                        List_db_dns_out["MINIMUM"] = sep7.group(1)
                        List_db_dns_out["SOA"] = List_db_dns_out.get("MNAME") + List_db_dns_out.get("RNAME") \
                                                 + List_db_dns_out.get("SERIAL") + List_db_dns_out.get(
                            "REFRESH") + List_db_dns_out.get("RETRY") \
                                                 + List_db_dns_out.get("EXPIRE") + List_db_dns_out.get("MINIMUM")
                        Rdlend(List_db_dns_out["SOA"], List_db_dns_out_1)
                        List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                    + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                    + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get("SOA")
                        soa = 1
                        # print(List_db_dns_out_1["DATA"])
                    elif str(str2hex(sep.group(1)))[2:-1] == str(str2hex(soa_t))[2:-1] and soa == 0:
                        r1 = re.compile(r'MNAME =(.*)#(.*)')
                        sep1 = r1.search(fil.readline())
                        List_db_dns_out["MNAME"] = str(str2hex(sep1.group(1)))[2:-1] + "00"
                        r2 = re.compile(r'RNAME =(.*)#(.*)')
                        sep2 = r2.search(fil.readline())
                        List_db_dns_out["RNAME"] = str(str2hex(sep2.group(1)))[2:-1] + "0000"
                        r3 = re.compile(r'SERIAL =(.*)#(.*)')
                        sep3 = r3.search(fil.readline())
                        List_db_dns_out["SERIAL"] = sep3.group(1)
                        r4 = re.compile(r'REFRESH =(.*)#(.*)')
                        sep4 = r4.search(fil.readline())
                        List_db_dns_out["REFRESH"] = sep4.group(1)
                        r5 = re.compile(r'RETRY =(.*)#(.*)')
                        sep5 = r5.search(fil.readline())
                        List_db_dns_out["RETRY"] = sep5.group(1)
                        r6 = re.compile(r'EXPIRE =(.*)#(.*)')
                        sep6 = r6.search(fil.readline())
                        List_db_dns_out["EXPIRE"] = sep6.group(1)
                        r7 = re.compile(r'MINIMUM =(.*)#(.*)')
                        sep7 = r7.search(fil.readline())
                        List_db_dns_out["MINIMUM"] = sep7.group(1)
                        List_db_dns_out["SOA"] = List_db_dns_out.get("MNAME") + List_db_dns_out.get("RNAME") \
                                                 + List_db_dns_out.get("SERIAL") + List_db_dns_out.get(
                            "REFRESH") + List_db_dns_out.get("RETRY") \
                                                 + List_db_dns_out.get("EXPIRE") + List_db_dns_out.get("MINIMUM")
                        Rdlend(List_db_dns_out["SOA"], List_db_dns_out_1)
                        List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                    + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                    + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get("SOA")
                    else:
                        pass
                else:
                    pass

        infile.close()
        message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") \
                             + List_db_dns_out.get("QDCOUNT") + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get(
            "NSCOUNT") \
                             + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get(
            "QTYPE") \
                             + List_db_dns_out.get("QCLASS") + List_db_dns_out_1.get("DATA")

    else:
        message_db_dns_out = answer_no_name(List_db_dns_out, List_db_dns_out_1)  # print("error") # answer SOA

        #  print(message_db_dns_out)
    return message_db_dns_out


def answer_TXT(requst, List_db_dns_out, List_db_dns_out_1):
    #  List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ARCOUNT"] = "0000"
    List_db_dns_out["NSCOUNT"] = "0000"  # numba write name servis available
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))

    List_db_dns_out["NAME"] = "c00c"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0010"  # txt(16)
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    fin_end = 0
    if os.path.isfile(os.path.abspath('./Records/TXT.txt')):
        infile = open(os.path.abspath('./Records/TXT.txt'), 'r')
        with infile as fil:
            for line in fil:
                if line.startswith('TXT_record'):
                    r = re.compile(r'TXT_record =(.*)#(.*)')
                    sep = r.search(line)
                    if str(str2hex(sep.group(1)))[2:-1] == requst.NAME:
                        r1 = re.compile(r'TXT_count =(.*)#(.*)')
                        sep1 = r1.search(fil.readline())
                        if sep1.group(1).startswith("1"):
                            # print("yes")
                            r2 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep2 = r2.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep2.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                        + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            List_db_dns_out["ANCOUNT"] = "0001"
                            fin_end = 1
                        elif sep1.group(1).startswith("2"):
                            r2 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep2 = r2.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep2.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                        + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r3 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep3 = r3.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep3.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            List_db_dns_out["ANCOUNT"] = "0002"
                            fin_end = 1
                        elif sep1.group(1).startswith("3"):
                            r2 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep2 = r2.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep2.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                        + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r3 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep3 = r3.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep3.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r4 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep4 = r4.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep4.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            List_db_dns_out["ANCOUNT"] = "0003"
                            fin_end = 1
                        elif sep1.group(1).startswith("4"):
                            r2 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep2 = r2.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep2.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                        + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r3 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep3 = r3.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep3.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r4 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep4 = r4.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep4.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            r5 = re.compile(r'TXT_DATA =(.*)#(.*)')
                            sep5 = r5.search(fil.readline())
                            List_db_dns_out["TXT_DATA"] = str(str2hex(sep5.group(1)))[2:-1]
                            Rdlend(List_db_dns_out["TXT_DATA"], List_db_dns_out_1)
                            List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                        + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                "CLASS") + List_db_dns_out.get("TTL") \
                                                        + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                "TXT_DATA")
                            List_db_dns_out["ANCOUNT"] = "0004"
                            fin_end = 1
                        else:
                            pass
                    else:
                        pass
                else:
                    pass

        infile.close()
        if fin_end == 1:
            message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") \
                                 + List_db_dns_out.get("QDCOUNT") + List_db_dns_out.get("ANCOUNT") \
                                 + List_db_dns_out.get("NSCOUNT") + List_db_dns_out.get("ARCOUNT") \
                                 + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                                 + List_db_dns_out.get("QCLASS") + List_db_dns_out_1.get("DATA")
        else:
            message_db_dns_out = answer_no_name(List_db_dns_out, List_db_dns_out_1)
    else:
        message_db_dns_out = answer_no_name(List_db_dns_out, List_db_dns_out_1)  # #print("error") # answer SOA

    # print(message_db_dns_out)
    return message_db_dns_out


def answer_NS(requst, List_db_dns_out, List_db_dns_out_1):
    #  List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ARCOUNT"] = "0000"
    List_db_dns_out["NSCOUNT"] = "0000"  # numba write name servis available
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))

    List_db_dns_out["NAME"] = "c00c"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0002"  # ns(2)
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    fin_end = 0
    if os.path.isfile(os.path.abspath('./Records/NS.txt')):
        infile = open(os.path.abspath('./Records/NS.txt'), 'r')
        with infile as fil:
            for line in fil:
                if line.startswith('NS record'):
                    r = re.compile(r'NS record =(.*)#(.*)')
                    sep = r.search(line)
                    if requst.NAME is None:
                        pass
                    else:
                        NS_record = "*.dynhost.ml"
                        if str(str2hex(sep.group(1)))[2:-1] == str(str2hex(NS_record))[2:-1] \
                                or str(str2hex(sep.group(1)))[2:-1] == requst.NAME:
                            r1 = re.compile(r'NS_count =(.*)#(.*)')
                            sep1 = r1.search(fil.readline())
                            if sep1.group(1).startswith("1"):
                                r2 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep2 = r2.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep2.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                            + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                List_db_dns_out["ANCOUNT"] = "0001"
                                fin_end = 1
                            elif sep1.group(1).startswith("2"):
                                r2 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep2 = r2.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep2.group(1)))[2:-1] + "00"
                                # print(List_db_dns_out["NS_DATA"])
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                            + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r3 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep3 = r3.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep3.group(1)))[2:-1] + "00"
                                # print(List_db_dns_out["NS_DATA"])
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                List_db_dns_out["ANCOUNT"] = "0002"
                                fin_end = 1
                            elif sep1.group(1).startswith("3"):
                                r2 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep2 = r2.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep2.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                            + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r3 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep3 = r3.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep3.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r4 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep4 = r4.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep4.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                List_db_dns_out["ANCOUNT"] = "0003"
                                fin_end = 1
                            elif sep1.group(1).startswith("4"):
                                r2 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep2 = r2.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep2.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                                                            + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r3 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep3 = r3.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep3.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r4 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep4 = r4.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep4.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                r5 = re.compile(r'NS_DATA =(.*)#(.*)')
                                sep5 = r5.search(fil.readline())
                                List_db_dns_out["NS_DATA"] = str(str2hex(sep5.group(1)))[2:-1] + "00"
                                Rdlend(List_db_dns_out["NS_DATA"], List_db_dns_out_1)
                                List_db_dns_out_1["DATA"] = List_db_dns_out_1["DATA"] + List_db_dns_out.get("NAME") \
                                                            + List_db_dns_out.get("TYPE") + List_db_dns_out.get(
                                    "CLASS") + List_db_dns_out.get("TTL") \
                                                            + List_db_dns_out_1.get("RDLENGTH") + List_db_dns_out.get(
                                    "NS_DATA")
                                List_db_dns_out["ANCOUNT"] = "0004"
                                fin_end = 1
                            else:
                                pass
                        else:
                            pass

                else:
                    pass

        infile.close()
        if fin_end == 1:
            message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") \
                                 + List_db_dns_out.get("QDCOUNT") + List_db_dns_out.get("ANCOUNT") \
                                 + List_db_dns_out.get("NSCOUNT") + List_db_dns_out.get("ARCOUNT") \
                                 + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                                 + List_db_dns_out.get("QCLASS") + List_db_dns_out_1.get("DATA")
        else:

            message_db_dns_out = answer_no_name(List_db_dns_out, List_db_dns_out_1)
    else:
        message_db_dns_out = answer_no_name(List_db_dns_out, List_db_dns_out_1)  # print("error") # answer SOA

        #  print(message_db_dns_out)
    return message_db_dns_out


def DB_DNS_in(in_message, Session, lock):
    # distionary incoming message
    #
    session = Session()
    List_db_dns_in = {}
    List_db_dns_in["ID"] = in_message[0:4]
    id4 = ("{0:4b}".format(int(in_message[4:5], 16)) + "{0:4b}".format(int(in_message[5:6], 16)) +
           '{0:4b}'.format(int(in_message[6:7], 16)) + '{0:4b}'.format(int(in_message[7:8], 16)))

    i = 0
    id4_1 = {}
    while i <= 15:
        if id4[i] == "1":
            id4_1[i] = "1"
        else:
            id4_1[i] = "0"
        i = i + 1

    List_db_dns_in["QR"] = id4_1[0]
    List_db_dns_in["OPCODE"] = id4_1[1] + id4_1[2] + id4_1[3] + id4_1[4]
    List_db_dns_in["AA"] = id4_1[5]
    List_db_dns_in["TC"] = id4_1[6]
    List_db_dns_in["RD"] = id4_1[7]
    List_db_dns_in["RA"] = id4_1[8]
    List_db_dns_in["Z"] = id4_1[9] + id4_1[10] + id4_1[11]
    List_db_dns_in["RCODE"] = id4_1[12] + id4_1[13] + id4_1[14] + id4_1[15]
    List_db_dns_in["QDCOUNT"] = in_message[8:12]
    List_db_dns_in["ANCOUNT"] = in_message[12:16]
    List_db_dns_in["NSCOUNT"] = in_message[16:20]
    List_db_dns_in["ARCOUNT"] = in_message[20:24]

    # ("Syn_dns_out")
    if List_db_dns_in["ID"] == "F5F5" or List_db_dns_in["ID"] == "f5f5" and in_message[4:12] == "01000001":
        data_up = binascii.hexlify(bytes(str.encode(json.dumps(UPDATE_DYNDNS_start(session)))))
        len_up = len(data_up)
        n = (len_up / 1000) + 1  # 1000 hex byt len udp data
        i = 1
        data_updat = {}
        start = 0
        stop = 1000  # udp len
        while n >= i:
            data_updat[i] = data_up[start:stop]
            start = stop
            stop = stop + 1000
            # F5F5 id + ""0001""-i + ""0005""-n +""03E8""- len(1000) + ""data""- data_updat[i]
            message = bytes(str.encode("F5F5") + bytes(str.encode(INlend(i))) + bytes(str.encode(INlend(int(n))))
                            + bytes(str.encode(INlend(len(data_updat[i]))) + data_updat[i]))
            server_address = (host_DNS2, port_DNS)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(binascii.unhexlify(message), server_address)
                sock.settimeout(10)  # time answer c
                data, _ = sock.recvfrom(1024)
            except socket.error:
                sock.close()
            else:
                sock.close()
                in_message_dns = binascii.hexlify(data).decode("utf-8")
                str_pak = int(in_message_dns[4:8], 16)
                if str_pak == i:
                    i = i + 1
                else:
                    i = i + 1

    # ("Syn_dns_in")
    elif List_db_dns_in["ID"] == "F5F5" or List_db_dns_in["ID"] == "f5f5":

        str_pak = in_message[4:8]
        stop_pak = in_message[8:12]
        len_pak = in_message[12:16]
        data_pak = in_message[16:]

        if len(data_pak) == int(len_pak, 16):
            str_pak_nest = int(str_pak, 16) + int(1)
            message_db_dns_out_f = 'F5F5' + str(INlend(str_pak_nest)) + str(
                stop_pak) + "0000000000000764796e686f7374026d6c0000010001"
            lock.acquire()
            shelfFile = shelve.open('SYN_DNS_DB')
            message_in = in_message[16:]
            shelfFile[str(int(str_pak, 16))] = message_in
            if (len(shelfFile)) == int(stop_pak, 16):
                i = 1
                update_dns = list()
                while int(stop_pak, 16) >= i:
                    update_dns = update_dns + list(shelfFile.setdefault(str(i)))
                    i = i + 1


                syn_update_dns = ''.join(update_dns)
                shelfFile.clear()
                shelfFile.close()
                lock.release()
                UPDATE_DYNDNS_finish(json.loads((str(binascii.unhexlify(syn_update_dns)))[2:-1]), session, lock)
            else:
                shelfFile.close()
                lock.release()


        else:
            message_db_dns_out_f = 'F5F5' + str(str_pak) + str(
                stop_pak) + "0000000000000764796e686f7374026d6c0000010001"

        return message_db_dns_out_f

    else:
        pass

    if List_db_dns_in["Z"] != "000":
        List_db_dns_in["AD"] = List_db_dns_in["Z"][1]
        List_db_dns_in["CD"] = List_db_dns_in["Z"][2]
    else:
        List_db_dns_in["AD"] = "0"
        List_db_dns_in["CD"] = "0"
    i = (int((in_message[24:26]), 16))
    y = i

    while True:
        if (in_message[(26 + y * 2):(28 + y * 2)]) == "00":
            z = y
            List_db_dns_in["QNAME"] = in_message[24:28 + y * 2]
            break
        else:
            i = (int((in_message[(26 + y * 2):(28 + y * 2)]), 16))
            y = y + i + 1

    List_db_dns_in["QTYPE"] = in_message[(28 + z * 2):(32 + z * 2)]
    List_db_dns_in["QCLASS"] = in_message[(32 + z * 2):(36 + z * 2)]
    List_db_dns_in["List_db_dns_in"] = in_message
    l = (int((List_db_dns_in.get("QNAME")[0:2]), 16))
    qname = (List_db_dns_in.get("QNAME")[2: 2 + l * 2])
    while True:
        if (List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
            break
        else:
            m = int(List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
            qname = qname + "2e" + (List_db_dns_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
            l = l + m + 1
    List_db_dns_out = {}
    List_db_dns_out_1 = {}
    List_db_dns_out["ID"] = List_db_dns_in["ID"]
    List_db_dns_out["QR"] = "1"  # 0-requst , 1 answer
    List_db_dns_out["OPCODE"] = List_db_dns_in["OPCODE"]  # 0- standart requst and variant
    List_db_dns_out["AA"] = List_db_dns_out["AA"] = "1"  # Code answer authoritarian DNS server
    List_db_dns_out["TC"] = List_db_dns_in["TC"]  # TrunCation
    List_db_dns_out["RD"] = "0"  # Recursion
    List_db_dns_out["RA"] = "0"  # Recursion Available
    List_db_dns_out["Z"] = List_db_dns_in["Z"]  # Reservation
    List_db_dns_out["QDCOUNT"] = List_db_dns_in["QDCOUNT"]  # 1-requst
    List_db_dns_out["NSCOUNT"] = List_db_dns_in["NSCOUNT"]  # numba write name servis available  #default 0000
    List_db_dns_out["ARCOUNT"] = List_db_dns_in["ARCOUNT"]  # numba write recurs additionally
    List_db_dns_out["QNAME"] = List_db_dns_in["QNAME"]
    List_db_dns_out["QTYPE"] = List_db_dns_in["QTYPE"]
    List_db_dns_out["QCLASS"] = List_db_dns_in["QCLASS"]

    requst = session.query(DynDNS).filter(DynDNS.NAME == qname).first()
    if List_db_dns_in["QTYPE"] == "0001":  # A format
        if qname == Qname(host_name):
            List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)  good
            message_db_dns_out_f = answer_A_host_name(session, requst, List_db_dns_out)  # yes host_name
        else :
            if requst is not None:
                if requst.Time_stop == "millenium":
                    List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) good
                    message_db_dns_out_f = answer_A_name(requst, List_db_dns_out)  # yes A
                else:
                    if float(requst.Time_stop) >= time.time():
                        List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) good
                        message_db_dns_out_f = answer_A_name(requst, List_db_dns_out)  # yes A
                    else:
                        List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
                        message_db_dns_out_f = answer_no_name_millenium(List_db_dns_out)  # no A

            else:
                List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15)  NXDomain (3)
                message_db_dns_out_f = answer_no_name(List_db_dns_out, List_db_dns_out_1)  # no A



    elif List_db_dns_in["QTYPE"] == "0110":  # SOA format
        if requst is not None:
            List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) good
            message_db_dns_out_f = answer_SOA(requst, List_db_dns_out, List_db_dns_out_1)
        else:
            List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15)  NXDomain (3)
            message_db_dns_out_f = answer_no_name(List_db_dns_out, List_db_dns_out_1)


    elif List_db_dns_in["QTYPE"] == "0010":  # TXT format
        if requst is not None:
            List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) good
            message_db_dns_out_f = answer_TXT(requst, List_db_dns_out, List_db_dns_out_1)
        else:
            List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15)  NXDomain (3)
            message_db_dns_out_f = answer_no_name(List_db_dns_out, List_db_dns_out_1)

    elif List_db_dns_in["QTYPE"] == "0002":  # NS format
        if requst is not None:
            List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15) good
            message_db_dns_out_f = answer_NS(requst, List_db_dns_out, List_db_dns_out_1)
        else:
            List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15)  NXDomain (3)
            message_db_dns_out_f = answer_no_name(List_db_dns_out, List_db_dns_out_1)

    else:
        List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15)  NXDomain (3)
        message_db_dns_out_f = answer_no_name(List_db_dns_out, List_db_dns_out_1)

    session.commit()
    session.close()
    return message_db_dns_out_f

