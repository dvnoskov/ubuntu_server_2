import selectors
import urllib.parse
import binascii
import base64
import json
import time
import threading
import re
import logging.handlers
import queue
import concurrent.futures
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from threading import Thread
from config import max_pool, max_queue, route_DB
from cr_dyndns_db import DynDNS, User


class Message:
    def __init__(self, selector, sock, addr):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self._jsonheader_len = None
        self.jsonheader = None
        self.request = None
        self.response_created = False
        self.methold = None
        self.path = None
        self.version_http = None
        self.headers = None
        self.body = None
        self.header_out = None
        self.body_out = None
        self.send_response = None
        self.request_line = None
        self.loger = logging.getLogger()
        self.loger.setLevel(logging.DEBUG)
        concurrent.futures.ThreadPoolExecutor(max_workers=max_pool)
        self.pipeline = queue.Queue(maxsize=max_queue)


    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError("Invalid events mask mode {repr(mode)}.")

        self.selector.modify(self.sock, events, data=self)


    def _read(self):   #3
        try:
            # Should be ready to read
            data = self.sock.recv(1024)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")



    def _write(self):   #11
        if self._send_buffer:
       #     print("sending", repr(self._send_buffer), "to", self.addr)
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]
                # Close when the buffer is drained. The response has been sent.
                if sent and not self._send_buffer:
                    self.close()



    def _create_response_content(self):
        self.header_out += "Content-Type" + ":" + "text/html" + "\r\n" + 'Server' + ":" + 'HTTP_v.1 Python/3.5.3' + \
            "\r\n" + 'Date' + ":" + time.ctime() + "\r\n\r\n"
        response = self.version_http + " " + self.send_response + "\r\n" + self.header_out + self.body_out
        respo = response.encode("utf-8")   # default
        return respo



    def _create_response_content_no(self):
        self.header_out += "Content-Type" + ":" + "text/html" + "\r\n" + 'Server' + ":" + 'HTTP_v.1 Python/3.5.3' + \
            "\r\n" + 'Date' + ":" + time.ctime() + "\r\n\r\n"
        response = self.version_http + " " + self.send_response + "\r\n" + self.header_out
        respo = response.encode("utf-8")   # default
        return respo



    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()


    def read(self):
        self._read()

        if self._jsonheader_len is None:
            self.process_protoheader()

        if self.jsonheader is None:
                self.process_request()



    def write(self):
        if self.request:
            if not self.response_created:
                self.create_response()

        if self.request:
            if self.response_created:
                if self._send_buffer:
                    p1 = Thread(target=self._write(), args=self.pipeline)
                    p1.start()


    def close(self):
    #    print("closing connection to", self.addr)
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            self.loger.debug("error: selector.unregister() exception for" + self.addr + time.ctime())
            self.loger.debug(logging.exception(Exception))

        try:
            self.sock.close()
        except OSError as e:
            self.loger.debug("error: socket.close() exception for" + self.addr + time.ctime())
            self.loger.debug(logging.exception(OSError))
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None


    def process_protoheader(self):
        hdrlen = 2
        if len(self._recv_buffer) >= hdrlen:
            self._recv_buffer = self._recv_buffer
            data = self._recv_buffer
            req = str(data)
            str_head_body = req.split("\\r\\n\\r\\n")
            str_hed = str_head_body[0].split("\\r\\n")
            str_line = str_hed[0][2:].split(" ")
            if ((re.compile(r'.?').search(str_line[1])).group(0)) == "/":
                str_line_path = str_line[1].split("?")
            else:
                str_line_path = str_line[1]

            self.methold = str_line[0]
            self.path = str_line_path[0]
            self.request_line = str_line_path
            self.version_http = str_line[2]

            heade = {}
            start_heade = 0
            while True:
                if start_heade <= len(str_hed[1:]) - 1:
                    heade[(str_hed[1:][start_heade][0:(str_hed[1:][start_heade]).find(":")])] = (\
                    str_hed[1:][start_heade][(str_hed[1:][start_heade]).find(":") + 1:])
                    start_heade = start_heade + 1
                else:
                    break

            self.headers = heade
            if len(str_head_body[1]) >= hdrlen:
                if self.headers['Content-Type'] == 'text/html':
                    if not len(str_head_body[1]) >= len(self.headers['Content-Length']):
                        return
                    else:
                        self.body = str_head_body[1]
                        self.request = self.body
            else:
                self.request = self.path



    def process_request(self):
        if self.request != self.path or self.version_http != "HTTP/1.1":
            self.do_POST()
        else:
            if self.methold == "GET":
                self.do_GET()
            elif self.methold == "POST":
                self.do_POST()
            elif self.methold == "HEAD":
                self.do_POST()
            else:
                self.do_POST()


    def create_response(self):

        if len(self.body_out) >= 2:
            response = self._create_response_content()
        else:
            response = self._create_response_content_no()

        message = response
        self.response_created = True
        self._send_buffer += message



    def str2hex(self):
        return binascii.hexlify(bytes(str.encode()))

#
    def UPDATE_DYNDNS(self, incom):
        if incom == "ip":
            query = self.session.query(DynDNS)
            update = {}
            while True:

                work = query.filter(DynDNS.STATUS == 'USER').count()
                if work >= 1:
                    menu = self.session.query(DynDNS).filter(DynDNS.STATUS == 'USER').first()
                    work_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
                    a1 = (int(menu.RDATA[0:2], 16))
                    a2 = (int(menu.RDATA[2:4], 16))
                    a3 = (int(menu.RDATA[4:6], 16))
                    a4 = (int(menu.RDATA[6:8], 16))
                    ip = str(a1) + "." + str(a2) + "." + str(a3) + "." + str(a4)
                    update[((binascii.unhexlify(menu.NAME)).decode('utf-8'))] = ip  #
                    work_no.update({DynDNS.STATUS: ("SYN")})
                    self.session.commit()

                else:
                    break

            sys = query.filter(DynDNS.STATUS == 'SYN')
            sys.update({DynDNS.STATUS: ("USER")})
            self.stop_DB()

        elif incom == "time":
            query = self.session.query(DynDNS)
            update = {}
            while True:

                work = query.filter(DynDNS.STATUS == 'USER').count()
                if work >= 1:
                    menu = self.session.query(DynDNS).filter(DynDNS.STATUS == 'USER').first()
                    work_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
                    if menu.Time_stop == "millenium":
                        update[((binascii.unhexlify(menu.NAME)).decode('utf-8'))] = menu.Time_stop  #
                        work_no.update({DynDNS.STATUS: ("SYN")})
                        self.session.commit()
                    else:
                       # update[((binascii.unhexlify(menu.NAME)).decode('utf-8'))] = time.ctime(float(menu.Time_stop))  #
                        update[((binascii.unhexlify(menu.NAME)).decode('utf-8'))] = time.strftime("%d-%m-%Y",\
                                time.localtime(float(menu.Time_stop)))  #
                        work_no.update({DynDNS.STATUS: ("SYN")})
                        self.session.commit()



                else:
                    break

            sys = query.filter(DynDNS.STATUS == 'SYN')
            sys.update({DynDNS.STATUS: ("USER")})
            self.stop_DB()


        return update


    def stop_DB(self):
        self.session.commit()
        self.session.close()


    def do_HEAD(self):
        self._set_selector_events_mask("w")


    def do_AUTHHEAD(self):
        self.send_response = "401 OK"
        text = "badauth"
        self.body_out = text
        self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                          'WWW-Authenticate' + ":" + 'Basic realm="DynDNS API Access' + "\r\n" + 'Content-Length'\
                          + ":" + str(len(text)) + "\r\n"
        self.do_HEAD()


    def do_POST(self):
        self.send_response = "200 OK"
        text = "badagent"
        self.body_out = text
        self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                           'Content-Length' + ":" + str(len(text)) + "\r\n"
        self.do_HEAD()


    def do_GET(self):
        engine = create_engine(route_DB)
        self.Session = sessionmaker(bind=engine)
        self.session = self.Session()
        self.Base = declarative_base()
        if self.headers["Host"] == " dimon49.ml" or self.headers["Host"] == " members.dyndns.org" \
                or self.headers["Host"] == " 193.254.196.206" or self.headers["Host"] == " 192.168.1.144":
                                                                   # "_xxxxxxxx' example " 127.0.0.1:65432"

            if self.path == "/nic/update":
                if self.headers['Authorization'] == None:
                    self.do_AUTHHEAD()
                else:
                    if self.headers.get('Authorization')[0:7] == ' Basic ':
                        self.do_Authorization()
                    else:
                        self.do_AUTHHEAD()


            elif self.path == "/nic/test":
                self.send_response = "200 OK"
                text = "work"
                self.body_out = text
                self.header_out = "Content-Encoding"+":"+ "utf-8"+"\r\n"+'Pragma'+":"+ 'no-cache'+"\r\n"+\
                    'Cache-Control'+":"+'no-cache'+"\r\n"+'Content-Length'+":"+ str(len(text))+"\r\n"
                self.do_HEAD()

            elif self.path == "/nic/ip":
                self.send_response = "200 OK"
                text = " Ip adress :"+self.addr[0]
                self.body_out = text
                self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'Pragma' + ":" + 'no-cache' + "\r\n" + \
                    'Cache-Control' + ":" + 'no-cache' + "\r\n" + 'Content-Length' + ":" + str(len(text)) + "\r\n"
                self.do_HEAD()

            elif self.path == "/nic/status":
                self.send_response = "200 OK"
                text = json.dumps(self.UPDATE_DYNDNS("ip"))
                self.body_out = text
                self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'Pragma' + ":" + 'no-cache' + "\r\n" + \
                    'Cache-Control' + ":" + 'no-cache' + "\r\n" + 'Content-Length' + ":"\
                                  + str(len(text)) + "\r\n"
                self.do_HEAD()

            elif self.path == "/nic/time":
                self.send_response = "200 OK"
                text = json.dumps(self.UPDATE_DYNDNS("time"))
                self.body_out = text
                self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'Pragma' + ":" + 'no-cache' + "\r\n" + \
                    'Cache-Control' + ":" + 'no-cache' + "\r\n" + 'Content-Length' + ":"\
                                  + str(len(text)) + "\r\n"
                self.do_HEAD()

            else:
                self.send_response = "404 OK" # no route
                text = "404 "
                self.body_out = text
                self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'X' + "\r\n" + \
                    'Content-Length' + ":" + str(len(text)) + "\r\n"
                self.do_HEAD()

        else:
            self.send_response = "404 OK" # no route
            text = "404 "
            self.body_out = text
            self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'X' + "\r\n" + \
                'Content-Length' + ":" + str(len(text)) + "\r\n"
            self.do_HEAD()


    def do_Authorization(self):
        aut_in = (base64.b64decode((self.headers["Authorization"][7:])).decode('utf-8'))
        autoriz = aut_in.split(":")
        self.user = autoriz[0]
        login = autoriz[1]
        query = self.session.query(User)
        filt0 = query.filter(User.username == self.user or User.password == login).first()
        if filt0 is None:
            self.stop_DB()
            self.do_AUTHHEAD()
        else:
            filt1 = query.filter(User.password == login or User.username == self.user).first()
            if filt1 is None:
                self.stop_DB()
                self.do_AUTHHEAD()
            else:
                self.stop_DB()
                self.do_Requst_get()


    def do_Requst_get(self):
        if self.user != "admin":
            requestline = self.request_line[1]
            parse = dict(urllib.parse.parse_qsl(qs=requestline, keep_blank_values=True))
            for k in parse.keys():
                if ("".join(re.compile(r'myip').findall(k))) == "myip":
                    myip_in_parse = parse.get(k)
                    if myip_in_parse == "":
                        myip_in = self.addr[0]
                    else:
                        myip_in = myip_in_parse.split(" ")[0]

                elif ("".join(re.compile(r'hostname').findall(k))) == "hostname":
                    homename_in = parse.get(k)
                    homnam_in = homename_in.split(" ")[0]

                else:
                    pass


            ip = myip_in.split(".")
            s = [int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])]
            rdata_in = str(binascii.hexlify(bytes(bytearray(s))))[2:10]
            homenam_in = (binascii.hexlify(bytes(str.encode(homnam_in)))).decode('utf-8')
            query = self.session.query(DynDNS)
            filt2 = query.filter(
                DynDNS.NAME == homenam_in or DynDNS.USER == self.user and DynDNS.RDATA == rdata_in).first()
            if filt2 is None:
                self.stop_DB()
                self.send_response = "200 OK"
                text = "dnserr"
                self.body_out = text
                self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                    'Content-Length' + ":" + str(len(text)) + "\r\n"
                self.do_HEAD()
            else:
                filt3 = query.filter(
                    DynDNS.USER == self.user or DynDNS.NAME == homenam_in and DynDNS.RDATA == rdata_in).first()
                if filt3 is None:
                    self.stop_DB()
                    self.send_response = "200 OK"
                    text = "nohost"
                    self.body_out = text
                    self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                        'Content-Length' + ":" + str(len(text)) + "\r\n"
                    self.do_HEAD()
                else:
                    filt4 = query.filter(
                        DynDNS.USER == self.user or DynDNS.RDATA == rdata_in and DynDNS.NAME == homenam_in).first()
                    if filt4 is None:
                        self._lock = threading.Lock()
                        self._lock.acquire()
                        filt5 = query.filter(DynDNS.USER == self.user, DynDNS.NAME == homenam_in)
                        filt5.update({DynDNS.RDATA: rdata_in})
                        self._lock.release()
                        self.stop_DB()
                        self.send_response = "200 OK"
                        text = "good   " + str(myip_in)
                        self.body_out = text
                        self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                            'Content-Length' + ":" + str(len(text)) + "\r\n"
                        self.do_HEAD()
                    else:
                        self.stop_DB()
                        self.send_response = "200 OK"
                        text = "nochg"
                        self.body_out = text
                        self.header_out = "Content-Encoding" + ":" + "utf-8" + "\r\n" + 'X-UpdateCode' + ":" + 'A' + "\r\n" + \
                            'Content-Length' + ":" + str(len(text)) + "\r\n"
                        self.do_HEAD()

        else:
            self.do_AUTHHEAD()

