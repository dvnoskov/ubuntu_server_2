#-------------------------------------------------------------------
# v02.2020
# authoritarian DNS server
# libs s_libs_server_DNS
# syn DNS_DB
#--------------------------------------------------------------------
import socket
import binascii
from s_libs_server_DNS import DB_DNS_in
import time
from config import port_DNS,host_DNS,max_pool,max_queue
#import multiprocessing
import logging.handlers
from threading import Thread
import threading
import concurrent.futures
import queue
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import route_DB


def worker(address,Session):
   # start_time = time.time()
    UDPServerSocket.sendto(binascii.unhexlify(DB_DNS_in(in_message,Session,lock)), address)
   # duration = time.time() - start_time
  #  print("answear message :", clientIP,"Working in ",duration," seconds")
    return

if __name__ == '__main__':
    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPServerSocket.bind((host_DNS, port_DNS))
  #  print("UDP server up and listening",host_DNS)
    concurrent.futures.ThreadPoolExecutor(max_workers=max_pool)
    pipeline = queue.Queue(maxsize=max_queue)
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    lock = threading.Lock()

    loger = logging.getLogger()
    loger.setLevel(logging.DEBUG)
    h = logging.handlers.RotatingFileHandler("listen_dns_log.out", 300, 10)
    loger.addHandler(h)

    while (True):

       try:

           data = UDPServerSocket.recvfrom(1024)
           in_message = binascii.hexlify(data[0]).decode("utf-8")
           address = data[1]
       #    print(in_message)
           clientIP = "Client IP Address:{}".format(address)
        #   print("incoming message :", clientIP)
         #  p = multiprocessing.Process(target=worker(address))
           p = Thread(target=worker(address,Session), args=pipeline)
           p.start()
       except :
          loger.debug("incoming message :" + str(clientIP)+time.ctime() )
          loger.debug(logging.exception(IndexError))#work

       finally:
           pass


