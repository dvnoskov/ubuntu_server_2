import socket
import time
import selectors
import queue
from threading import Thread
import concurrent.futures
import logging.handlers

from config import port_DYN_DNS, host_DNS, max_pool_ser, max_queue_ser
import libserver_dyn_dns



def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    conn.setblocking(False)
    message = libserver_dyn_dns.Message(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ, data=message)


if __name__ == '__main__':
    sel = selectors.DefaultSelector()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host_DNS, port_DYN_DNS))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    concurrent.futures.ThreadPoolExecutor(max_workers=max_pool_ser)
    pipeline = queue.Queue(maxsize=max_queue_ser)

    loger = logging.getLogger()
    loger.setLevel(logging.DEBUG)
    h = logging.handlers.RotatingFileHandler("listen_dyn_dns_log.out", 300, 10)
    loger.addHandler(h)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    p = Thread(target=accept_wrapper(key.fileobj), args=pipeline)
                    p.start()

                else:
                    message = key.data
                    try:
                        message.process_events(mask)
                    except Exception:
                        loger.debug("incoming message :" + str(message) + time.ctime())
                        loger.debug(logging.exception(IndexError))
                        message.close()

    finally:
        sel.close()
