#!/usr/bin/env python

import socket
import time

conn1 = socket.socket()
conn1.connect( ("127.0.0.1", 2003) )

conn2 = socket.socket()
conn2.connect( ("127.0.0.1", 2003) )

conn1.send(b"test.a1 1 1602515799\n")
conn1.send(b"test.a2 1 ")
time.sleep(1)
conn1.send(b"1602515799\ntest.a3 3 1602515799\n")

conn2.send(b"test.a4 4 1602515799\n")

conn1.close()
conn2.close()
