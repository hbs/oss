#!/usr/bin/env python -u
#
# Proxy for the SSH Agent
#
# Proxying can be done on stdin/stdout (which must be unbuffered, therefore we use -u)
# which can be connected to named pipes which can be specified in juds.in and juds.out.
# This is the recommended way of proxying the SSH Agent on platforms on which JUDS
# cannot be easily compiled.
#
# An unsecure way of proxying the SSH Agent using TCP/IP socket is also provided. This
# is NOT recommended as anyone with access to the local machine will then be able to
# talk to the agent and use the private key. This is solely provided as a solution when
# all others cannot be used.
#
# Copyright 2012-2013 Mathias Herberts 
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#


import threading
import select
import socket
import os
import sys


backlog = 16
port = None

infd = None
outfd = None

try:
  if len(sys.argv) > 1:
    port = int(sys.argv[1])

  if len(sys.argv) > 2:
    backlog = int(sys.argv[2])
except ValueError:
  if len(sys.argv) > 2:
    infd = os.open(sys.argv[1], os.O_RDONLY|os.O_NONBLOCK)
    outfd = os.open(sys.argv[2], os.O_WRONLY)

class AgentProxy(threading.Thread):
  def __init__(self, instream, outstream):
    self.instream = instream
    self.outstream = outstream

  def run(self):
    proxy()

  def proxy(self):
    #
    # Connect to Unix Domain Socket in stream mode
    #

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.setblocking(0)
    s.connect(os.environ['SSH_AUTH_SOCK'])

    #
    #
    #

    while True:
      r, w, x = select.select([self.instream,s], [], [self.instream,s], 0.001)
      if x:
        return
      if self.instream in r:
        if 'read' in dir(self.instream):
          buf = self.instream.read(1024)
        elif 'recv' in dir(self.instream):
          buf = self.instream.recv(1024)
        else:
          buf = os.read(self.instream, 1024)
        if not buf:
          return
        if len(buf) > 0:
          s.sendall(buf)
      if s in r:
        buf = s.recv(1024)
        if not buf:
          return
        if len(buf) > 0:
          if 'write' in dir(self.outstream):
            self.outstream.write(buf)
            self.outstream.flush()
          elif 'sendall' in dir(self.outstream):
            self.outstream.sendall(buf)
          else:
            os.write(self.outstream, buf)

#
# Bind to address/port
#

if port:
  netsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  netsock.bind(('127.0.0.1', port))
  netsock.listen(backlog)

  while True:
    (clientsocket, address) = netsock.accept()
    proxy = AgentProxy(clientsocket, clientsocket)
    proxy.run()
else:
  if infd and outfd:
    AgentProxy(infd,outfd).proxy()
  else:
    AgentProxy(sys.stdin,sys.stdout).proxy()
