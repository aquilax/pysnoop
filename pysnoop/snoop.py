# config=utf8
import sys
from urllib import unquote
from socket import *
from cgi import parse_qs
import re

def udec(match):
  return unichr(int('0x'+match.group(1), 16)).encode('utf8')
  
def unifix(self,text):
  p = re.compile('%u([\dABCDEF]{4})')  
  return p.sub(udec, text)

class TSnoop:

  host = '64.207.133.96'
  port = 8080

  def __init__(self, user, passw):
    self.s = socket(AF_INET, SOCK_STREAM)
    self.user = user
    self.passw = passw
    self.status = ''
    self.events = {}
  
  def bind(self, name, func):
    self.events[name] = func

  def event(self, name, val):
    if self.events.has_key(name):
      func = self.events[name]
      return func(val)
    else:
      return 0

  def connect(self):
    print "Connecting server",self.host,"port",self.port
    try:
      self.s.connect((self.host, self.port))
      self.event('connected', None);
    except: 
      raise RuntimeError, "Connection refused"

  def generateLogin(self):
    res = self.event('onAuthorize', None)
    if res == 0:
      return "password="+self.passw+"&username="+self.user+"\r\n"
    else:
      (u, p) = res
      return "password="+u+"&username="+p+"\r\n"

  def parseHash(self, data):
    ary = parse_qs(data)
    self.event('listsites', ary)
    if ary.has_key('hash0'):
      self.hash = ary['hash0'][0]
      return self.hash
    else:
      return '';

  def processData(self, data):
    ary = self.parseResp(data);  
    if self.status == 'init':
      if self.getVal(ary, 'client') == 'ok':
        self.status = 'authorize'
        return self.generateLogin()
      else: 
        raise RuntimeError, "Service not available"
    if self.status == 'authorize':
      if self.getVal(ary, 'auth') == 'ok':
        self.status = 'authorized'
        return "manifest\r\n"
      else:
        raise RuntimeError, "Not authorized"
    if self.status == 'authorized':
      self.hash = self.getVal(ary, 'hash0')
      if self.hash != '':
        self.status = 'finished';
        return 'snoop='+self.hash+"\r\n"
      else:
        raise RuntimeError, "No hash received"
    if self.status == 'finished':
      if self.getVal(ary, 'ses') != '':
        self.event('onVisitor', data)
    return '';
  
  def stop(self):
    print "closing..."
    self.s.send('stop\r\n')
    
  def parseResp(self, data):
    return parse_qs(data);
  
  def getVal(self, ary, name):
    if ary.has_key(name):
      return ary[name][0]
    else:
      return ''

  def run(self):
    #Init Communication
    self.s.send('client\r\n')
    self.status = 'init'
    data = '';
    while 1:
      char = self.s.recv(1)
      if char == '\n':
        resp = self.processData(data)
        if resp != '':
          #print "<<"+resp
          self.s.send(resp)
        data = '';
      else:
        data += char
    self.s.close
