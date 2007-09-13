from snoop import TSnoop

#Config
user = ''   #username
passw = ''  #password

def onVisitor(data):
  ary = parse_qs(data)
  if ary.has_key('title'):
    print ary['title'][0]

Snoop = TSnoop(user, passw);
Snoop.bind('onVisitor', onVisitor)
Snoop.connect()
try:
  Snoop.run()
finally:
  Snoop.stop()
