#! /usr/bin/env python

from scapy.all import *
import string,binascii,signal,sys,threading,socket,struct,getopt
from sys import stdout
import pcap
import logging
from pprint import pformat

conf.use_pcap = True
conf.checkIPaddr = False
conf.iface = "lo"
conf.verb = False

config = {
  'prefix': '2',
  'vlan_depth': 0,
  'client_count': 1,
  'per_second': 1
}
clients = {}
threads = []

STATE_INIT = 0
STATE_DISCOVER_SENT = 1
STATE_REQUEST_SENT = 2
STATE_ACKED = 3
STATE_RENEW_SENT = 4

discover_sent = 0
discover_retransmitted = 0
request_rediscovered = 0
rebinding_time_hit = 0
offer_received = 0
request_sent = 0
ack_received = 0
nack_received = 0
out_of_state = 0
renew_sent = 0
renew_retransmitted = 0

logger = logging.getLogger(__name__)

class send_dhcp(threading.Thread):
  def __init__ (self):
    threading.Thread.__init__(self)
    self.kill_received = False

  def run(self):
    global clients, discover_sent, discover_retransmitted, request_rediscovered, rebinding_time_hit
    while not self.kill_received:
      logger.debug("send_dhcp")
      for mac in clients.keys():
        needs_discover = False
        if (clients[mac]["state"] == STATE_INIT and clients[mac]["updated"] == None and clients[mac]["start"] < time.time()):
          logger.debug("Sending first discover")
          discover_sent += 1
          needs_discover = True

        if (clients[mac]["state"] == STATE_DISCOVER_SENT and ((time.time() - clients[mac]["updated"]) > 5)):
          logger.debug("Discover not answered, retransmitting")
          discover_retransmitted += 1
          needs_discover = True

        if (clients[mac]["state"] == STATE_REQUEST_SENT and ((time.time() - clients[mac]["updated"]) > 5)):
          logger.debug("Request not answered, sending a new discover")
          request_rediscovered += 1
          clients[mac]["lock"].acquire()
          clients[mac]["state"] = STATE_INIT
          clients[mac]['updated'] = time.time()
          clients[mac]["lock"].release()
          needs_discover = True

        if clients[mac]["rebinding_time"] and ((clients[mac]["updated"] + clients[mac]["rebinding_time"]) < time.time()):
          logger.debug("Rebind timer reached")
          rebinding_time_hit += 1
          clients[mac]["lock"].acquire()
          clients[mac]["state"] = STATE_INIT
          clients[mac]['updated'] = time.time()
          clients[mac]["lock"].release()
          needs_discover = True

        if not needs_discover:
          continue

        logger.debug("Discover needed")

        clients[mac]["lock"].acquire()

        discover = Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")
        if len(clients[mac]['vlans']) > 0:
          discover.type = 0x88a8
        for vlan in clients[mac]['vlans']:
          discover.add_payload(Dot1Q(vlan=vlan))

        discover.add_payload(IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(mac)],xid=clients[mac]["xid"])/DHCP(options=[("message-type","discover"),("hostname",clients[mac]["hostname"]),"end"]))

        logger.debug("--> DISCOVER ["+mac+"]")

        sendp(discover,iface=conf.iface)

        clients[mac]["state"] = STATE_DISCOVER_SENT
        clients[mac]['updated'] = time.time()
        clients[mac]["lock"].release()

      time.sleep(1)

class sniff_dhcp(threading.Thread):
  def __init__ (self):
    threading.Thread.__init__(self)
    self.kill_received = False

  def run(self):
    while not self.kill_received:
      sniff(prn=self.detect_dhcp,store=0,timeout=3,iface=conf.iface)

  def detect_dhcp(self,pkt):
    global clients, out_of_state, offer_received, request_sent, ack_received, nack_received
    logger.debug("PKT %s\n" % pkt.summary())
    if not Dot1Q in pkt:
      logger.debug("Not a dot1q packet")
      return

    if DHCP in pkt:

      if not pkt[DHCP]:
        return

      logger.debug("DHCP %s\n" % pkt.summary())

      if pkt[DHCP].options[0][1] == 2:
        client_mac = unpack_mac(pkt[BOOTP].chaddr)

        if not client_mac in clients:
          return

        if clients[client_mac]["state"] != STATE_DISCOVER_SENT:
          logger.debug("Got an out of state packet. Type: [%d] Mac: [%s] Client: [%s]" % (pkt[DHCP].options[0][1], client_mac, pformat(clients[client_mac], indent=1).replace('\n','')))
          out_of_state += 1
          return

        clients[client_mac]["lock"].acquire()

        server_ip = pkt[IP].src
        dhcp_server_mac = pkt[Ether].src
        client_ip = pkt[BOOTP].yiaddr
        xid = pkt[BOOTP].xid

        for opt in pkt[DHCP].options:
          if opt[0] == 'subnet_mask':
            subnet=opt[1]
            break

        offer_received += 1
        logger.debug("<-- OFFER ["+pkt[Ether].src+"] ["+server_ip+"] ["+client_ip+"] ["+pkt[Ether].dst+"]")

        b = pkt[BOOTP]
        logger.debug("\t* xid=%s"%repr(b.xid))
        logger.debug("\t* CIaddr=%s"%repr(b.ciaddr))
        logger.debug("\t* YIaddr=%s"%repr(b.yiaddr))
        logger.debug("\t* SIaddr=%s"%repr(b.siaddr))
        logger.debug("\t* GIaddr=%s"%repr(b.giaddr))
        logger.debug("\t* CHaddr=%s"%repr(b.chaddr))
        logger.debug("\t* Sname=%s"%repr(b.sname))
        for o in pkt[DHCP].options:
          if isinstance(o,str):
            if o=="end": break
            logger.debug("\t\t* "+repr(o))
          else:
            logger.debug("\t\t* %s\t%s"%(o[0],o[1:]))


        dhcp_req = Ether(src=client_mac,dst="ff:ff:ff:ff:ff:ff")
        if len(clients[client_mac]['vlans']) > 0:
          dhcp_req.type = 0x88a8
        for vlan in clients[client_mac]['vlans']:
          dhcp_req.add_payload(Dot1Q(vlan=vlan))
        dhcp_req.add_payload(IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(client_mac)],xid=xid)/DHCP(options=[("message-type","request"),("server_id",server_ip),("requested_addr",client_ip),("hostname",clients[client_mac]["hostname"]),("param_req_list","pad"),"end"]))

        request_sent += 1
        logger.debug("--> REQUEST ["+client_mac+"] ["+client_ip+"]")

        sendp(dhcp_req,iface=conf.iface)

        clients[client_mac]['state'] = STATE_REQUEST_SENT
        clients[client_mac]['updated'] = time.time()
        clients[client_mac]['lock'].release()

      elif pkt[DHCP].options[0][1] == 5:
        client_mac = unpack_mac(pkt[BOOTP].chaddr)

        if not client_mac in clients:
          return

        if (clients[client_mac]["state"] != STATE_REQUEST_SENT and
            clients[client_mac]["state"] != STATE_RENEW_SENT):
          out_of_state += 1
          logger.debug("Got an out of state packet. Type: [%d] Mac: [%s] Client: [%s]" % (pkt[DHCP].options[0][1], client_mac, pformat(clients[client_mac], indent=1).replace('\n','')))
          return

        clients[client_mac]["lock"].acquire()

        client_ip=pkt[BOOTP].yiaddr
        server_ip=pkt[IP].src

        lease_time = 3600
        for option in pkt[DHCP].options:
          if option[0] == 'lease_time':
            lease_time = int(option[1])
            break

        renewal_time = int(lease_time/2)
        for option in pkt[DHCP].options:
          if option[0] == 'renewal_time':
            lease_time = int(option[1])
            break

        rebinding_time = int(lease_time*0.85)
        for option in pkt[DHCP].options:
          if option[0] == 'rebinding_time':
            lease_time = int(option[1])
            break

        ack_received += 1
        logger.debug("<-- ACK ["+pkt[Ether].src+"] ["+server_ip+"] ["+client_ip+"] ["+pkt[Ether].dst+"]")

        clients[client_mac]['state'] = STATE_ACKED
        clients[client_mac]['updated'] = time.time()
        clients[client_mac]['lease_time'] = lease_time
        clients[client_mac]['renewal_time'] = renewal_time
        clients[client_mac]['rebinding_time'] = rebinding_time
        clients[client_mac]['server_ip'] = server_ip
        clients[client_mac]['ip'] = client_ip
        clients[client_mac]['lock'].release()
      elif pkt[DHCP].options[0][1] == 6:
        client_mac = unpack_mac(pkt[BOOTP].chaddr)

        if not client_mac in clients:
          return

        nack_received += 1
        logger.debug("<-- NAK [%s]" % client_mac)

        clients[client_mac]["lock"].acquire()

        clients[client_mac]['state'] = STATE_INIT
        clients[client_mac]['updated'] = time.time()
        clients[client_mac]['lock'].release()
      elif pkt[DHCP].options[0][1] == 1 or pkt[DHCP].options[0][1] == 3:
        pass
      else:
        logger.debug("<-- Unknown DHCP msg type: [%d]" % pkt[DHCP].options[0][1])

class renew_dhcp(threading.Thread):
  def __init__ (self):
    threading.Thread.__init__(self)
    self.kill_received = False

  def run(self):
    global clients, renew_sent, renew_retransmitted
    while not self.kill_received:
      logger.debug("renew_dhcp")
      for mac in clients.keys():
        needs_renew = False
        if clients[mac]["renewal_time"] and clients[mac]["state"] == STATE_ACKED and ((clients[mac]["updated"] + clients[mac]["renewal_time"]) < time.time()):
          logger.debug("Time to renew")
          renew_sent += 1
          needs_renew = True

        if clients[mac]["state"] == STATE_RENEW_SENT and ((clients[mac]["updated"] + 5) < time.time()):
          logger.debug("Renew not answered in 5 seconds, re-sending")
          renew_retransmitted += 1
          needs_renew = True

        if not needs_renew:
          continue

        clients[mac]["lock"].acquire()

        server_ip = clients[mac]["server_ip"]
        client_ip = clients[mac]["ip"]
        hostname = clients[mac]["hostname"]
        clients[mac]["xid"] += 1
        xid = clients[mac]["xid"]

        dhcp_renew = Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")
        if len(clients[mac]['vlans']) > 0:
          dhcp_renew.type = 0x88a8
        for vlan in clients[mac]['vlans']:
          dhcp_renew.add_payload(Dot1Q(vlan=vlan))
        dhcp_renew.add_payload(IP(src=client_ip,dst=server_ip)/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(mac)],xid=xid,ciaddr=client_ip)/DHCP(options=[("message-type","request"),("server_id",server_ip),("hostname",hostname),("param_req_list","pad"),"end"]))

        logger.debug("--> RENEW ["+mac+"] ["+server_ip+"] ["+client_ip+"] ["+hostname+"]")

        sendp(dhcp_renew,iface=conf.iface)

        clients[mac]["state"] = STATE_RENEW_SENT
        clients[mac]['updated'] = time.time()
        clients[mac]["lock"].release()

      time.sleep(1)


def signal_handler(signal, frame):
  global threads
  logger.info('Got a signal')
  i = 0
  for t in threads:
    t.kill_received = True
    logger.debug('Waiting for thread %d to die' % i)
    i+=1

  logger.debug('All done')
  sys.exit(0)

def random_mac():
  global clients

  while True:
    prefix = int(config['prefix'],base=16)
    mac = [ 0x00, prefix,
        random.randint(0x00, 0x29),
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    macstr = ':'.join(map(lambda x: "%02x" % x, mac))

    logger.debug("Checking if new mac [%s] is already used" % macstr)

    if not macstr in clients:
      return macstr

def random_hostname():
  global clients

  while True:
    hostname = config['prefix']+''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))

    logger.debug("Checking if new hostname [%s] is already used" % hostname)
    if not any(client['hostname'] == hostname for client in clients.itervalues()):
      return hostname

def random_vlans():
  if not config['vlan_depth'] > 0:
    return []

  while True:
    new_vlans = []
    # if config['vlan_depth'] >= 1:
    #   new_vlans.append(int(config['prefix']))
    # for i in range(1,config['vlan_depth']):
    #   new_vlans.append(random.randint(1000, 3000))

    new_vlans.append(int(config['prefix']))
    new_vlans.append(random.randint(1000, 3000))

    logger.debug("Checking if new vlans [%s] are already used" % pformat(new_vlans))
    if not any(client['vlans'] == new_vlans for client in clients.itervalues()):
      return new_vlans

def unpack_mac(binmac):
    mac=binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

def print_status():
  global clients, discover_sent, discover_retransmitted, request_rediscovered, rebinding_time_hit, offer_received, request_sent, ack_received, nack_received, out_of_state, renew_sent, renew_retransmitted


  total = len(clients)
  state_init = 0
  state_discover_sent = 0
  state_request_sent = 0
  state_acked = 0
  state_renew_sent = 0

  for client_mac in clients.keys():
    if clients[client_mac]["state"] == 0:
      state_init += 1
    elif clients[client_mac]["state"] == 1:
      state_discover_sent += 1
    elif clients[client_mac]["state"] == 2:
      state_request_sent += 1
    elif clients[client_mac]["state"] == 3:
      state_acked += 1
    elif clients[client_mac]["state"] == 4:
      state_renew_sent += 1

  logger.info("States:  IN: %s DI: %s RS: %s AC: %s RN: %s     Stats: DS: %s DR: %s RR: %s BT: %s OR: %s RS: %s AR: %s NR: %s OS: %s RS: %s RT: %s " % (
    repr(state_init).ljust(5),
    repr(state_discover_sent).ljust(5),
    repr(state_request_sent).ljust(5),
    repr(state_acked).ljust(5),
    repr(state_renew_sent).ljust(5),
    repr(discover_sent).ljust(5),
    repr(discover_retransmitted).ljust(5),
    repr(request_rediscovered).ljust(5),
    repr(rebinding_time_hit).ljust(5),
    repr(offer_received).ljust(5),
    repr(request_sent).ljust(5),
    repr(ack_received).ljust(5),
    repr(nack_received).ljust(5),
    repr(out_of_state).ljust(5),
    repr(renew_sent).ljust(5),
    repr(renew_retransmitted).ljust(5)
  ))

  discover_sent = 0
  discover_retransmitted = 0
  request_rediscovered = 0
  rebinding_time_hit = 0
  offer_received = 0
  request_sent = 0
  ack_received = 0
  nack_received = 0
  out_of_state = 0
  renew_sent = 0
  renew_retransmitted = 0

  # logger.debug("Data: [%s]", pformat(clients, indent=1))

def main():
  global clients,config,threads

  logging.basicConfig(level=logging.INFO)

  # Sort out command line args
  try:
    opts, args = getopt.getopt(sys.argv[1:], "c:dhi:p:r:v:", ["clients", "debug", "help", "interface", "prefix", "per_second", "vlans"])
  except getopt.GetoptError, err:
    # print help information and exit:
    print str(err) # will print something like "option -a not recognized"
    usage()
    sys.exit(2)
  for o,a in opts:
    if o in ("-c", "--clients"):
      config['client_count'] = int(a)
    elif o in ("-d", "--debug"):
      logging.basicConfig(level=logging.DEBUG)
      conf.verb = True
    elif o in ("-h", "--help"):
      usage()
      sys.exit()
    elif o in ("-i", "--interface"):
      conf.iface = a
    elif o in ("-v", "--vlans"):
      config['vlan_depth'] = int(a)
    elif o in ("-p", "--prefix"):
      config['prefix'] = a
    elif o in ("-r", "--per_second"):
      config['per_second'] = int(a)
    else:
      assert False, "unhandled option"

  # signal.signal(signal.SIGINT, signal_handler)

  start = time.time()

  # Generate a list of clients
  logger.info("Creating %d clients" % config['client_count'])
  for i in xrange(config['client_count']):
    mac = random_mac()
    hostname = random_hostname()
    vlans = random_vlans()
    offset = i/config['per_second']
    client = {
      'hostname': hostname,
      'state': STATE_INIT,
      'lease_time': None,
      'rebinding_time': None,
      'renewal_time': None,
      'server_ip': None,
      'updated': None,
      'ip': None,
      'start': start + offset,
      'vlans': vlans,
      'xid': random.randint(1, 2**32),
      'lock': threading.Lock()
    }
    clients[mac] = client
    logger.debug("Client: [%s]" % pformat(client, indent=1))

  logger.debug("Clients: [%s]" % pformat(clients, indent=1))

  logger.debug("Starting sniffer thread")
  t=sniff_dhcp()
  t.start()
  threads.append(t)

  logger.debug("Starting discovery thread")
  t=send_dhcp()
  t.start()
  threads.append(t)

  logger.debug("Starting renew thread")
  t=renew_dhcp()
  t.start()
  threads.append(t)

  while True:
    print_status()
    time.sleep(1)

def usage():
    print __doc__

if __name__ == '__main__':
    main()
    print "\n"
