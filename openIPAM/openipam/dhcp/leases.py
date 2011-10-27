import shelve
import heapq
import time

class ipinfo:
	address = None
	network = None
	mac = None
	pool = None
	starts = None
	ends = None
	shared_network = None
	server_id=None
	def __init__(self, **args):
		self.type = 'ipinfo'
		#TODO: evil stub. 
		self.__dict__.update(args)

class hostinfo:
	expires = None
	pools = None
	hostname = None
	dhcp_group = None
	disabled = False
	def __init__(self, **args):
		self.type = 'hostinfo'
		#TODO: evil stub. 
		self.addresses = set()
		self.__dict__.update(args)

hosts_columns = mac, pools
hosts_query = """SELECT h.mac, h.hostname,
	FROM hosts JOIN 
"""

pools_query = """SELECT mac, pool_id FROM hosts_to_pools"""

addresses_query = """SELECT a.address, a.network, coalesce(a.mac,l.mac) AS mac, a.mac IS NOT NULL AS static,
		a.pool, EXTRACT(epoch FROM l.starts), EXTRACT(epoch FROM l.ends), n.shared_network,
		n.dhcp_group AS net_dhcp_group, p.dhcp_group AS pool_dhcp_group, l.server, l.abandoned
	FROM addresses AS a LEFT OUTER JOIN leases AS l ON a.address = l.address
		JOIN networks AS n ON a.network = n.network
		JOIN pools AS p ON a.pool = p.id
"""

class localcache:	
	def __init__(self, dbfile, ipamdb):
		self.db = shelve.open(dbfile)
		self.byps = {}
		for row in self.db.itervalues():
			if row.type == 'ipinfo':
				self.setip(row, False)
			elif row.type == 'hostinfo':
				self.sethost(row, False)
		self.pslock = threading.Lock()
		self.setlock = threading.Lock()
		if '_laststamp' not in self.db:
			self.db['_laststamp'] = 0
		if '_disabled' not in self.db:
			self.db['_disabled'] = set()
		# FIXME: need to cache dhcp_options_to_dhcp_groups
		self.ipam=ipamdb
		self.updates = Queue()
		self.updatedb( fullupdate=True )
		self.dbinterval = 5
		self.thread = threading.Thread(target = self.updatethread, name='updatedb')
		self.thread.daemon=True
		self.thread.start()
	
	def find_preferred_address(self, mac, requested_address, router, is_request=False):
		host = self.gethostbymac(mac)
		preferred_address = None
		allowed_pools = host.pools
		unknown = mac in self.disabled_macs or not host or not host.ends
		if unknown:
			allowed_pools = get_unknown_pools()
		if requested_address:
			r = self.getbyip(requested_address)
			if (r.mac == h.mac and r.shared_network == router.shared_network
					and (r.pool in allowed_pools or (not unknown and
						r.is_static))):
				preferred_address = r
		for ip in hosts.addresses:
			if preferred_address.is_static:
				# take the first valid static address we come across
				break
			address = self.getbyip(ip)
			if address.shared_network == router.shared_network and address.pool in allowed_pools:
				preferred_address = address
		if not preferred_address:
			# FIXME: get an address, would ya'?
			for pool in pools:
				preferred_address = getbyps(pool=pool, shared_network=router.shared_network)
				if preferred_address:
					break
		if not preferred_address:
			raise Exception("Yo! No addresses left!")
		return preferred_address

	def sendtopeers(self, row):
		pass
	def setip(self, row, sync=True):
		with self.pslock:
			with self.setlock:
				self.db[row.ip] = row
				if row.mac and row.mac in self.db:
					#there is no real need to make sure .addresses stays up to date on the disk 
					#since we update it here when we load the db
					self.db[row.mac].addresses.add(row.ip)
				pskey = (row.server_id, row.pool, row.shared_network) 
				if pskey not in self.byps: self.byps[pskey] = []
				heapq.heappush(self.byps[pskey], (row.ends, row.ip))
				self.updates.put(row)
		if sync:
			self.sendtopeers(row)
	def sethost(self, row, sync=True):
		with self.pslock:
			with self.setlock:
				if row.mac in self.db:
					old = self.db[row.mac]
					addresses = set(row.addresses)
					for a in old.addresses:
						if a in self.db:
							if row.mac == self.db[a].mac:
								addresses.add(a)
					row.addresses = tuple(addresses)
				
				self.db[row.mac] = row
				self.updates.put(row)
		if sync:
			self.sendtopeers(row)
	def updatethread(self):
		while (True):
			time.sleep(self.dbinterval)
			self.updatedb()
		
	def updatedb(self, full=False):
		ips, hosts, disabled, laststamp = self.ipam.get_dhcp_changes_since(self.db['_laststamp'])
		laststamp = self.db['_laststamp']
		for h in hosts:
			self.sethost(h, False)
		for i in ips:
			self.setip(i, False)
		self.db['_disabled'] = set(disabled)
			
	def updatefrompeer(self, rows):
		for r in rows:
			if r.type == 'ipinfo':
				self.setip(r, False)
	def getbyip(self, ip):
		return self.db.get(ip, None)
	def getipsbymac(self, mac):
		if mac not in self.db: return None
		return [self.db[i] for i in self.db[mac].addresses]
	def getbyps(self, pool, shared_network):
		if (pool, shared_network) not in self.byps or len(self.byps[(pool, shared_network)]) == 0: return None
		with self.pslock:
			pskey = self.me, pool, shared_network
			ip = None
			if pskey in self.byps:
				ends, ip = self.byps[pskey][0]
				if ends < time.time():
					heapq.heappop(self.byps[(pool, shared_network)])
				else:
					ip = None
		if ip:
			return self.db[ip]
		return None
	def hostdisabled(self, mac):
		return mac in self.db['_disabled']
	def gethostbymac(self, mac):
		return self.db.get(mac, None)
		
			
	
	

		
	
		

	
	
		
		
		




