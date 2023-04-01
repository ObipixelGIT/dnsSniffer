# dnsSniffer
DNS Sniffer - Figure out where your traffic is being sent to, when browsing the Internet and classified as an OSINT tool.

## How this script works?
- Activate this Sniffer from the terminal.
- Open your browser and go to a website.
- Go back to the terminal and see where your traffic is being sent to while loading the website.

## Requirements

Install your libraries:
```python
pip3 install optparse
```

Install the Scapy library:
```bash
sudo apt install python3-scapy
```

## Permissions

Ensure you give the script permissions to execute. Do the following from the terminal:

```bash
sudo chmod +x dnsSniffer.py
```

## Usage

Help:
```bash
sudo python3 dnsSniffer.py -h
```

Basic:
```bash
sudo python3 dnsSniffer.py
```

Use a specific adapter:
```bash
sudo python3 dnsSniffer.py -i eth0
```

Log to a database:
```bash
sudo python3 dnsSniffer.py -d db.sqlite
	
sudo python3 dnsSniffer.py -d db.sqlite -i eth0
```

Use Quiet Mode:
```bash
sudo python3 dnsSniffer.py -d db.sqlite -q

sudo python3 dnsSniffer.py -d db.sqlite -i eth0 -q
```

Export the SQLite DB to a CSV file:
```bash
sudo python3 dnsSniffer.py -d db.sqlite -e db.csv
```

## Example script

```python
#!/usr/bin/env python3

from os import system
from optparse import OptionParser

queries_liste = {}
quiet = False
databaseConn = None
databaseCursor = None

def process(pkt):
	global quiet
	global databaseConn
	ip46 = IPv6 if IPv6 in pkt else IP
	if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53 and ip46 in pkt:
		# pkt[IP].dst == IP source of the DNS request
		# pkt[IP].src == IP of the DNS server
		# pkt[DNS].qd.qname == DNS name
		query = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd != None else "?"

		if not pkt[ip46].dst in queries_liste:
			queries_liste[pkt[ip46].dst] = {}

		if not pkt[ip46].src in queries_liste[pkt[ip46].dst]:
			queries_liste[pkt[ip46].dst][pkt[ip46].src] = {}
		
		if not query in queries_liste[pkt[ip46].dst][pkt[ip46].src]:
			queries_liste[pkt[ip46].dst][pkt[ip46].src][query] = 1
		else:
			queries_liste[pkt[ip46].dst][pkt[ip46].src][query] += 1

		if databaseConn and query != None and query != "?":
			databaseCursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?);", (query,))
			databaseConn.commit()

			databaseCursor.execute("SELECT idDomain FROM domains WHERE domain=?;", (query,))
			domainId = databaseCursor.fetchone()[0]

			databaseCursor.execute("SELECT count, idWhoAsk FROM whoAsk WHERE ipFrom=? AND ipTo=? AND domainId=?;", (pkt[ip46].src, pkt[ip46].dst, domainId))
			whoAsk = databaseCursor.fetchone()

			if whoAsk:
				databaseCursor.execute("UPDATE whoAsk SET count=? WHERE idWhoAsk=?",(whoAsk[0]+1 if whoAsk[0] else 2, whoAsk[1]))
			else:
				databaseCursor.execute("INSERT INTO whoAsk (ipFrom, ipTo, domainId, count) VALUES (?,?,?,1);", (pkt[ip46].src, pkt[ip46].dst, domainId))

			databaseConn.commit()

		if not quiet:
			system('clear')
			print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))
			for ip in queries_liste:
				print("{:15s}".format(ip)) # IP source
				for query_server in queries_liste[ip]:
					print(" "*18+"{:15s}".format(query_server)) # IP of DNS server
					for query in queries_liste[ip][query_server]:
						print(" "*36+"{:19s} {}".format(str(queries_liste[ip][query_server][query]),query)) # Count DNS request | DNS



def init_db(databasePath):
	global databaseConn
	global databaseCursor
	databaseConn = sqlite3.connect(databasePath)
	databaseCursor=databaseConn.cursor()

	databaseCursor.execute("""CREATE TABLE if not exists domains (
							idDomain INTEGER PRIMARY KEY AUTOINCREMENT,
							domain TEXT DEFAULT NULL,
							UNIQUE(domain)
						);""")
	databaseCursor.execute("""CREATE TABLE if not exists whoAsk (
							idWhoAsk INTEGER PRIMARY KEY AUTOINCREMENT,
							ipFrom TEXT DEFAULT NULL,
							ipTo TEXT DEFAULT NULL,
							domainId INTEGER,
							count INTEGER,
							UNIQUE(ipFrom, ipTo, domainId),
							FOREIGN KEY(domainId) REFERENCES domains(id)
						);""")

	# SELECT domain, ipFrom, ipTo, count FROM domains, whoAsk WHERE idDomain = domainId ORDER BY count DESC;

if __name__ == "__main__":
	parser = OptionParser(usage="%prog: [options]")
	parser.add_option("-i", "--iface", dest="iface", default='', help="Interface. Ex: enp0s7")
	parser.add_option("-q", "--quiet", dest="quiet", action="store_true", help="Quiet")
	parser.add_option("-d", "--database", dest="databasePath", default='', help="Path to sqlite database for loggin. Ex: db.sqlite")
	parser.add_option("-e", "--export", dest="exportPath", default='', help="Export sqlite database to CSV. Ex: db.csv")
	(options, args) = parser.parse_args()

	iface = options.iface
	quiet = options.quiet
	databasePath = options.databasePath

	if databasePath != "":
		try:
			import sqlite3
		except ImportError:
			from sys import exit
			exit("\033[31mYou need to setup sqlite3\033[0m")

		init_db(databasePath)

	if options.exportPath:
		databaseCursor.execute("SELECT domain, ipFrom, ipTo, count FROM domains, whoAsk WHERE idDomain = domainId ORDER BY count DESC;")
		data = databaseCursor.fetchall()
		import csv
		with open(options.exportPath, 'w') as f:
		    writer = csv.writer(f, delimiter=';')
		    writer.writerows([( 'domain', 'ipFrom', 'ipTo', 'count')])
		    writer.writerows(data)
	else:
		try:
			from scapy.all import sniff
			from scapy.all import ARP
			from scapy.all import DNSQR
			from scapy.all import UDP
			from scapy.all import IP
			from scapy.all import IPv6
			from scapy.all import DNS
		except ImportError:
			from sys import exit
			exit("\033[31mYou need to setup python3-scapy\033[0m\nsudo apt install python3-scapy")

		if not quiet:
			system('clear')
			print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))

		if iface != "":
			sniff(filter='udp port 53', store=0, prn=process, iface=iface)
		else:
			sniff(filter='udp port 53', store=0, prn=process)

```

## License Information

This library is released under the [Creative Commons ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/). You are welcome to use this library for commercial purposes. For attribution, we ask that when you begin to use our code, you email us with a link to the product being created and/or sold. We want bragging rights that we helped (in a very small part) to create your 9th world wonder. We would like the opportunity to feature your work on our homepage.
