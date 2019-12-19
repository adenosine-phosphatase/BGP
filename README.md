# BGP
BGP authentication attack and route injection PoC

2 utilities available, working labels md5sigserver and tcprecv6
tcprecv6 is a listener that captures BGP traffic, extracts the TCP MD5 signature and runs online cracking attack
md5sigserver is an active BGP process emulator that uses the password from tcprecv6 and injects arbitrary routes into BGP process

Talk is playable in Windows MEdia Player and shows the demo of the attack (no audio for now)
Also added is the presentation deck to outline the methodology and development process of the attack
