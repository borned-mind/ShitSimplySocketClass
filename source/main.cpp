
#include "socket.hpp"
#define SOCKSTEST
#include<iostream>


int main(int argcount,char**arguments){
#ifdef SOCKSTEST
if(argcount < 4)
	return fprintf(stderr, "%s host port text\n",arguments[0]);
try{
	Dark::Socks5Proxy sock =  Dark::Socks5Proxy{};
	std::cout << "Connect via socks" << std::endl;
	if( !sock.SocksConnect(arguments[1],atoi( arguments[2] ) ) ){	
		std::cerr << "Can't connect via socks" << std::endl;
	}

	std::cout << "Write" << std::endl;
	sock.write(arguments[3]);
	sock.write("\r\n");
	std::cout << "Read" << std::endl;
	std::cout << sock.Read() << std::endl;
	std::cout << sock.Read() << std::endl;


}catch(std::runtime_error & e){
	std::cerr << e.what() << std::endl;
}
#else

static Sockets::Socket * sock;
#ifdef SIMPLYHTTPCONNECTTEST
sock = new Sockets::Socket("google.com",80);
sock->write("GET /\r\n");
std::cout << sock->Read() << std::endl;
delete sock;
sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_tcp());
try{
sock->connect_to("localhost",80);
sock->write("GET /\r\n");
printf("%s\n",sock->Read());
}catch(...){

}
delete sock;
#endif


#ifdef UDPTEST
sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_udp());
sock->binding("0.0.0.0",15055);
Sockets::Socket::udp_packet tmp;
while(1){
try{
   tmp = sock->Read_UDP();
   char ipv4[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &tmp.from.sin_addr, ipv4, INET_ADDRSTRLEN);
   sock->write(tmp.message,0,(struct sockaddr*)&tmp.from);
   printf("%s:%d write -> %s\n",ipv4,ntohs(tmp.from.sin_port),tmp.message);
   delete tmp.message;
}catch(Sockets::for_throws err){
}
}
#endif

#ifdef TCPTEST
sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_tcp());
sock->binding("127.0.0.1",15055);

while(1){
try{
	std::cout <<"Accepting" << std::endl;
	Sockets::Socket tmp = sock->accepting();
	std::cout <<"Write" << std::endl;
	tmp.write("Test Test how you are see this text?\r\n");
	std::cout <<"Read" << std::endl;
	printf("%s write -> %s\n", tmp.getHost(), tmp.Read().c_str() );
}catch(std::runtime_error & e){
		std::cerr << e.what() << std::endl;
	}
}
#endif

#ifdef ICMPTEST
struct icmphdr icmp_hdr;
struct sockaddr_in addr;
char packetdata[sizeof(icmp_hdr) + 3];
icmp_hdr.type = ICMP_ECHO;
icmp_hdr.un.echo.id = 666;
icmp_hdr.un.echo.sequence = 1;

memcpy(packetdata, &icmp_hdr, sizeof(icmp_hdr));
memcpy(packetdata + sizeof(icmp_hdr), "667", 3);

memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = htonl(0x7F000001);


sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_icmp());
Sockets::Socket::icmp_packet tmp;
sock->write(packetdata,0,(struct sockaddr*)&addr);
#endif

#ifdef RAWTEST

#endif
#endif

}
