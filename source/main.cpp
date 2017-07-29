#include "socket.hpp"
#define TCPTEST
int main(int argcount,char**arguments){
static Sockets::Socket * sock;
sock = new Sockets::Socket("google.com",80);
sock->write("GET /\r\n");
printf("%s\n",sock->Read());
delete sock;
sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_tcp());
try{
sock->connect_to("localhost",80);
sock->write("GET /\r\n");
printf("%s\n",sock->Read());
}catch(Sockets::for_throws err){
  if ( err == 1 ) printf("You are not set sock");
}
delete sock;

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
   printf("%s write -> %s\n",ipv4,tmp.message);
   delete tmp.message;
}catch(Sockets::for_throws err){
}
}
#endif
#ifdef TCPTEST
sock = new Sockets::Socket();
sock->set_sock(sock->init_socket_tcp());
sock->binding("0.0.0.0",15055);
Sockets::Socket::user_struct tmp;
while(1){
try{
tmp = sock->accepting();
char ipv4[INET_ADDRSTRLEN];

inet_ntop(AF_INET, &tmp.cli_addr.sin_addr, ipv4, INET_ADDRSTRLEN);

sock->writeTo(tmp.socket,"Test Test how you are see this text?\r\n");
printf("%s write -> %s\n",ipv4,sock->Read_from(tmp.socket));
close(tmp.socket);
}catch(Sockets::for_throws err){
}
}
#endif

}
