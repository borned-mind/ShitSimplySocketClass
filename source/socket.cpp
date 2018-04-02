#include "socket.hpp"

namespace Sockets{

Socket::Socket(void){
	status_sock = status_of_socket::not_inited;
}

Socket::Socket(int domain,int type,int protocol) {
	self_socket=init_socket(domain,type,protocol);
}

Socket::Socket(const char * host, int port, type_sock type, int domain , int protocol ){
   switch( type ) {
	case type_sock::tcp:
			self_socket=init_socket_tcp(domain,protocol);
				break;
	case type_sock::udp:
			self_socket=init_socket_udp(domain,protocol);
	default:
		throw( std::runtime_error( "Undefined type of socket" ) );
   }

   this->connect_to(host,port);
}



Socket::~Socket(void) noexcept{
   close_self_sock();
}

void Socket::close_connect(int socket) noexcept{
   close(socket);
}

void Socket::close_self_sock(void) noexcept{
   close(self_socket);
   status_sock = status_of_socket::not_inited;
}

void Socket::close_socket(int socket) noexcept{
   close(socket);
}


void Socket::connect_to(std::string host, int port) {

  
   if( static_cast<int>(status_sock) > 1 ) 
	throw_error("Socket already using");

   struct sockaddr_in serv_addr;
   struct hostent *server = gethostbyname(host.c_str());

   if(!server) 
	throw_error( "Can't find host" );


   serv_addr.sin_family = sock_family;
   serv_addr.sin_port = htons(port);

   memcpy( server->h_addr, &serv_addr.sin_addr.s_addr, server->h_length);



   if (connect(self_socket,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
		throw_error("Can't connect to ", host, ":", port );

   status_sock = status_of_socket::connected;

}

void Socket::binding(std::string host,int port,int maxlisten){

   if(static_cast<int>(status_sock)  > 1) 
	throw_error( "Already used" ) ;

   struct sockaddr_in serv_addr;


    serv_addr.sin_family = sock_family;
    serv_addr.sin_addr = { inet_addr(host.c_str()) };
    serv_addr.sin_port = htons(port);

    if (bind(self_socket, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
	 	throw_error( "Can't bind" );

    listen( self_socket, maxlisten );

    status_sock = status_of_socket::server;

}

int Socket::getsockopt_(int socket,int level, int optname,void *optval, socklen_t *optlen) noexcept{
	return getsockopt(socket, level, optname,optval, optlen);
}

void Socket::setsockopt_(int socket,int level, int optname,const void *optval, socklen_t optlen) noexcept{
	
	if( setsockopt (socket, level, optname, optval,optlen) < 0) 
		throw_error( "Can't set socket option") ;
	
}

void Socket::set_sock(int socket){
  self_socket = socket;
}


int Socket::init_socket(int domain, int type, int protocol){

   #ifdef WIN32
   WSADATA wsaData;
   DWORD dwError;
   // Initialize Winsock
   if ( (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) )
      throw( (int)WSAStartup_Failed );
   #endif

  sock_family=domain;
  int sockfd = socket(domain, type, protocol);
  if(sockfd == -1) 
	throw(std::runtime_error("Can't open socket") );

  status_sock = status_of_socket::inited;
  return sockfd;
}

inline int Socket::init_socket_udp(int domain, int protocol) noexcept{ 
   return init_socket(domain,SOCK_DGRAM,protocol);
}

inline int Socket::init_socket_tcp(int domain, int protocol) noexcept{ 
   return this->init_socket(domain,SOCK_STREAM,protocol);
}



int Socket::get_descriptor_of_self_socket(void){
   return this->self_socket;
}



Socket Socket::accepting(int socket){

	
	struct sockaddr_in cli_addr;
	int newsock;
	socklen_t  clientlen  = sizeof(cli_addr);
	newsock = accept(socket,
				  (struct sockaddr *) &cli_addr,
								 &clientlen);

	if(newsock < 0) 
		throw( std::runtime_error ("Can't accept client" ) );


	char ipv4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &cli_addr.sin_addr, ipv4, INET_ADDRSTRLEN);

	return Socket{ newsock, std::string(ipv4) };
}


Socket Socket::accepting(void){
	return accepting(self_socket);
}



void Socket::writeBytes(const wchar_t * message, size_t n , int signal, struct sockaddr * to){
	if(! static_cast<int>(status_sock) ) throw( std::runtime_error("Not inited socket" ) );

	if(to == nullptr)
		send(self_socket, message, n, signal) == -1 ? 
			throw( std::runtime_error("Can't write to socket") ) : 0;
	else
		sendto(self_socket, message, n, signal,
		               to, sockaddr_len) == -1 ?
				throw( std::runtime_error("Can't write to socket") ) : 0;
}


void Socket::writeBytes(const char * message, size_t n , int signal, struct sockaddr * to){
	writeBytes( reinterpret_cast< const wchar_t* >( message ), n, signal, to);
}


void Socket::write(std::string message,int signal,struct sockaddr *to) {
	writeBytes(message.c_str(), message.size(), signal, to);
}

void Socket::write(std::wstring message,int signal,struct sockaddr *to) {
	writeBytes(message.c_str(), message.size(), signal, to);
}


std::string Socket::Read(unsigned long long sizebuf, int socket){
   if(socket == 0) socket = self_socket;
   char * buffer = new char[sizebuf];
   #ifdef WIN32
   if((recv(socket, buffer, sizebuf-1, 0)) <=0 ) 
		throw( std::runtime_error("Can't read from socket" ) );
   #else
   if(read(socket,buffer,sizebuf-1) == -1) 
		throw( std::runtime_error("Can't read from socket" ) );
   #endif
   
   delete [] buffer;
   return std::string( buffer );
}



udp_packet Socket::Read_UDP(unsigned long long sizebuf,int flags){
  udp_packet returns;
  returns.fromlen=sizeof(returns.from);
  char * buffer = new char[sizebuf];

 if( recvfrom(this->self_socket, buffer, sizebuf-1, flags,
                 (struct sockaddr *)&returns.from, &returns.fromlen) == -1 )
		throw_error("can't read");
  returns.message=buffer;
  return returns;
}





int Socket::shutdown_sock(int how){
	shutdown(self_socket,how);
}

int Socket::shutdown_sock(int socket,int how){
	shutdown(socket,how);
}

} //namespace Sockets


// PROXY

namespace Dark{

Socks5Proxy::Socks5Proxy(const char * proxy_host,const int proxy_port){

try{
	set_sock(init_socket_tcp());
}

catch(...){
this->error=true;
try{
	close_self_sock(); // close self sock.
}catch(...){
	this->error=true;
}


}// try 13:0

if(!this->error){


	try{
		connect_to(proxy_host,proxy_port); // conecting to proxy
	}catch( ...){
	try{
		close_self_sock(); // close self sock.
	}catch(...){
		this->error=true;// if error with closing fd
	}
		this->error=true;// if error with connect
	} 

}// if not error

}


bool Socks5Proxy::ReConnectToDark(void){
try{
shutdown_sock(0); // close read in fd.
shutdown_sock(1); // close write in fd.
close_self_sock(); // close self sock.
}catch(...){
return false;
} 
if(!BackHost || !BackPort) return false;
Socks5Proxy(BackHost,BackPort);
return SocksConnect();
}

bool Socks5Proxy::SocksConnect(void){
if(!BackHost || !BackPort) return false;
return SocksConnect(BackHost,BackPort);
}bool Socks5Proxy::SocksConnect(const char * host,const int port){
//set streaming
byte * bytes = new byte[4];
bytes[0] = 0x05;
bytes[1] = 0x01;
bytes[2] = 0x00;
try{
writeBytes((const char*)bytes,3);
}catch(...){
delete [] bytes;
return false;
}



char * server_answer = strdup(Read(4).c_str());
if( server_answer[1] != 0  ){
delete [] bytes;
return false; // error
}
if( !BackHost || !BackPort){
// not connected, we have to set
BackHost = strdup(host);
BackPort = port;
}


delete  [] server_answer;


char  hostLen = (char)strlen(host);
char* LastRequst = new char[4 + 1 + hostLen + 2];
short HPort = htons(port);

bytes[3]=3;

memcpy(LastRequst, bytes, 4);                // 5, 1, 0, 3
memcpy(LastRequst + 4, &hostLen, 1);        // Domain Length 1 byte
memcpy(LastRequst + 5, host, hostLen);    // Domain 
memcpy(LastRequst + 5 + hostLen, &HPort, 2); // Port

writeBytes((const char*)LastRequst,4 + 1 + hostLen + 2);

delete [] LastRequst;


server_answer=strdup(Read(10).c_str());
if(server_answer[1] != 0){
delete [] bytes;
return false;
}

delete  [] server_answer;
delete [] bytes;

this->connected=true;
return true;
}

}



// RAW / ICMP
namespace Sockets{


int Socket::init_socket_icmp(
      int domain,
      int type,
      unsigned int /*__attribute__((aligned(8)))*/ type_icmp , 
      unsigned short echo_id ,
      unsigned short echo_sequence 

){
this->self_icmp_packet.icmph.type=type_icmp;
this->self_icmp_packet.icmph.un.echo.id=echo_id;
this->self_icmp_packet.icmph.un.echo.sequence=echo_sequence;
this->self_icmp_packet.icmp_buf=new char[SIZEBUFFER];
memcpy(this->self_icmp_packet.icmp_buf, &this->self_icmp_packet.icmph, sizeof(this->self_icmp_packet.icmph));
return this->init_socket(domain,type, IPPROTO_ICMP);
}int Socket::init_socket_raw(
        int domain,
	bool ownHeader,
	const char * source_ip,
	const char * dest_ip,
	int source_port,
	int dest_port,
	unsigned char ihl,
	unsigned char ver,
	unsigned char tos,
	unsigned char TTL,
	unsigned char protocol
){
if(!ownHeader){
  return this->init_socket(domain,SOCK_RAW, IPPROTO_RAW);
}
else{
 int s = this->init_socket(domain,SOCK_RAW, IPPROTO_RAW);
 if( s == -1 ) throw_error("Can't init socket");
 this->self_raw_packet.raw_buf = new char[SIZEBUFFER];
 this->self_raw_packet.ip = (struct ipheader *) this->self_raw_packet.raw_buf;
 this->self_raw_packet.header = (struct raw_header *) (this->self_raw_packet.raw_buf + sizeof(struct ipheader));
 this->self_raw_packet.socket=&s;
 this->self_raw_packet.ip->iph_ihl = ihl;
 this->self_raw_packet.ip->iph_ver = ver;
 this->self_raw_packet.ip->iph_tos = tos; 
 this->self_raw_packet.ip->iph_len = sizeof(struct ipheader) + sizeof(struct raw_header);
 //this->self_raw_packet->ipheader->iph_ident = htons(54321); // <<<< --- ident?
 this->self_raw_packet.ip->iph_ttl = TTL;
 this->self_raw_packet.ip->iph_protocol = protocol; 
 this->self_raw_packet.ip->iph_sourceip = inet_addr(source_ip);
 this->self_raw_packet.ip->iph_destip = inet_addr(dest_ip);
 this->self_raw_packet.header->srcport = htons(source_port);
 this->self_raw_packet.header->destport = htons(dest_port);
 this->self_raw_packet.header->len = htons(sizeof(struct raw_header));
 //this->self_raw_packet->ipheader->iph_chksum = csum((unsigned short *)this->raw_buf, sizeof(struct ipheader) + sizeof(struct raw_header));
 this->setsockopt_(s,IPPROTO_IP, IP_HDRINCL, (const void *)1, sizeof(int));
 return s;
}

}


}

#undef SIZEBUFFER
