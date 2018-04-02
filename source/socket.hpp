#ifndef __cplusplus
 #error This code for C++
#endif

#pragma once
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#ifdef WIN32// || MINGW || __MINGW32__
   #include <windows.h>
   #include <winsock.h>
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #define MSG_NOSIGNAL 0
   #pragma comment(lib, "ws2_32.lib")
#else
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netdb.h>
 #include <arpa/inet.h>
 #include <netinet/ip_icmp.h>
#endif
#include<iostream>
#include<sstream>
#include<functional>


#include"sockets_stuff.hpp"


#include "somefunc.hpp"


#ifndef bzero
#define bzero(d,n) memset((d),0,(n))
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#endif

#define SIZEBUFFER 4096

namespace Sockets{

      using byte = char;
      using ubyte = unsigned byte;

   // The IP header's structure
   struct ipheader {
 	ubyte      iph_ihl:5, iph_ver:4;
 	ubyte      iph_tos;
 	unsigned short int iph_len;
 	unsigned short int iph_ident;
 	ubyte      iph_flag;
 	unsigned short int iph_offset;
 	ubyte      iph_ttl;
	ubyte      iph_protocol;
	unsigned short int iph_chksum;
 	unsigned int       iph_sourceip;
 	unsigned int       iph_destip;
	};

   struct raw_header {
	raw_header(unsigned short int srcport, unsigned short int destport, unsigned short int len, unsigned short int chksum):
	srcport(srcport), destport(destport), len(len), chksum(chksum){}
	unsigned short int srcport;
 	unsigned short int destport;
 	unsigned short int len;
 	unsigned short int chksum;
   };

   struct icmp_struct{
    struct icmphdr icmph;
    char * icmp_buf;
   };

   struct raw_socket_struct{
    char * raw_buf;
    ipheader * ip;
    raw_header * header;
    int * socket;
   };




   class Socket{

   private:
	
	void inline join_msgs(std::string & t){}
	template <typename T, typename ... Args> inline void join_msgs(std::string & t, T msg, Args ... args) {
		t+= static_cast<std::ostringstream*>
					( &(std::ostringstream () << msg) )->str();		
		join_msgs(t, args...);
	}
	template <typename T, typename ... Args> inline void throw_error(T msg, Args ... args){
		std::string end_msg;
		join_msgs(end_msg ,msg, args...);
		throw( std::runtime_error( msg ) ) ;
	}
   protected:
      int self_socket;
      int sock_family;
      raw_socket_struct self_raw_packet;
      icmp_struct self_icmp_packet;
      std::string selfHost;

   public:
      decltype(auto) getHost(){
	return (selfHost);
      }

      const int sockaddr_len = sizeof(struct sockaddr_in);
      status_of_socket status_sock;

      Socket(void);
      Socket(int socket, std::string ownaddr,  int domain = AF_INET, status_of_socket status=status_of_socket::connected):
		self_socket(socket), selfHost(ownaddr), sock_family(domain) ,status_sock ( status ) {}
		
      Socket(int domain,int type,int protocol);
      Socket(const char * host, int port,type_sock type=type_sock::tcp, int domain = AF_INET, int protocol = 0 );
      ~Socket(void);

      void close_self_sock(void) noexcept;
      int get_descriptor_of_self_socket(void);

      int init_socket(int domain=AF_INET, int type=SOCK_STREAM, int protocol=0);
      int init_socket_udp(int domain=AF_INET,int protocol=0) noexcept;
      int init_socket_tcp(int domain=AF_INET,int protocol=0) noexcept;
      int init_socket_icmp(
      int domain=AF_INET,
      int type=SOCK_DGRAM,
      unsigned int /*__attribute__((aligned(8)))*/ type_icmp = ICMP_ECHO , 
      unsigned short echo_id = 1,
      unsigned short echo_sequence = 1
      );
      int init_socket_raw(
        int domain=AF_INET,
	bool ownHeader=true,
	const char * source_ip=0,
	const char * dest_ip=0,
	int source_port=0,
	int dest_port=0,
	unsigned char ihl = 5,
	unsigned char ver = 4,
	unsigned char tos = 16,
	unsigned char TTL = 128,
	unsigned char protocol = 17
	);


      int getsockopt_(int socket,int level, int optname,
                                      void *optval, socklen_t *optlen) noexcept;
      void setsockopt_(int socket,int level, int optname,
                                      const void *optval, socklen_t optlen) noexcept;
    
      void close_socket(int socket) noexcept;
      Socket accepting(int socket);
      Socket accepting(void);





      void writeBytes(const wchar_t * bytes, size_t n, int signal=MSG_NOSIGNAL, struct sockaddr * to = nullptr);
      void writeBytes(const char * bytes, size_t n, int signal=MSG_NOSIGNAL, struct sockaddr * to = nullptr);

      void write( std::string message, int signal=MSG_NOSIGNAL, struct sockaddr *to=nullptr);
      void write( std::wstring message, int signal=MSG_NOSIGNAL, struct sockaddr *to=nullptr);
 
      int shutdown_sock(int how);
      int shutdown_sock(int socket,int how);
      


           

      std::string Read(unsigned long long sizebuf=1024, int socket=0);


      udp_packet Read_UDP(unsigned long long sizebuf=4096,int flags=0);

      udp_packet (Socket::*Read_Other)(unsigned long long sizebuf,int flags	) = &Socket::Read_UDP;

      void set_sock(int socket);
      virtual void connect_to(std::string host, int port);
      virtual void binding(std::string, int port, int maxlisten=100);
      virtual void close_connect(int socket) noexcept;

private:
	void inline setSock(Socket & s)  noexcept{
		close_self_sock();
		self_socket = s.self_socket;
		s.self_socket=0;
		selfHost = s.selfHost;
		sock_family = s.sock_family;
		status_sock = s.status_sock;
	}
public:
     Socket & operator=(Socket & s){
		setSock(s);
	}
    Socket & operator=(Socket  s){
		setSock(s);
	}


   };

}

typedef unsigned char __attribute__((mode(QI))) byte;

namespace Dark{

struct Socks{
	byte version;
	byte type;
	byte host[2];
	byte port[4];
	byte idstring[10];
};




class Socks5Proxy : public Sockets::Socket{

	bool error;
protected:
	bool connected;
	char * BackHost=0;
	int BackPort=0;
public:
	bool isset_error(void){
		return error;
	}bool connected_succesfully(void){
		return connected;
	}

Socks5Proxy(const char * proxy_host="127.0.0.1",const int proxy_port=9050);
bool ReConnectToDark(void);
bool SocksConnect(const char * host,const int port);
bool SocksConnect(void);

};

}






