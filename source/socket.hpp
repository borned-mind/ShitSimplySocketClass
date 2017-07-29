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
#endif
#include <string>
#include "somefunc.hpp"

#ifndef bzero
#define bzero(d,n) memset((d),0,(n))
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#endif

#define SIZEBUFFER 4096

namespace Sockets{
   enum for_throws{
      #ifdef WIN32
      WSAStartup_Failed,
      #endif
      socket_init,   not_exist_sock,
      not_founded_host, connecting_refused,
      bad_banding,bad_accept,bad_write,bad_read,socket_used_for_other,
      socket_not_inited
   };
   class Socket{
   protected:
      int self_socket;
      int sock_family;
   public:
      /*enum type_addr{
         ipv4,ipv6
      };*/
      enum type_sock{
         tcp,udp
      };enum status_of_socket{
         not_inited,inited,connected,server
      };
      struct user_struct{
         int socket;
         struct sockaddr_in cli_addr;
      };
      struct udp_packet{
         struct sockaddr_in from;
         socklen_t fromlen;
         char * message;
      };

      status_of_socket status_sock;
      Socket(void);
      Socket(int domain,int type,int protocol);
      Socket(const char * host,int port,type_sock type=tcp, int domain = AF_INET, int protocol = 0 );
      ~Socket(void);
      void close_self_sock(void);
      int get_descriptor_of_self_socket(void);
      int init_socket(int domain=AF_INET, int type=SOCK_STREAM, int protocol=0);
      int init_socket_udp(int domain=AF_INET,int protocol=0);
      int init_socket_tcp(int domain=AF_INET,int protocol=0);
      int getsockopt_(int socket,int level, int optname,
                                      void *optval, socklen_t *optlen);
      int setsockopt_(int socket,int level, int optname,
                                      const void *optval, socklen_t optlen);
      void close_socket(int socket);
      user_struct accepting(int socket);
      user_struct accepting(void);

      bool write( std::string message,int signal=MSG_NOSIGNAL);
      bool write( std::wstring message,int signal=MSG_NOSIGNAL);
      bool write( const char *  message,int signal=MSG_NOSIGNAL);
      bool write( const unsigned char *  message,int signal=MSG_NOSIGNAL);

      bool writeTo( int socket, std::string message,int signal=MSG_NOSIGNAL);
      bool writeTo( int socket, std::wstring message,int signal=MSG_NOSIGNAL);
      bool writeTo( int socket, const char *  message,int signal=MSG_NOSIGNAL);
      bool writeTo( int socket, const unsigned char *  message,int signal=MSG_NOSIGNAL);


      char * Read(unsigned long long sizebuf=1024);
      udp_packet Read_UDP(unsigned long long sizebuf=4096,int flags=0);
      char * Read_from(int socket,unsigned long long sizebuf=1024);
      void set_sock(int socket);
      virtual bool connect_to(const char * host,int port);
      virtual bool binding(const char * host,int port,int maxlisten=100);
      virtual bool close_connect(int socket);

   };
}
