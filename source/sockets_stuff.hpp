#include"socket.hpp"
namespace Sockets{

      class Socket;

      enum class type_sock{
         tcp,udp
      };

     enum class status_of_socket{
	not_inited,inited,connected,server
     };



      struct udp_packet{
         struct sockaddr_in from;
         socklen_t fromlen;
         char * message;
      };

      using icmp_packet = udp_packet;
      using raw_packet = udp_packet;
}
