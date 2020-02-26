#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>
#include "TCPServer.h"
#include "ALMgr.h"
//LARKIN ADD FOR DYNAMIC CAST
#include "QueueMgr.h"
//LARKIN for passing in Replication Server
#include "ReplServer.h"

TCPServer::TCPServer(unsigned int verbosity)
                        :_aes_key(CryptoPP::AES::DEFAULT_KEYLENGTH), 
                         _server_log("server.log", 0),
                         _verbosity(verbosity)//, //part of attempt 2
                         //_svr(svr) //Part of attempt 2
{
}

TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   _sockfd.setReusable();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Starts the server socket listening for incoming connections
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

// Simple function that simply starts the server listening
void TCPServer::listenSvr() {
   _sockfd.listenFD(5);

   std::string ipaddr_str;
   std::stringstream msg;
   _sockfd.getIPAddrStr(ipaddr_str);
   msg << "Server listening on IP " << ipaddr_str << "' port '" << _sockfd.getPort() << "'";
   _server_log.writeLog(msg.str().c_str());
}

/**********************************************************************************************
 * runSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *          them. Also loops through the list of connections and handles data received and
 *          sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::runServer() {
   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   // Start the server socket listening
   listenSvr();

   while (online) {
      handleSocket();

      handleConnections();

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 


   
}

/**********************************************************************************************
 * handleSocket - Checks the socket for incoming connections and validates against the whitelist.
 *                Accepts valid connections and adds them to the connection list.
 *
 *    Returns: pointer to a new connection if one was found, otherwise NULL
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

TCPConn *TCPServer::handleSocket() {
  
   // The socket has data, means a new connection 
   if (_sockfd.hasData()) {

      // Try to accept the connection
      TCPConn *new_conn = new TCPConn(_server_log, _aes_key, _verbosity/*, _svr*/);
      if (!new_conn->accept(_sockfd)) {
         _server_log.strerrLog("Data received on socket but failed to accept.");
         return NULL;
      }
      std::cout << "***Got a connection***\n";

      _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));

      // Get their IP Address and Port string to use in logging
      std::string ipaddr_str;
      new_conn->getIPAddrStr(ipaddr_str);
      unsigned short port_num;
      port_num = new_conn->getPort();
      std::string port_str = std::to_string(port_num);

      // Check the whitelist
      ALMgr al("whitelist");
      if (!al.isAllowed(new_conn->getIPAddr()))
      {
         // Disconnect the user
         new_conn->disconnect();

         // Log their attempted connection
         std::string msg = "Connection by IP address '";
         msg += ipaddr_str;
         msg += "' not on whitelist. Disconnecting.";
         _server_log.writeLog(msg);

         return NULL;
      }

      std::string isthiscorrectserverid; //, isthiscorrectnodeid;
      if (QueueMgr* child = dynamic_cast<QueueMgr*>(this)){
         isthiscorrectserverid = child->getServerID();
         //isthiscorrectnodeid = child->getClientID(); //Won't work... this is a lookup in the Severs list and a Random High Port gets generated
      }
      new_conn->setSvrID(isthiscorrectserverid.c_str());

      std::string msg = "Connection from IP '";
      msg += ipaddr_str;
      msg += "' PORT '";
      msg += port_str;
      msg += "' with NodeID ";
      msg += new_conn->getNodeID(); //so this info aint known at this time
      msg += "(can't get NodeID). TCP 3-way handshake in TCPServer::handleSocket() Complete";

      _server_log.writeLog(msg);        

      return new_conn;
   }
   return NULL;
}

/**********************************************************************************************
 * handleConnections - Loops through the list of clients, running their functions to handle the
 *                     clients input/output.
 *
 *    Returns: number of new connections accepted
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::handleConnections() {
   // Loop through our connections, handling them
   std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
   while (tptr != _connlist.end())
   {
      // If the client is not connected, then either reconnect or drop 
      if ((!(*tptr)->isConnected()) || ((*tptr)->getStatus() == TCPConn::s_none)) {
         // Might be trying to connect
         if ((*tptr)->getStatus() == TCPConn::s_clientconnecting) {

            // If our retry timer hasn't expired....skip
            if ((*tptr)->reconnect > time(NULL)) {
               tptr++;
               continue;
            }

            unsigned long ip_addr = (*tptr)->getIPAddr();
            unsigned short port = (*tptr)->getPort();
            
            // Try to connect and handle failure
            try {
               (*tptr)->connect(ip_addr, port);
            } catch (socket_error &e) {
               std::stringstream msg;
               msg << "Connect to SID " << (*tptr)->getNodeID() << 
                        " failed when trying to send data. Msg: " << e.what();
               if (_verbosity >= 2)
                  std::cout << msg.str() << "\n";
               _server_log.writeLog(msg.str().c_str());
               (*tptr)->disconnect();
               (*tptr)->reconnect = time(NULL) + reconnect_delay;
               tptr++;
               continue;
            }
         // Else we're in a different state and there's not data waiting to be read
         } else if (!(*tptr)->isInputDataReady()) {
         // Log it
            std::string msg = "Node ID/IP/Port (not coded)'";
            msg += (*tptr)->getNodeID();
            msg += "' lost connection from '";
            msg += (*tptr)->getSvrID();
            msg += "'";
            _server_log.writeLog(msg);

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue; 
         }
         tptr++;
         continue;
      } 

      // Process any user inputs
      (*tptr)->handleConnection();

      // Increment our iterator
      tptr++;
   }

}

/*********************************************************************************************
 * loadAESKey - reads in the 128 bit AES key from the indicated file
 *********************************************************************************************/
void TCPServer::loadAESKey(const char *filename) {

   CryptoPP::FileSource keyfile(filename, true, new CryptoPP::ArraySink(_aes_key.begin(), _aes_key.size()));
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {
   _server_log.writeLog("Server shutting down.");

   _sockfd.closeFD();
}

void TCPServer::changeLogfile(const char *filename) {
   _server_log.changeFilename(filename);
}
