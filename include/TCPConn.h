#ifndef TCPCONN_H
#define TCPCONN_H

#include <crypto++/secblock.h>
#include "FileDesc.h"
#include "LogMgr.h"
//To get access to DronPlot deserialize function
#include "DronePlotDB.h"
class ReplServer;
// WHEN I ADD #include "ReplServer.h" I get the following errors
/*In file included from ../include/ReplServer.h:6:0,
                 from ../include/TCPConn.h:10,
                 from ../include/TCPServer.h:8,
                 from TCPServer.cpp:16:
../include/QueueMgr.h:26:1: error: expected class-name before ‘{’ token
 {*/
//#include "ReplServer.h" //WHY DOES INCLUDING THIS GIVE ME THE ERROR ABOVE?

const int max_attempts = 2;

// Methods and attributes to manage a network connection, including tracking the username
// and a buffer for user input. Status tracks what "phase" of login the user is currently in
class TCPConn 
{
public:
//ATTEMPT 1 with commented out code additions
   //TCPConn(ReplServer &svr);

//ATTEMPT 2 with commented out code additions
   TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity/*, ReplServer &svr*/);
   
   ~TCPConn();

   // The current status of the connection
   enum statustype { s_none, s_clientconnecting, s_serveracceptedconnection, s_threeclient, s_fourserver,   
   s_fiveclient, s_sixserver, s_sevendatatx, s_eightdatarx, s_ninewaitack, s_hasdata };

   statustype getStatus() { return _status; };

   bool accept(SocketFD &server);

   // Primary maintenance function. Checks this connection for input and handles it
   // depending on the state of the connection
   void handleConnection();

   // connect - second version uses ip_addr in network format (big endian)
   void connect(const char *ip_addr, unsigned short port);
   void connect(unsigned long ip_addr, unsigned short port);

   // Send data to the other end of the connection without encryption
   bool getData(std::vector<uint8_t> &buf);
   bool sendData(std::vector<uint8_t> &buf);

   // Calls encryptData or decryptData before send or after receive
   bool getEncryptedData(std::vector<uint8_t> &buf);
   bool sendEncryptedData(std::vector<uint8_t> &buf);

   // Simply encrypts or decrypts a buffer
   void encryptData(std::vector<uint8_t> &buf);
   void decryptData(std::vector<uint8_t> &buf);

   // Input data received on the socket
   bool isInputDataReady() { return _data_ready; };
   void getInputData(std::vector<uint8_t> &buf);

   // Data about the connection (NodeID = other end's Server Node ID string)
   unsigned long getIPAddr() { return _connfd.getIPAddr(); }; // Network format
   const char *getIPAddrStr(std::string &buf);
   unsigned short getPort() { return _connfd.getPort(); }; // host format
   const char *getNodeID() { return _node_id.c_str(); };
   const char *getSvrID() {return _svr_id.c_str(); }; 

   // Connections can set the node or server ID of this connection
   void setNodeID(const char *new_id) { _node_id = new_id; };
   void setSvrID(const char *new_id) { _svr_id = new_id; };

   // Closes the socket
   void disconnect();

   // Checks if the socket FD is marked as open
   bool isConnected();

   // When should we try to reconnect (prevents spam)
   time_t reconnect;

   // Assign outgoing data and sets up the socket to manage the transmission
   void assignOutgoingData(std::vector<uint8_t> &data);

   //MADE THEM PUBLIC... I DON'T SEE THE NEED TO MAKE EM PROTECTED
   void oneClientSendsCHAL(); //send UNencrypted <TIME><SID><CHAL>
   void twoSvrSendsRESPtoCHAL(); //send ENcrypted <TIME><SID><RESP>
   void threeClientProcRESP(); //if Good goto FIVE and prcess Svrs CHALL
   void fourSvrSendsCHAL(); //send UNencrypted <TIME><SID><CHAL>
   void fiveClientSendsRESPtoCHAL(); //send ENcrypted <TIME><SID><RESP>
   void sixSvrProcRESP(); //if good go to eight and receive REP dat form client
   void sevenClientTxREPData(); 
   void eigthSvrRxREPData();
   void nineClientRxAck();

protected:
   // Looks for commands in the data stream
   std::vector<uint8_t>::iterator findCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd);
   bool hasCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd);

   // Gets the data between startcmd and endcmd strings and places in buf
   bool getCmdData(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, std::vector<uint8_t> &endcmd);

   // Places startcmd and endcmd strings around the data in buf and returns it in buf
   void wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, std::vector<uint8_t> &endcmd);


private:

   bool _connected = false;

   std::vector<uint8_t> c_rep, c_endrep, c_auth, c_endauth, c_ack, c_sid, c_endsid, c_chal, 
   c_endchal, c_resp, c_endresp, c_t0, c_endt0, c_t1, c_endt1, c_t2, c_endt2;

   statustype _status = s_none;

   SocketFD _connfd;
 
   std::string _node_id; // The username this connection is associated with
   std::string _svr_id;  // The server ID that hosts this connection object

   // Store incoming data to be read by the queue manager
   std::vector<uint8_t> _inputbuf;
   bool _data_ready;    // Is the input buffer full and data ready to be read?

   // Store outgoing data to be sent over the network
   std::vector<uint8_t> _outputbuf;

   CryptoPP::SecByteBlock &_aes_key; // Read from a file, our shared key
   std::string _authstr;   // remembers the random authorization string sent

   unsigned int _verbosity;

   LogMgr &_server_log;

//Applies to Attempts 1 and 2
   //ReplServer &_svr;

};


#endif
