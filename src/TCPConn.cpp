#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/rijndael.h>
#include <crypto++/gcm.h>
#include <crypto++/aes.h>

using namespace CryptoPP;

//PLACE THIS FUNCTION AT THE TOP BECUASE IT DOES NOT NEED TO BE ASSOCIATED WITH THIS CLASS
//I JUST NEED IT TO GENERATE A RANDOM STRING
//TAKEN FROM: https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
std::string random_string( size_t length ) {
   auto randchar = []() -> char  {
      const char charset[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
      const size_t max_index = (sizeof(charset) - 1);
      return charset[ rand() % max_index ];
   };
   std::string str(length,0);
   std::generate_n( str.begin(), length, randchar );
   return str;
}

// Common defines for this TCPConn
const unsigned int iv_size = AES::BLOCKSIZE;
const unsigned int key_size = AES::DEFAULT_KEYLENGTH;
const unsigned int auth_size = 16;

/**********************************************************************************************
 * TCPConn (constructor) - creates the connector and initializes - creates the command strings
 *                         to wrap around network commands
 *
 *    Params: key - reference to the pre-loaded AES key
 *            verbosity - stdout verbosity - 3 = max
 *
 **********************************************************************************************/

TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity):
                                    _data_ready(false),
                                    _aes_key(key),
                                    _verbosity(verbosity),
                                    _server_log(server_log)
{
   // prep some tools to search for command sequences in data
   uint8_t slash = (uint8_t) '/';
   c_rep.push_back((uint8_t) '<');
   c_rep.push_back((uint8_t) 'R');
   c_rep.push_back((uint8_t) 'E');
   c_rep.push_back((uint8_t) 'P');
   c_rep.push_back((uint8_t) '>');

   c_endrep = c_rep;
   c_endrep.insert(c_endrep.begin()+1, 1, slash);

   c_ack.push_back((uint8_t) '<');
   c_ack.push_back((uint8_t) 'A');
   c_ack.push_back((uint8_t) 'C');
   c_ack.push_back((uint8_t) 'K');
   c_ack.push_back((uint8_t) '>');

   c_auth.push_back((uint8_t) '<');
   c_auth.push_back((uint8_t) 'A');
   c_auth.push_back((uint8_t) 'U');
   c_auth.push_back((uint8_t) 'T');
   c_auth.push_back((uint8_t) '>');

   c_endauth = c_auth;
   c_endauth.insert(c_endauth.begin()+1, 1, slash);

   c_sid.push_back((uint8_t) '<');
   c_sid.push_back((uint8_t) 'S');
   c_sid.push_back((uint8_t) 'I');
   c_sid.push_back((uint8_t) 'D');
   c_sid.push_back((uint8_t) '>');

   c_endsid = c_sid;
   c_endsid.insert(c_endsid.begin()+1, 1, slash);
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   // Accept the connection
   bool results = _connfd.acceptFD(server);


   // Set the state as waiting for the authorization packet
   _status = s_connected;
   _connected = true;
   return results;
}

/**********************************************************************************************
 * sendData - sends the data in the parameter to the socket
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendData(std::vector<uint8_t> &buf) {
   
   _connfd.writeBytes<uint8_t>(buf);
   
   return true;
}

/**********************************************************************************************
 * sendEncryptedData - sends the data in the parameter to the socket after block encrypting it
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendEncryptedData(std::vector<uint8_t> &buf) {

   // Encrypt
   encryptData(buf);

   // And send!
   return sendData(buf);
}

/**********************************************************************************************
 * encryptData - block encrypts data and places the results in the buffer in <ID><Data> format
 *
 *    Params:  buf - where to place the <IV><Data> stream
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

void TCPConn::encryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);
   AutoSeededRandomPool rnd;

   // Generate our random init vector
   rnd.GenerateBlock(init_vector, init_vector.size());

   // Encrypt the data
   CFB_Mode<AES>::Encryption encryptor;
   encryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string cipher;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(encryptor, new StringSink(cipher)));

   // Now add the IV to the stream we will be sending out
   std::vector<uint8_t> enc_data(init_vector.begin(), init_vector.end());
   enc_data.insert(enc_data.end(), cipher.begin(), cipher.end());
   buf = enc_data;
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   try {
      switch (_status) {

         // Client: Just connected, send our SID
         case s_connecting:
            clientSendSID();
            break;

         // Server: Wait for the SID from a newly-connected client, then send our SID
         case s_connected:
            serverWaitForSID();
            break;

         //client - tx challenge to server 
         case s_clienttxchallenge:
            clientTxChallenge();
            break;
         //server - encrypt challenge and send to client
         //   ??????    - tx challenge to client
         case s_svrrxchallenge:
            svrRxChallenge();
            break;
         
         //client - verify server response to challenge (decrypt), go to tx encrypted data client -> server
         //  ????     - encrypt challenge and send to server
         case s_clientrxsvrchallengeresponse:
            clientRxChallengeResponse();
            break;
         //server - very client response to challenge (decrypt), to to rx encrypted data from client

         // Client: connecting user - replicate data
         case s_datatx:
            transmitData();
            break;

         // Server: Receive data from the client
         case s_datarx:
            waitForData();
            break;
   
         // Client: Wait for acknowledgement that data sent was received before disconnecting
         case s_waitack:
            awaitAck();
            break;
         
         // Server: Data received and conn disconnected, but waiting for the data to be retrieved
         case s_hasdata:
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.\n";
      disconnect();
      return;
   }

}

/**********************************************************************************************
 * sendSID()  - Client: after a connection, client sends its Server ID to the server
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::clientSendSID() {

            std::stringstream msg;
      msg << "In clientSendSID()";
      _server_log.writeLog(msg.str().c_str());

   std::vector<uint8_t> buf(_svr_id.begin(), _svr_id.end());
   wrapCmd(buf, c_sid, c_endsid);
   sendData(buf);

   //_status = s_datatx;//this is client goto clientsendchallenge
   _status = s_clienttxchallenge;
   //_status = s_txrxchallenge;
}

/**********************************************************************************************
 * waitForSID()  - receives the SID and sends our SID
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::serverWaitForSID() {

   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      // Send our Node ID... sends a blank node
      buf.assign(_svr_id.begin(), _svr_id.end());
      wrapCmd(buf, c_sid, c_endsid);
      sendData(buf);

      //_status = s_datarx;//this is server goto receive challenge
      std::stringstream msg;
      msg << "In serverWaitForSID()";
      _server_log.writeLog(msg.str().c_str());

      _status = s_svrrxchallenge;
      //_status = s_txrxchallenge;
   }
}

void TCPConn::clientTxChallenge(){

//Server responded with their SID and now it is time ot transmit the challenge to the server
/*if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf))
         return;

      //the fact that i send the svr id is just extra, we care about the AUT challenge
      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "Msg from connection client DOES NOT conatian <SID></SID> from server. Cant Tx Challenge";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

*/    
      std::vector<uint8_t> buf;  
      buf.assign(_svr_id.begin(), _svr_id.end());
      wrapCmd(buf, c_sid, c_endsid);
      std::string _authstr = random_string(10); 
      std::cout << "MY RANDOM STRING IS: " << _authstr;
      std::vector<uint8_t> sendchallenge(_authstr.begin(), _authstr.end());
      wrapCmd(sendchallenge, c_auth, c_endauth);
      buf.insert(buf.end(), sendchallenge.begin(), sendchallenge.end());
            
      std::cout << "330 std::vector<uint8_t> buf in clientTxChallenge() is: ";
      for (int i=0; i<buf.size(); i++){
      std::cout << buf.at(i); } std::cout << "\n";
      
      //sendEncryptedData(buf);
      sendData(buf);
      std::stringstream msg;
      msg << "In clientTxChallenge()";
      _server_log.writeLog(msg.str().c_str());

      _status = s_clientrxsvrchallengeresponse;
  // }
}

void TCPConn::svrRxChallenge(){

/*
//server previously sent its sid, now receiving the challenge, will encrypt it and send back to client 
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf))
         return;

      //the fact that i send the svr id is just extra, we care about the AUT challenge
      //remember getCmdData strips the buffer of other stuff
      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::stringstream msg;
         msg << "Msg from connection client DOES NOT conatian <AUT></AUT>. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }
*/
      std::vector<uint8_t> buf;
      if (!getData(buf))
         return;
      
      getCmdData(buf, c_auth, c_endauth);
      //ENCRYPT THE CHALLENGE AND SEND BACK TO CLIENT, buf contains only what is between the AUT tags
      // REUSE WHEN WANTING TO PRINT OUT A <UINT8_T> OBJECT 
      //std::cout << "366 std::vector<uint8_t> buf in svrRxChallenge() is: ";
      //for (int i=0; i<buf.size(); i++){
      //std::cout << buf.at(i); } std::cout << "\n";
      // REUSE WHEN WANTING TO PRINT OUT A <UINT8_T> OBJECT 

      //We got the challenge and put it in buffer, we wrap in AUT tags
      wrapCmd(buf, c_auth, c_endauth);

      //We add the SID to the beginning of the buffer for good measure
      //REMEMBER the datatx function is looking for SID tags
      buf.insert(buf.begin(), c_sid.begin(), c_sid.end());
      buf.insert(buf.begin(), _svr_id.begin(), _svr_id.end());
      buf.insert(buf.begin(), c_endsid.begin(), c_endsid.end());
      
      //sendEncryptedData(buf);
      sendData(buf);
 
   std::stringstream msg;
   msg << "In svrRxChallenge()";
   _server_log.writeLog(msg.str().c_str());
      _status = s_datarx;
   //}
}

void TCPConn::clientRxChallengeResponse(){

/*      
// If data on the socket, should contian an encrypted packet with <AUT>_authstring</AUT> and <SID>_svr_id</SID>
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf))
         return;

      //Since I have multiple tags and getCmdData strips info out of the returned buffer... i need a copy
      std::vector<uint8_t> copyofbuf = buf;

      //First grab whats between the <AUT> tags in buf
      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::stringstream msg;
         msg << "Msg from connection client DOES NOT conatin <AUT></AUT>. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }   
*/
     std::vector<uint8_t> buf;  

    // if (!getData(buf))
    //     return;

// REUSE WHEN WANTING TO PRINT OUT A <UINT8_T> OBJECT 
      std::cout << "\n\n436 std::vector<uint8_t> buf in clientRxChallengeResponse() is: ";
      for (int i=0; i<buf.size(); i++){
      std::cout << buf.at(i); } std::cout << "\n";
      // REUSE WHEN WANTING TO PRINT OUT A <UINT8_T> OBJECT 

 
     std::vector<uint8_t> copyofbuf = buf;    
      //packet contains <AUT> tags and has already been decrypted, move <unit8_t> buf into a string
      //for comparison against _authstr
      std::string challengeresponsefromsvr;
      for (int i=0; i<buf.size(); i++){ challengeresponsefromsvr.at(i) = buf.at(i); }
      std::cout << "challengeresponsefromsvr contains: " << challengeresponsefromsvr << std::endl;
      if (_authstr.compare(challengeresponsefromsvr) == 0) {
         std::cout << "\n\nSTRINGS ARE EQUAL... YAY!!!\n\n";
         //get the SID 
         _status = s_datatx;
      } else {
         std::cout << "CLIENT DID NOT USE PROPER ENCRYPTION KEY";
      }
    
    //else... GO TO NEXT STEP FOR NOW?
   //_status = s_datatx;
   //}

   //restore buf back to original state wiht both <SID> and <AUT> tags
      buf=copyofbuf; 
     
   std::stringstream msg;
   msg << "In clientRxChallengeResponse()";
   _server_log.writeLog(msg.str().c_str());
      
   _status = s_datatx;
   //transmitData();
   //}
}


/**********************************************************************************************
 * transmitData()  - receives the SID from the server and transmits data
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::transmitData() {

/*
   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connected server invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }
*/
    std::vector<uint8_t> buf;

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      // Send the replication data
      sendData(_outputbuf);

      if (_verbosity >= 3)
         std::cout << "Successfully authenticated connection with " << getNodeID() <<
                      " and sending replication data.\n";

      // Wait for their response
      _status = s_waitack;
   //}
}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForData() {

//std::cout << "\n Entered TCPConn::waitForData";
   // If data on the socket, should be replication data
   if (_connfd.hasData()) {

   std::cout << "\n Entered TCPConn::waitForData where _connfd.hasData()";
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_rep, c_endrep)) {
         std::stringstream msg;
         msg << "Replication data possibly corrupted from" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      // Got the data, save it
      _inputbuf = buf;
      _data_ready = true;

      // Send the acknowledgement and disconnect
      sendData(c_ack);

      if (_verbosity >= 2)
         std::cout << "Successfully received replication data from " << getNodeID() << "\n";


      disconnect();
      _status = s_hasdata;
   }
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::awaitAck() {

   // Should have the ack message
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (findCmd(buf, c_ack) == buf.end())
      {
         std::stringstream msg;
         msg << "Ack expected from data send, received something else. Node:" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
      }
  
      if (_verbosity >= 3)
         std::cout << "Data ack received from " << getNodeID() << ". Disconnecting.\n";

 
      disconnect();
   }
}

/**********************************************************************************************
 * getData - Reads in data from the socket and checks to see if there's an end command to the
 *           message to confirm we got it all
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false if they lost connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getData(std::vector<uint8_t> &buf) {

   std::vector<uint8_t> readbuf;
   size_t count = 0;

   buf.clear();

   while (_connfd.hasData()) {
      // read the data on the socket up to 1024
      count += _connfd.readBytes<uint8_t>(readbuf, 1024);

      // check if we lost connection
      if (readbuf.size() == 0) {
         std::stringstream msg;
         std::string ip_addr;
         msg << "Connection from server " << _svr_id << " to node "<< _node_id<<" lost (IP: " << 
                                                         getIPAddrStr(ip_addr) <<":"<< getPort() << ") in getDATA() Function"; 
         _server_log.writeLog(msg.str().c_str());
         disconnect();  //This is necessary... but why are we losing connections...
         return false;
      }

      buf.insert(buf.end(), readbuf.begin(), readbuf.end());

      // concat the data onto anything we've read before
//      _inputbuf.insert(_inputbuf.end(), readbuf.begin(), readbuf.end());
   }
   return true;
}

/**********************************************************************************************
 * decryptData - Takes in an encrypted buffer in the form IV/Data and decrypts it, replacing
 *               buf with the decrypted info (destroys IV string>
 *
 *    Params: buf - the encrypted string and holds the decrypted data (minus IV)
 *
 **********************************************************************************************/
void TCPConn::decryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);

   // Copy the IV from the incoming stream of data
   init_vector.Assign(buf.data(), iv_size);
   buf.erase(buf.begin(), buf.begin() + iv_size);

   // Decrypt the data
   CFB_Mode<AES>::Decryption decryptor;
   decryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string recovered;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(decryptor, new StringSink(recovered)));

   buf.assign(recovered.begin(), recovered.end());

}


/**********************************************************************************************
 * getEncryptedData - Reads in data from the socket and decrypts it, passing the decrypted
 *                    data back in buf
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false otherwise
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getEncryptedData(std::vector<uint8_t> &buf) {
   // Get the data from the socket
   if (!getData(buf))
      return false;

   decryptData(buf);

   return true; 
}

/**********************************************************************************************
 * findCmd - returns an iterator to the location of a string where a command starts
 * hasCmd - returns true if command was found, false otherwise
 *
 *    Params: buf = the data buffer to look for the command within
 *            cmd - the command string to search for in the data
 *
 *    Returns: iterator - points to cmd position if found, end() if not found
 *
 **********************************************************************************************/

std::vector<uint8_t>::iterator TCPConn::findCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return std::search(buf.begin(), buf.end(), cmd.begin(), cmd.end());
}

bool TCPConn::hasCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return !(findCmd(buf, cmd) == buf.end());
}

/**********************************************************************************************
 * getCmdData - looks for a startcmd and endcmd and returns the data between the two 
 *
 *    Params: buf = the string to search for the tags
 *            startcmd - the command at the beginning of the data sought
 *            endcmd - the command at the end of the data sought
 *
 *    Returns: true if both start and end commands were found, false otherwisei
 *
 **********************************************************************************************/

bool TCPConn::getCmdData(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, 
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = buf;
   auto start = findCmd(temp, startcmd);
   auto end = findCmd(temp, endcmd);

   if ((start == temp.end()) || (end == temp.end()) || (start == end))
      return false;

   buf.assign(start + startcmd.size(), end);
   return true;
}

/**********************************************************************************************
 * wrapCmd - wraps the command brackets around the passed-in data
 *
 *    Params: buf = the string to wrap around
 *            startcmd - the command at the beginning of the data
 *            endcmd - the command at the end of the data
 *
 **********************************************************************************************/

void TCPConn::wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd,
                                                    std::vector<uint8_t> &endcmd) {
   //see https://en.cppreference.com/w/cpp/container/vector/insert
   // on item number 4) inserts elements from range [first, last) before pos with function format
   // insert(pos, first, last)
   
   std::vector<uint8_t> temp = startcmd; //create temp and fills with startcmd
   temp.insert(temp.end(), buf.begin(), buf.end()); //goes to pos at end of temp and fills with buf
   temp.insert(temp.end(), endcmd.begin(), endcmd.end()); //go to pos at end of temp and fills with endcmd

   buf = temp;
}


/**********************************************************************************************
 * getReplData - Returns the data received on the socket and marks the socket as done
 *
 *    Params: buf = the data received
 *
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getInputData(std::vector<uint8_t> &buf) {

   // Returns the replication data off this connection, then prepares it to be removed
   buf = _inputbuf;

   _data_ready = false;
   _status = s_none;
}

/**********************************************************************************************
 * connect - Opens the socket FD, attempting to connect to the remote server
 *
 *    Params:  ip_addr - ip address string to connect to
 *             port - port in host format to connect to
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPConn::connect(const char *ip_addr, unsigned short port) {

   // Set the status to connecting
   _status = s_connecting;

   // Try to connect
   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
   // Set the status to connecting
   _status = s_connecting;

   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

/**********************************************************************************************
 * assignOutgoingData - sets up the connection so that, at the next handleConnection, the data
 *                      is sent to the target server
 *
 *    Params:  data - the data stream to send to the server
 *
 **********************************************************************************************/

void TCPConn::assignOutgoingData(std::vector<uint8_t> &data) {

   _outputbuf.clear();
   _outputbuf = c_rep;
   _outputbuf.insert(_outputbuf.end(), data.begin(), data.end());
   _outputbuf.insert(_outputbuf.end(), c_endrep.begin(), c_endrep.end());
}
 

/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
   _connected = false;
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connected;
   // return _connfd.isOpen(); // This does not work very well
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
const char *TCPConn::getIPAddrStr(std::string &buf) {
   _connfd.getIPAddrStr(buf);
   return buf.c_str();
}

