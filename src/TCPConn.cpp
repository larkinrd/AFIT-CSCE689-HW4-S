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
//Larkin ADD
//#include "ReplServer.h"
//class ReplServer;
#include <ctime>
#include <stdlib.h>



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

// Part of attempt 1 logic
//TCPConn::TCPConn(ReplServer &svr):_svr(svr){}

// Part of attempt 2 logic
TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity/*, ReplServer &svr*/):
                                    _data_ready(false),
                                    _aes_key(key),
                                    _verbosity(verbosity),
                                    _server_log(server_log)//, //Part of attempt 2 logic
                                    //_svr(svr) //part of attempt 2 logic
{
   // prep some tools to search for command sequences in data
   uint8_t slash = (uint8_t) '/';
   c_rep.push_back((uint8_t) '<');    c_rep.push_back((uint8_t) 'R');    c_rep.push_back((uint8_t) 'E');
   c_rep.push_back((uint8_t) 'P');    c_rep.push_back((uint8_t) '>');

   c_endrep = c_rep;
   c_endrep.insert(c_endrep.begin()+1, 1, slash);

   c_ack.push_back((uint8_t) '<');    c_ack.push_back((uint8_t) 'A');    c_ack.push_back((uint8_t) 'C');
   c_ack.push_back((uint8_t) 'K');    c_ack.push_back((uint8_t) '>');

   c_auth.push_back((uint8_t) '<');    c_auth.push_back((uint8_t) 'A');    c_auth.push_back((uint8_t) 'U');
   c_auth.push_back((uint8_t) 'T');    c_auth.push_back((uint8_t) 'H');    c_auth.push_back((uint8_t) '>');

   c_endauth = c_auth;
   c_endauth.insert(c_endauth.begin()+1, 1, slash);

   c_sid.push_back((uint8_t) '<');    c_sid.push_back((uint8_t) 'S');    c_sid.push_back((uint8_t) 'I');
   c_sid.push_back((uint8_t) 'D');    c_sid.push_back((uint8_t) '>');

   c_endsid = c_sid;
   c_endsid.insert(c_endsid.begin()+1, 1, slash);
   
   //CHAL for sending the challenge
   c_chal.push_back((uint8_t) '<');    c_chal.push_back((uint8_t) 'C');    c_chal.push_back((uint8_t) 'H');
   c_chal.push_back((uint8_t) 'A');    c_chal.push_back((uint8_t) 'L');    c_chal.push_back((uint8_t) '>');

   c_endchal = c_chal;
   c_endchal.insert(c_endchal.begin()+1, 1, slash);
   
   //RESP for sending an ENCRYPTED response to the challenge
   c_resp.push_back((uint8_t) '<');    c_resp.push_back((uint8_t) 'R');    c_resp.push_back((uint8_t) 'E');
   c_resp.push_back((uint8_t) 'S');    c_resp.push_back((uint8_t) 'P');    c_resp.push_back((uint8_t) '>');

   c_endresp = c_resp;
   c_endresp.insert(c_endresp.begin()+1, 1, slash);
   
   //TIME; T0 for Initial, T1 for first attempt to sync, T2 for final attempt
   c_t0.push_back((uint8_t) '<');    c_t0.push_back((uint8_t) 'T');    c_t0.push_back((uint8_t) '0');    c_t0.push_back((uint8_t) '>');
   c_t1.push_back((uint8_t) '<');    c_t1.push_back((uint8_t) 'T');    c_t1.push_back((uint8_t) '1');    c_t1.push_back((uint8_t) '>');
   c_t2.push_back((uint8_t) '<');    c_t2.push_back((uint8_t) 'T');    c_t2.push_back((uint8_t) '2');    c_t2.push_back((uint8_t) '>');

   c_endt0 = c_t0; c_endt0.insert(c_endt0.begin()+1, 1, slash);
   c_endt1 = c_t1; c_endt1.insert(c_endt1.begin()+1, 1, slash);
   c_endt2 = c_t2; c_endt2.insert(c_endt2.begin()+1, 1, slash);
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
   _status = s_serveracceptedconnection;
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

         // Client: Initiated connection and we "ASSUME" success!!!
         // //send UNencrypted <TIME><SID><CHAL>
         case s_clientconnecting: oneClientSendsCHAL(); break;

         // Server: //send ENcrypted <TIME><SID><RESP>
         case s_serveracceptedconnection: twoSvrSendsRESPtoCHAL(); break;

         //client: //if Good goto FIVE and prcess Svrs CHALL
         case s_threeclient: threeClientProcRESP(); break;
         
         //Server: send UNencrypted <TIME><SID><CHAL>
         case s_fourserver: fourSvrSendsCHAL(); break;
         
         //Client: send ENcrypted <TIME><SID><RESP>
         case s_fiveclient: fiveClientSendsRESPtoCHAL(); break;

         //Server: if good go to eight and receive REP dat form client
         case s_sixserver: sixSvrProcRESP(); break;
         
         // Client: connecting user - replicate data
         case s_sevendatatx: sevenClientTxREPData(); break;

         // Server: Receive data from the client
         case s_eightdatarx: eigthSvrRxREPData(); break;
   
         // Client: Wait for acknowledgement that data sent was received before disconnecting
         case s_ninewaitack: nineClientRxAck(); break;
         
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
   //ONE send UNencrypted <TIME><SID><CHAL>
   void TCPConn::oneClientSendsCHAL() {
      
      std::cout << "***My realifesystemstarttime in TCPConn.cpp.256 is: " << globalrealifesystemstarttime << std::endl;
      //std::cout << "***The simulatoroffset in TCPConn.cpp.257 is: " << globalsimtimeoffset << std::endl;
      //std::cout << "The Adjusted Time is: " << getAdjustedTime() <<"\n";

//      ReplServer *temp;
//      time_t mytime; 
//      mytime = temp->getAdjustedTime();
//      std::cout << "ONE: send UNencrypted <TIME><SID><CHAL> & mytime is: " << mytime <<"\n";
      
      std::stringstream msg;
      msg << "In clientSendSID()";
      _server_log.writeLog(msg.str().c_str());
      
      //INSERT <TIME> tag data into buf
/*** THIS WAS A COMPLETE WASTE OF MY TIME... TRYING TO CONVERT FROM TIME_T TO STRING TO UINT_8 AND BACK***/      
//      char* dt = ctime(&globalrealifesystemstarttime); //convert time_t to string form
//      std::string timestr = dt;//"seqONEtimestamp"; 
//      unsigned long testthis = globalrealifesystemstarttime;
//      std::string str2 = std::to_string(globalrealifesystemstarttime);
//      std::cout << "testthis is: " << (unsigned long) globalrealifesystemstarttime 
//         << "timestr is: " << timestr << " str2 is: " << str2 << std::endl;
/*** THIS WAS A COMPLETE WASTE OF MY TIME... TRYING TO CONVERT FROM TIME_T TO STRING TO UINT_8 AND BACK***/

      std::string timestr = std::to_string(globalrealifesystemstarttime); 
      std::vector<uint8_t> buf(timestr.begin(), timestr.end());
      wrapCmd(buf, c_t0, c_endt0);
      
      //INSERT <SID> tag data with my _svr_id into buf
      std::vector<uint8_t> mysid;
      mysid.assign(_svr_id.begin(), _svr_id.end());
      wrapCmd(mysid, c_sid, c_endsid);
      buf.insert(buf.end(), mysid.begin(), mysid.end());

      //On my first transmission, add my sid and startuptime to the vector of servers
      if ( std::find(otherserverids.begin(), otherserverids.end(), _svr_id) != otherserverids.end()){
         //std::cout << "\nGOT DUPLICATES\n";
      } else { //add my info to the vector
      otherserverids.push_back(_svr_id);
      otherserversrealtimes.push_back((unsigned long) globalrealifesystemstarttime);
      }

      //INSERT <CHAL>
      _authstr = random_string(10); 
      std::vector<uint8_t> sendchallenge(_authstr.begin(), _authstr.end());
      wrapCmd(sendchallenge, c_chal, c_endchal);
      buf.insert(buf.end(), sendchallenge.begin(), sendchallenge.end());

      //std::cout << "\n\n265 std::vector<uint8_t> buf in oneClientSendsCHAL() is: ";
      //for (int i=0; i<buf.size(); i++){
      //std::cout << buf.at(i); } std::cout << "\n";

      sendData(buf);

   _status = s_threeclient;}
   
//TWO send ENcrypted <TIME><SID><RESP>
void TCPConn::twoSvrSendsRESPtoCHAL(){//std::cout << "TWO: send ENcrypted <TIME><SID><RESP>\n";

   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf)) //getData zero's out the passed in buffer and gets whats on the socket
      return;

      if (!getCmdData(buf, c_chal, c_endchal)) {
         std::cout << "BUF DID NOT CONTAIN <CHAL>"; return; }
            
      wrapCmd(buf, c_resp, c_endresp);

      //INSERT <SID> tag data with my _svr_id into buf before <RESP>
      std::vector<uint8_t> mysid;
      mysid.assign(_svr_id.begin(), _svr_id.end());
      wrapCmd(mysid, c_sid, c_endsid);
      buf.insert(buf.begin(), mysid.begin(), mysid.end());

      //INSERT <T0> tag into first part of buf prior to <SID><RESP>
      std::string timestr = std::to_string(globalrealifesystemstarttime); 
      std::vector<uint8_t> temp(timestr.begin(), timestr.end());
      wrapCmd(temp, c_t0, c_endt0);
      buf.insert(buf.begin(), temp.begin(), temp.end());
      
      sendData(buf);
      //sendEncryptedData(buf);

      _status = s_fourserver;
   } else {   /*std::cout << "Nothing on buffer in twoSvrSendsRESPtoCHAL\n"; */}
}
   //THREE
   void TCPConn::threeClientProcRESP(){//std::cout << "THREE: if Good goto FIVE and prcess Svrs CHAL\n";
   
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf)) //getData zero's out the passed in buffer and gets whats on the socket
      return;
      
      //Get the other system (i.e. servers) time from between the <t0> tags
      std::vector<uint8_t> gett0(buf.begin(), buf.end());
      getCmdData(gett0, c_t0, c_endt0);
      std::string svrstime (gett0.begin(), gett0.end()); //convert to string
      unsigned long otherservertime = strtol(svrstime.c_str(), NULL, 0); //convert to unsigned long

      //std::cout << "gett0 in threeClientProcRESP when cast as unsigned long is: " << otherservertime;
      
      std::vector<uint8_t> getsid(buf.begin(), buf.end());
      getCmdData(getsid, c_sid, c_endsid);
      std::string svrsid (getsid.begin(), getsid.end());

      //Got the other servers ID and their Startup time, check to see if already in vector
      if ( std::find(otherserverids.begin(), otherserverids.end(), svrsid) != otherserverids.end()){
         //std::cout << "\nGOT DUPLICATES\n";
      } else { //add the info to the vector
      otherserverids.push_back(svrsid);
      otherserversrealtimes.push_back(otherservertime);
      }

      //PRINT WHATS IN THE VECTORS
      std::cout << "371 otherserverids and otherserversrealtimes in threeClientProcRESP() is: \n";
      for (int i=0; i<otherserverids.size(); i++){ 
         std::cout << "SvrID: " << otherserverids.at(i) <<" Time: " << otherserversrealtimes.at(i) <<"\n"; 
      } std::cout << "\n";      

      //Find the minimum element in the vector
      std::cout << "min element in otherserverrealtimes is: " << *std::min_element(otherserversrealtimes.begin(), otherserversrealtimes.end()) << std::endl;
      std::cout << "my servertime is: " << globalrealifesystemstarttime << std::endl;
      if(globalrealifesystemstarttime == *std::min_element(otherserversrealtimes.begin(), otherserversrealtimes.end())){
         std::cout << "I'm the min with offset zero";
         myoffset = 0;
      } else {
         std::cout << "I'm NOT the min with offset" << globalrealifesystemstarttime - *std::min_element(otherserversrealtimes.begin(), otherserversrealtimes.end()) << "\n";
         myoffset = globalrealifesystemstarttime - *std::min_element(otherserversrealtimes.begin(), otherserversrealtimes.end());
      }
      
      if (!getCmdData(buf, c_resp, c_endresp)) {
         std::cout << "BUF DID NOT CONTAIN <RESP>"; return; }

      std::string challengeresponsefromsvr;
      for (int i=0; i<buf.size(); i++){  challengeresponsefromsvr += buf.at(i); }
      
      if (_authstr.compare(challengeresponsefromsvr) == 0) {
         std::cout << "\n***strings Equal in in three***\n";
         std::string authenticated = "clientTRUSTSserver";
         buf.assign(authenticated.begin(), authenticated.end());
         wrapCmd(buf, c_auth, c_endauth);
         
         //INSERT <SID> tag data with my _svr_id into buf before <RESP>
         std::vector<uint8_t> mysid;
         mysid.assign(_svr_id.begin(), _svr_id.end());
         wrapCmd(mysid, c_sid, c_endsid);
         buf.insert(buf.begin(), mysid.begin(), mysid.end());

         //INSERT <T1> Timestamp
         std::string timestr = "seqTHREEtimestamp"; 
         std::vector<uint8_t> temp(timestr.begin(), timestr.end());
         wrapCmd(temp, c_t1, c_endt1);
         buf.insert(buf.begin(), temp.begin(), temp.end());
         sendData(buf);
         //sendEncryptedData(buf);
         _status = s_fiveclient; //if Good goto FIVE and prcess Svrs CHAL
      } else {
         std::cout << "SERVER DID NOT USE PROPER ENCRYPTION KEY. Client DONT trust yah!";
      }
  
   } else {   /*std::cout << "NOTHING ON THE BUFFER IN threeClientProcRESP\n";*/ }
}
    
   //FOUR send UNencrypted <TIME><SID><CHAL>... NOTE: Exact same code as Client sends a challenge
void TCPConn::fourSvrSendsCHAL(){

   if (_connfd.hasData()) {
   //std::cout << "Entered FOUR with data on socket: send UNencrypted <TIME><SID><CHAL>\n";
   std::vector<uint8_t> buf;

   //if (!getEncryptedData(buf))
   if (!getData(buf)) //getData zero's out the passed in buffer and gets whats on the socket
   return;

   std::vector<uint8_t> gett1(buf.begin(), buf.end());
   getCmdData(gett1, c_t1, c_endt1);
   std::vector<uint8_t> getsid(buf.begin(), buf.end());
   getCmdData(getsid, c_sid, c_endsid);
   
   if (!getCmdData(buf, c_auth, c_endauth)) {
      std::cout << "BUF DID NOT CONTAIN <AUTH> from Client"; return; }

   //INSERT <SID> tag data with my _svr_id into buf
   std::vector<uint8_t> mysid;
   mysid.assign(_svr_id.begin(), _svr_id.end());
   wrapCmd(mysid, c_sid, c_endsid);
   buf.insert(buf.begin(), mysid.begin(), mysid.end());
   
   //INSERT <T2> tag data into buf
   std::string timestr = "seqFOURtimestamp"; 
   buf.insert(buf.begin(), timestr.begin(), timestr.end());
   wrapCmd(buf, c_t2, c_endt2);
   buf.insert(buf.begin(), timestr.begin(), timestr.end());
   
   //INSERT <CHAL>
   _authstr = random_string(20); //NOTE: Keeping same length of 10 returned same random string.. prob needed SEED
   std::vector<uint8_t> sendchallenge(_authstr.begin(), _authstr.end());
   wrapCmd(sendchallenge, c_chal, c_endchal);
   buf.insert(buf.end(), sendchallenge.begin(), sendchallenge.end());

   sendData(buf);
   _status = s_sixserver;
   }
}

   //FIVE send ENcrypted <TIME><SID><RESP>
void TCPConn::fiveClientSendsRESPtoCHAL(){//std::cout << "FIVE: send ENcrypted <TIME><SID><RESP>\n";
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf)) //getData zero's out the passed in buffer and gets whats on the socket
      return;
      
      std::vector<uint8_t> gett2(buf.begin(), buf.end());
      getCmdData(gett2, c_t2, c_endt2);
      std::vector<uint8_t> getsid(buf.begin(), buf.end());
      getCmdData(getsid, c_sid, c_endsid);

      if (!getCmdData(buf, c_chal, c_endchal)) {
         std::cout << "BUF DID NOT contain <CHAL> in FIVE\n"; return; }

      //send the challenge string 
      wrapCmd(buf, c_resp, c_endresp);
      
      //INSERT <SID> tag data with my _svr_id into buf
      std::vector<uint8_t> mysid;
      mysid.assign(_svr_id.begin(), _svr_id.end());
      wrapCmd(mysid, c_sid, c_endsid);
      buf.insert(buf.begin(), mysid.begin(), mysid.end());
      
      //INSERT <T2> Timestamp
      std::string timestr = "seqFIVEimestamp"; 
      std::vector<uint8_t> temp(timestr.begin(), timestr.end());
      wrapCmd(temp, c_t2, c_endt2);
      buf.insert(buf.begin(), temp.begin(), temp.end());
      
      sendData(buf);
      //sendEncryptedData(buf);

      _status = s_sevendatatx;


   } else {   /*std::cout << "NOTHING ON THE BUFFER IN threeClientProcRESP\n";*/ }
}
   
   //SIX
   void TCPConn::sixSvrProcRESP(){//std::cout << "SIX: if good go to eight and receive REP dat form client\n";
   
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf)) //getData zero's out the passed in buffer and gets whats on the socket
      return;
      
      std::vector<uint8_t> gett2(buf.begin(), buf.end());
      getCmdData(gett2, c_t2, c_endt2);
      std::vector<uint8_t> getsid(buf.begin(), buf.end());
      getCmdData(getsid, c_sid, c_endsid);
      
      if (!getCmdData(buf, c_resp, c_endresp)) {
         std::cout << "BUF DID NOT CONTAIN <RESP>"; return; }

      std::string challengeresponsefromclient;
      for (int i=0; i<buf.size(); i++){  challengeresponsefromclient += buf.at(i); }
       
      if (_authstr.compare(challengeresponsefromclient) == 0) {
         std::cout << "\n***strings Equal in five***\n";
         std::string authenticated = "serverTRUSTSclient";
         buf.assign(authenticated.begin(), authenticated.end());
         wrapCmd(buf, c_auth, c_endauth);
         
         //INSERT <SID> tag data with my _svr_id into buf
         std::vector<uint8_t> mysid;
         mysid.assign(_svr_id.begin(), _svr_id.end());
         wrapCmd(mysid, c_sid, c_endsid);
         buf.insert(buf.begin(), mysid.begin(), mysid.end());
         
         //INSERT <T2> Timestamp
         std::string timestr = "seqTHREEtimestamp"; 
         std::vector<uint8_t> temp(timestr.begin(), timestr.end());
         wrapCmd(temp, c_t2, c_endt2);
         buf.insert(buf.begin(), temp.begin(), temp.end());
         
         sendData(buf);
         //sendEncryptedData(buf);
         _status = s_eightdatarx; //if good go to eight and receive REP dat form client
      } else {
         std::cout << "strings NOT EQUAL in five";
      }
   }   
} 

/**********************************************************************************************
 * transmitData()  - receives the SID from the server and transmits data
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::sevenClientTxREPData() {

   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf))
         return;

      //If an <AUTH> tag on the buffer, we have a trust
      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::stringstream msg;
         msg << "No <AUTH> tag in step seven, did not authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      //std::cout << "got to sevenClientTxREPData with an <AUTH> tag from Server\n";

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      // Send the replication data
      sendData(_outputbuf);
      //sendEncryptedData(_outputbuf);

      // Show what is in the replication data
         DronePlot bob_tmp_plot; //#include "DronePlotDB.h" was placed in TCPconn.h
         
      int numbytes = 9;   
      //for(int numbytes=0; numbytes<12;numbytes++){   
         bob_tmp_plot.deserialize(_outputbuf, 9); //Is this cause 0-4 is <AUTH> ???
         
         std::cout << "SHOW ME bob_tmp_plot.deserialize(_outputbuf," << numbytes << ") ";
         for (int i = 0; i<_outputbuf.size(); i++){std::cout << _outputbuf.at(i) << "";} std::cout << std::endl;   
         
         std::cout << "\nTCPConn::drone_id " << bob_tmp_plot.drone_id << " node_id " << bob_tmp_plot.node_id << 
         "\n timestamp " << bob_tmp_plot.timestamp << " myoffset " << myoffset << " (timestamp-offset)=" << bob_tmp_plot.timestamp - myoffset <<
         "\n lat " << bob_tmp_plot.latitude << " long " << bob_tmp_plot.longitude << "\n";
      //}
      //getchar();
      //readBytes();         

      if (_verbosity >= 3)
         std::cout << "Successfully authenticated connection with " << getNodeID() <<
                      " and sending replication data.\n";

      //write to log file when successful
      std::stringstream msg;
      msg << "Successfully authenticated connection with " << getNodeID() << " and SENT replication data.\n";
      _server_log.writeLog(msg.str().c_str());  
      
      // Wait for their response
      _status = s_ninewaitack;
   }
}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::eigthSvrRxREPData() {

//std::cout << "got to eigthSvrRxREPData\n";
//std::cout << "\n Entered TCPConn::waitForData";
   // If data on the socket, should be replication data
   if (_connfd.hasData()) {

   //std::cout << "\n Entered TCPConn::waitForData where _connfd.hasData()";
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
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
      //sendEncryptedData(c_ack);

      if (_verbosity >= 2)
         std::cout << "Successfully received replication data from " << getNodeID() << "\n";


      disconnect();
      _status = s_hasdata; // WHAT IS THIS?... Go to next connection?
   }
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::nineClientRxAck() {

std::cout << "got to nineClientRxAck\n";
   // Should have the ack message
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      //if (!getEncryptedData(buf))
      if (!getData(buf))
         return;

      if (findCmd(buf, c_ack) == buf.end())
      {
         std::stringstream msg;
         msg << "Ack expected from data send, received something else. Node:" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
      }
  
      //if (_verbosity >= 3)
         std::cout << "Data ack received from " << getNodeID() << ". Disconnecting.\n";

 std::cout << "got to END OF nineClientRxAck\n";
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

   // a CLIENT Connects() and a SERVER Listens() & Accepts(); set status to clientconnecting
   _status = s_clientconnecting;

   // Try to connect
   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
   // Set the status to connecting
   _status = s_clientconnecting;

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

