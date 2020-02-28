#include <string>
#include <vector>

// Remove /r and /n from a string
void clrNewlines(std::string &str);

// Removes spaces from leading and trailing edge
void clrSpaces(std::string &str);

// Takes the orig string and splits it into left and right sides around a delimiter
bool split(std::string &orig, std::string &left, std::string &right, const char delimiter);

// Turns a string into lowercase
void lower(std::string &str);

// Turns off local echo from a user's terminal
int hideInput(int fd, bool hide);

// Generates a random string of the assigned length
void genRandString(std::string &buf, size_t n);

// Create global variables for ReplServer and TCPConn to exchange info
//extern time_t globalrealifesystemstarttime;// initialized in ReplServer.cpp
extern time_t simrepserverstarttime;
//NOTE: I get the time since epoch that can be changed directly to a string or unsigned long
extern std::vector<ulong> otherserversstarttimes; //to save other serversrealtimes
extern std::vector<std::string> otherserverids; //to save all other serverids
extern std::vector<int> otherserveroffsets;
extern int myoffset;
extern int maxnumservers;

// I WOULD HAVE USED THIS... if we had easy access to a server clock/startup time
extern time_t simulatedrepserverstarttime;

