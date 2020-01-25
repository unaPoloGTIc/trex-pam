#include <libssh/libssh.h>
#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>

extern "C" {
#include <curl/curl.h>
}
using namespace std;

/*
CT for trex-pam OTP PAM module

TODOs:
-add RAII everywhere
-grab QR image
-compare QR text to challange (and add to UTs)

*/

class sshraii {
  string host;
  int port, log;
  ssh_session session;
public:
  
  sshraii(string hostp = "localhost",
	  int portp = 2222,
	  int logp = SSH_LOG_PROTOCOL/*NOLOG*//*PROTOCOL*/)
    :host{hostp},
     port{portp},
     log{logp}
  {
    session = ssh_new();
    if (!session)
      throw runtime_error("failed to start a new ssh session");

    ssh_options_set(session, SSH_OPTIONS_HOST, hostp.c_str());
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &log);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (ssh_connect(session) != SSH_OK)
      throw runtime_error("failed to connect");
  }
  
  ~sshraii()
  {
    ssh_disconnect(session);
    ssh_free(session);
  }
  
  operator ssh_session() {return session;};
};

//TODO: copied from UTs, unify.
class globalRaii {
public:
  globalRaii() { curl_global_init(CURL_GLOBAL_ALL); }
  ~globalRaii() { curl_global_cleanup(); }
};

class curlraii {
  CURL *curl;
public:
  curlraii(): curl{curl_easy_init()}{}
  ~curlraii() { curl_easy_cleanup(curl); }
  operator CURL*(){return curl;}
};

class poster {
private:
public:
  curlraii curl;
  stringstream ss;
  poster(string host = "https://trex-security.com:1720/webdemo", string formdata="") : curl{} {
    ss.clear();
    if (!curl)
      throw runtime_error{"can't init curl\n"s};
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ss);
    auto res{curl_easy_perform(curl)};
  }

  static size_t write_data(void *buffer, size_t size, size_t nmemb,
                           void *userp) {
    auto streamPtr{static_cast<stringstream *>(userp)};
    *streamPtr << string{static_cast<char *>(buffer)};
    return nmemb;
  }

  string get() { return ss.str(); }
};


int main()
{
  globalRaii init{};
  auto my_ssh{sshraii()};

  ssh_userauth_kbdint(my_ssh, "docker", nullptr);
  string prompt{ssh_userauth_kbdint_getprompt(my_ssh, 0, nullptr)};
  auto chal{prompt.substr(0,prompt.find("\n\nFor QR"))};
  cout << "DBG:\n" << chal << endl ; //<< ssh_userauth_kbdint_getnprompts(my_ssh) << endl;
  if (chal=="")
    throw runtime_error("invalid challange");
  
  //TODO: query https://trex-security.com:1720/webdemo via POST for responce
  
  string resp{};
  cout << "Responce: ";
  cin >> resp;  
  if (ssh_userauth_kbdint_setanswer(my_ssh, 0, resp.c_str()) < 0)
    throw runtime_error("failed to set answear");

  auto rc{ssh_userauth_kbdint(my_ssh, "docker", nullptr)};
  int i{0};
  while ( rc == SSH_AUTH_INFO && i < 3)
    {
      i++;
      rc = ssh_userauth_kbdint(my_ssh, "docker", nullptr);
    }
  if (rc != SSH_AUTH_SUCCESS)
    {
      stringstream ss{};
      ss << " err: " << rc << " returned";
      throw runtime_error("failed to connect with responce: " + resp + string{" | "} + string{ssh_get_error(my_ssh)}  + string{" | "} + ss.str());
    } else {
    cout << "success" << endl;
  }
  
}
