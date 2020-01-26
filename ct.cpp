#include <libssh/libssh.h>
#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <functional>

extern "C" {
#include <curl/curl.h>
}
using namespace std;

/*
CT for trex-pam OTP PAM module

TODOs:
-add RAII everywhere

*/

class sshraii {
  string host;
  int port, log;
  ssh_session session;
public:
  
  sshraii(string hostp = "localhost",
	  int portp = 2222,
	  int logp = SSH_LOG_NOLOG)
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
  poster(string formdata="", string host = "https://trex-security.com:1720/webdemo") : curl{} {
    ss.clear();
    if (!curl)
      throw runtime_error{"can't init curl\n"s};
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ss);
    curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_REFERER, "https://demo.trex-security.com/");
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, formdata.c_str());
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

void checkresponse(function<string(string)> callback)
{
  auto my_ssh{sshraii()};

  auto prompt = [](auto& my_ssh){
		   ssh_userauth_kbdint(my_ssh, "docker", nullptr);
		   return ssh_userauth_kbdint_getprompt(my_ssh, 0, nullptr);
		}(my_ssh);
  
  auto chal = [](auto& my_ssh, string prompt){
		   auto chal{prompt.substr(0,prompt.find("\n\nFor QR"))};
		   if (chal=="")
		     throw runtime_error("invalid challenge");
		   return chal;
	      }(my_ssh, prompt);

  auto resp = [](string chal, auto& callback){
		string resp{callback(chal)};
		return resp.substr(resp.find(":")+2, resp.npos);
	      }(chal, callback);
  
  if (ssh_userauth_kbdint_setanswer(my_ssh, 0, resp.c_str()) < 0)
    throw runtime_error("failed to set answear");

  auto sshlambda{[&my_ssh](){return ssh_userauth_kbdint(my_ssh, "docker", nullptr);}};
  int retries{5};
  auto rc{sshlambda()};
  for (int i{0}; rc == SSH_AUTH_INFO && i < retries; i++)
    {
      rc = sshlambda();
    }

  if (rc != SSH_AUTH_SUCCESS)
    {
      stringstream ss{};
      ss << " err: " << rc << " returned";
      throw runtime_error("failed to connect with response: " +
			  resp +
			  string{" | "} + string{ssh_get_error(my_ssh)}  +
			  string{" | "} + ss.str());
    } else {
    cout << "success" << endl;
  }
}

int main()
{
  globalRaii init{};

  cout << "test good response\n";
  checkresponse([](string chal){return poster(chal).get();});

  cout << "test bad response\n";
  string unexpected{"bad response did not fail"};
  try
    {
      checkresponse([](string chal){return string{"bad : response"};});
      throw runtime_error(unexpected);
    }
  catch (runtime_error e)
    {
      if (e.what() == unexpected)
	throw e;
    }
  cout << "success\n";

  //TODO: test grabbing QR via HTTPS with good credentials

  //TODO: test that QR == challenge

  //TODO: test grabbing QR via HTTP fails

  //TODO: test grabbing QR via HTTPS with bad credentials fails
  
}
