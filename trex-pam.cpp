/*
  Copyright 2019 Sharon Dvir

  Unless authorized beforehand and in writting by the author,
  this program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD

#include <fstream>
#include <chrono>
#include <qrcodegen/QrCode.hpp>
#include <boost/algorithm/string.hpp>
#include "common-raii/common-raii.h"

using namespace std;
using namespace commonRaii;

/*
  Helper class to get challenges.
*/
class challengeHandler {
private:
  
  string nonce(int len = 10)
  {
    return getNonce(len);
  }

public:
  challengeHandler(){}

  pair<string, string> getChallenge(string gpgHome, string recp)
  {
    auto pass{nonce()};
    auto plaintext{pass};
    encrypter enc{plaintext, gpgHome};
    return {enc.ciphertext(recp, true, false, ""s),pass};
  }
};

/*
  helper to parse a config line into parameters
*/
class userRecord {
private:
  string trustStr;
public:
  string encryptTo, signStr, webQr, key, pem;
  bool trustFlag, signFlag;
  userRecord(){}
  userRecord(string ss)
  {
    stringstream s{ss};
    s >> encryptTo;
    if(s)
      s >> webQr;
    if(s)
      s >> key;
    if(s)
      s >> pem;
  }
  auto get()
  {
    return make_tuple(encryptTo, webQr, key, pem);
  }
};

/*
  helper to parse a config file
*/
class userDb {
private:
  userRecord rec;
  bool hasKey{false};
public:
  userDb(string p)
  {
    fstream f{p+"/.auth_gpg"};
    if (!f)
      return;

    string l;
    while (getline(f, l))
      {
	if (l.length() == 0 || l[0]=='#')
	  continue;
	userRecord r{l};
	rec = r;
	hasKey = true;
	break;
      }
  }

  bool has()
  {
    return hasKey;
  }

  auto get()
  {
    return rec.get();
  }
};


string globalChallenge{};

/*
  wrapper around libcppgenqr to get a qr representation of a string
*/
string getQR()
{
  const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(globalChallenge.c_str(), qrcodegen::QrCode::Ecc::QUARTILE);//TODO: in order to use HIGH, split the challenge into 10556 bits pieces or risk 'qrcodegen::data_too_long' exception
  return qr.toSvgString(1);
}

//globals, carefull.
string globalUser, globalPass;
bool globalAuth;

/*
  called by libmicrohttpd
  serve a QR image over http/s and optionally authenticate the requester.
*/
static int
answer_to_connection (void *cls, struct MHD_Connection *connection,
		      const char *url, const char *method,
		      const char *version, const char *upload_data,
		      size_t *upload_data_size, void **con_cls)
{
  int fail;
  int ret;

  if (0 != strncmp (method, "GET", 4))
    return MHD_NO;
  if (NULL == *con_cls)
    {
      *con_cls = connection;
      return MHD_YES;
    }

  char *user;
  char *pass;
  pass = NULL;

  user = MHD_basic_auth_get_username_password (connection, &pass);

  unique_ptr<char[],void (*)(void*)> userRaii(user,free);//freed by C free()
  unique_ptr<char[],void (*)(void*)> passRaii(pass,free);//freed by C free()

  if ( globalAuth && (!userRaii || !passRaii ||
		      string{userRaii.get()} != globalUser ||
		      string{passRaii.get()} != globalPass ))
    {
      const char *page = "<html><body>Invalid credentials</body></html>";
      auto response{mhdRespRaii(page)};
      ret = MHD_queue_basic_auth_fail_response (connection,
						"QR login",
						response.get());
      return ret;
    }

  auto qr{getQR()};
  string strayXml{R"(<?xml version="1.0" encoding="UTF-8"?>)"};
  string strayDoc{R"(<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">)"};
  qr.replace(qr.find(strayXml), strayXml.length(),""s);
  qr.replace(qr.find(strayDoc), strayDoc.length(),""s);
  auto content = "<!DOCTYPE html><html><head>"s+
    R"(<style>
     figure {
         max-width: 17cm;
     }
     </style>)" +
    "<title>QR challenge</title></head><body><figure>"s +
    qr +
    "</figure></body></html>"s;
  auto response{mhdRespRaii(content)};
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response.get());
  return ret;
}

/*
  helper to make sense of the QR parameter in the config
*/
auto handleAuthTlsParams(string webQr)
{
  bool webQrFlag{(webQr=="webQrAuthTls")||//TODO: refactor strings
		 (webQr=="webQrNoAuthTls")||
		 (webQr=="webQrAuthNoTls")||
		 (webQr=="webQrNoAuthNoTls")};
  globalAuth = (webQrFlag &&
		!(webQr=="webQrNoAuthNoTls" || webQr=="webQrNoAuthTls"));
  bool tlsFlag = {webQrFlag &&
		  !(webQr=="webQrNoAuthNoTls" || webQr=="webQrAuthNoTls")};

  return make_tuple(webQrFlag, tlsFlag);
}

/*
  RAII class to hold a webserver to serve QR codes
*/
class webServerRaii {//TODO: move to commonRaii
private:
  struct MHD_Daemon * d{nullptr};
  static constexpr int fileSize{2'000};
  char key_pem[fileSize]{""};
  char cert_pem[fileSize]{""};
  bool tlsFlag;
public:
  webServerRaii(bool _tlsFlag = true, string key = ""s, string cert = ""s):tlsFlag{_tlsFlag} {
    //if needed, use TLS
    if (tlsFlag)
      {
	ifstream keyRead{key};
	if (!keyRead)
	  throw(runtime_error{"Can't open key file"s});
	keyRead.get(key_pem, fileSize-1,'\0');
	ifstream certRead{cert};
	if (!certRead)
	  throw(runtime_error{"Can't open cert file"s});
	certRead.get(cert_pem, fileSize-1,'\0');
      }
  }

  //start serving QR, return a string description to display to the user
  //  should have been called by ctor, but couldn't due to scoping issues in pam_auth
  string start()
  {
    string clearMsg{};
    int useTls{tlsFlag?MHD_USE_TLS:0};
    d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | useTls,
			 0,
			 nullptr,
			 nullptr,
			 &answer_to_connection,
			 nullptr,
			 MHD_OPTION_HTTPS_MEM_KEY, key_pem,
			 MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
			 MHD_OPTION_END);
    if (!d)
      {
	clearMsg = "\nFailed starting server for QR "s + clearMsg;
      } else {
      stringstream ss{};
      auto dinfo{MHD_get_daemon_info(d, MHD_DAEMON_INFO_BIND_PORT)};
      ss<<"\nFor QR point your browser at http"s << (tlsFlag?"s"s:""s) << "://<this-host>:"s<<dinfo->port;
      if (globalAuth)
	ss<<"\nAuthenticate as '" << globalUser << "' and '"s<<globalPass<<"'";
      clearMsg = ss.str() + clearMsg;
    }
    return clearMsg;
  }

  ~webServerRaii() {
    if (d)
      {
	MHD_stop_daemon(d);
      }
  }
};

/*
  main event.
  create a challenge, get a response, 
  validate that the user is able to decrypt using a key that was preconfigured.
*/
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
#ifdef HAVE_PAM_FAIL_DELAY
  pam_fail_delay (pamh, 2'000'000);
#endif /* HAVE_PAM_FAIL_DELAY */

  if (flags & PAM_SILENT)
    {
      pam_syslog(pamh, LOG_WARNING, "can't operate in silent mode");
      return PAM_IGNORE;
    }

  constexpr auto maxUsernameSize = 100;
  const char *userChar[maxUsernameSize]{nullptr};

  //get user name, or fail
  if (pam_get_user(pamh, userChar, nullptr)!=PAM_SUCCESS || !userChar || !*userChar)
    {
      pam_syslog(pamh, LOG_WARNING, "pam_get_user() failed");
      return PAM_USER_UNKNOWN;
    }
  string user{*userChar, maxUsernameSize - 1};

  //get homedir, or fail
  auto userPw(getpwnam(user.c_str()));
  if (!userPw)
    {
      pam_syslog(pamh, LOG_WARNING, "can't get homedir of pam user");
      return  PAM_AUTHINFO_UNAVAIL;
    }

  //drop privilleges, or fail
  privDropper priv{pamh, userPw};

  //parse config file, or fail
  string homeDir{userPw->pw_dir};
  userDb db{homeDir};
  if(!db.has())
    {
      pam_syslog(pamh, LOG_WARNING, "pam user has no valid .auth_gpg file under $HOME");
      return PAM_IGNORE;
    }

  //get all params from parsed config file
  auto [reciever, webQr, key, cert] = db.get();
  auto [webQrFlag, tlsFlag] = handleAuthTlsParams(webQr);

  try
    {
      challengeHandler ver{};
      auto gpHomeCstr{pam_getenv(pamh, "GNUPGHOME")};
      string gnupgHome{gpHomeCstr?gpHomeCstr:".gnupg"s};

      //generate challenge
      auto [challenge, pass]{ver.getChallenge(homeDir+"/"s+gnupgHome, reciever)};
      auto clearMsg{"\nTimeout set for 10 minutes\nResponse:"s};

      //hold a non running webserver.
      //  must be declared in this scope.
      webServerRaii qrServer(tlsFlag, key, cert);

      //globals used by libmicrohttpd
      globalChallenge = challenge;
      globalPass = getNonce(10);
      globalUser = user.substr(0, user.find('\0'));

      //if needed, start a webserver to serve QR
      if (webQrFlag)
	clearMsg = qrServer.start() + clearMsg;

      //get a response from the user
      auto timeOut{chrono::system_clock::now() + 10min};
      auto response{converse(pamh, challenge + clearMsg)};

      //verify that the user supplied the correct response in time
      if (response == pass && timeOut > chrono::system_clock::now())
	{
	  return PAM_SUCCESS;
	}
      pam_syslog(pamh, LOG_WARNING, "wrong response or timeout reached");
      return PAM_AUTH_ERR;
    }
  //handle exceptions
  catch(const runtime_error& ex)
    {
      string errMsg{"internal exception thrown: "s + ex.what()};
      pam_syslog(pamh, LOG_WARNING, errMsg.c_str() );
      return PAM_AUTH_ERR;
    }
  catch(const exception& ex)
    {
      string errMsg{"non internal exception thrown: "s + ex.what()};
      pam_syslog(pamh, LOG_WARNING, errMsg.c_str());
      return PAM_AUTH_ERR;
    }
  catch(...)
    {
      pam_syslog(pamh, LOG_WARNING, "unknown exception thrown");
      return PAM_AUTH_ERR;
    }
  pam_syslog(pamh, LOG_WARNING, "fallen off the end of pam_sm_authenticate()");
  return PAM_AUTH_ERR;
}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}
