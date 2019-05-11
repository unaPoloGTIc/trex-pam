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

extern "C" {
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <gpgme.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <syslog.h>
#include <microhttpd.h>
}

#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <sstream>
#include <memory>
#include <random>
#include <algorithm>
#include <chrono>
#include <map>
#include <future>
#include <qrcodegen/QrCode.hpp>
#include <boost/algorithm/string.hpp>

using namespace std;

#define DEFAULT_USER "nobody"

/*
  RAII wrapper around PAM's conversation convention.
  Presents *in* to the user and returns the reply that was supplied.
*/
template<typename resp>
resp converse(pam_handle_t *pamh, string in)
{
  const void *vconv{nullptr};
  if (pam_get_item(pamh, PAM_CONV, &vconv) == PAM_SUCCESS)
    {
      const struct pam_conv *conv{static_cast<decltype(conv)>(vconv)};
      try
	{
	  if (vconv != nullptr && conv != nullptr && conv->conv != nullptr)
	    {
	      pam_message m{PAM_PROMPT_ECHO_ON, in.c_str() };
	      pam_response *rr{nullptr};
	      array<const struct pam_message*, 1> marr{&m};

	      if (conv->conv(marr.size(), marr.data(), &rr, conv->appdata_ptr) != PAM_SUCCESS)
		throw runtime_error("App callback failed"s);

	      if (rr != nullptr && rr->resp != nullptr)
		{
		  unique_ptr<char[]> uniqResp(rr->resp);
		  string stealResp{uniqResp.get()};
		  return resp{stealResp};
		}
	      throw runtime_error("Empty response"s);
	    }
	}
      catch(...)
	{
	  throw;
	}
    }
  throw runtime_error("pam_get_item() failed"s);
}

/*
  RAII class to release gpgme keys when leaving scope.
*/
class keyRaii{
private:
  gpgme_key_t key;

public:
  keyRaii():key{nullptr}{}
  ~keyRaii()
  {
    if (key)
      gpgme_key_release (key);
  }

  gpgme_key_t &get()
  {
    return key;
  }
  
};

/*
  RAII class to release gpgme data when leaving scope.
*/
class gpgme_data_raii{
private:
  gpgme_data_t data = nullptr;
  gpgme_error_t err;
public:
  gpgme_data_raii(const string& str)
  {
    if (auto err{gpgme_data_new_from_mem(&data,str.c_str(), str.length(), 1)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme data from mem "s + string{gpgme_strerror(err)});
  }
  gpgme_data_raii()
  {
    if (auto err{gpgme_data_new(&data)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme empty data "s + string{gpgme_strerror(err)});
  }

  gpgme_data_t& get()
  {
    return data;
  }

  ~gpgme_data_raii(){
    if(data)
      gpgme_data_release (data);
  }
};

/*
  RAII class to release gpgme ctx when leaving scope.
*/
class gpgme_ctx_raii{
private:
  gpgme_ctx_t ctx;
  static const gpgme_protocol_t proto{GPGME_PROTOCOL_OpenPGP};
public:
  gpgme_ctx_raii(string gpgHome)
  {
    gpgme_check_version (NULL);
    if (auto err{gpgme_engine_check_version(proto)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init libgpgme "s + string{gpgme_strerror(err)});

    if (auto err{gpgme_new(&ctx)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't create libgpgme context "s + string{gpgme_strerror(err)});
    if (auto err{gpgme_ctx_set_engine_info(ctx, proto, NULL, gpgHome.c_str())}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't set libgpgme engine info "s +  string{gpgme_strerror(err)});
    if (auto err{gpgme_set_protocol(ctx, proto)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't set libgpgme protocol "s + string{gpgme_strerror(err)});

    gpgme_set_armor (ctx, 1);
  }

  gpgme_ctx_t& get()
  {
    return ctx;
  }

  ~gpgme_ctx_raii()
  {
    if(ctx)
      gpgme_release(ctx);
  }
};

/*
  RAII wrapper around GPGME encryption operations.
*/
class encrypter {
private:
  string plain, gpgHome;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);

  /*
    RAII helper to encrypt ro the public key of *recp*, optionally signing as *sender*
  */
  string encPub(string recp, bool trust = false, bool sign = true, string sender = ""s)
  {
    gpgme_ctx_raii ctx(gpgHome);
    gpgme_data_raii in{plain};
    gpgme_data_raii out{};

    string recpFormatted{"--\n "s + recp + " \n"s};
    gpgme_encrypt_flags_t params{trust?GPGME_ENCRYPT_ALWAYS_TRUST:static_cast<gpgme_encrypt_flags_t>(0)};
    if (sign)
      {
	if (auto err{gpgme_op_keylist_start (ctx.get(), sender.c_str(), 0)}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_start() failed"s + string{gpgme_strerror(err)});
	keyRaii key;
	if (auto err{gpgme_op_keylist_next (ctx.get(), &key.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_next() failed "s + string{gpgme_strerror(err)});
	if (auto err{gpgme_op_keylist_end(ctx.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_end() failed "s + string{gpgme_strerror(err)});
	if (auto err{gpgme_signers_add (ctx.get(), key.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("Can't add signer "s + sender + " " + string{gpgme_strerror(err)});
	if (auto err{gpgme_op_encrypt_sign_ext(ctx.get(),
					       NULL,
					       recpFormatted.c_str(),
					       params,
					       in.get(),
					       out.get())}; err != GPG_ERR_NO_ERROR)
	  {
	    throw runtime_error("Can't encrypt/sign with keys "s + recp + ", " + sender + " : " + string{gpgme_strerror(err)});
	  }
      }
    else
      {
	if (auto err{gpgme_op_encrypt_ext(ctx.get(),
					  NULL,
					  recpFormatted.c_str(),
					  params,
					  in.get(),
					  out.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("Can't encrypt to "s + recp + " "s +  string{gpgme_strerror(err)});
      }

    constexpr int buffsize{500};
    char buf[buffsize + 1] = "";
    int ret = gpgme_data_seek (out.get(), 0, SEEK_SET);
    string s{};
    while ((ret = gpgme_data_read (out.get(), buf, buffsize)) > 0)
      {
	buf[ret] = '\0';
	s += string{buf};
      }
    return s;
  }

public:

  /*
    RAII wrapper around a gpgme engine
  */
  encrypter(string s, string gpghome):plain{s},gpgHome{gpghome}
  {}

  string ciphertext(string recp, bool trust = false, bool sign = true, string sender = "")
  {
    return encPub(recp, trust, sign, sender);
  }
};

/*
  returns a (hopefully) uniformlly random alphanumeric (lower+uppercase) string of length *len*
*/
string getNonce(int len = 10)
{
  static string chars{"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"s};
  auto ret{""s};
  random_device rd{};
  mt19937 g{rd()};
  uniform_int_distribution<> d(0, chars.size()-1);
  
  shuffle(chars.begin(), chars.end(), g);
  
  for (int i=0; i < len; i++)
    ret.push_back(chars[d(g)]);
  return ret;
}

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

  pair<string, string> getChallenge(string gpgHome, string recp, bool trust=false, bool sign=true, string sender="")
  {
    auto pass{nonce()};
    auto plaintext{pass};
    encrypter enc{plaintext, gpgHome};
    return {enc.ciphertext(recp, trust, sign, sender),pass};
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
    s >> trustStr;
    s >> signStr;
    if(s)
      s >> webQr;
    if(s)
      s >> key;
    if(s)
      s >> pem;

    trustFlag = (trustStr=="trust"s);
    signFlag = !(signStr=="nosign"s);
  }
  auto get()
  {
    return make_tuple(encryptTo, trustFlag, signStr, signFlag, webQr, key, pem);
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

/*
  RAII class to temporarilly drop privilleges using setegid,seteuid
*/
class privDropper{
private:
  uid_t origUid;
  gid_t origGid;
  bool dropped;
  pam_handle_t *pamh;
public:
  privDropper(pam_handle_t *pam, struct passwd *p):pamh{pam},origUid{geteuid()}, origGid{getegid()}, dropped{false}
  {
    if (origUid == 0)
      {
	if (setegid(p->pw_gid) != 0)
	  throw runtime_error{"setegid() failed"s};
	if (seteuid(p->pw_uid) != 0)
	  {
	    setegid(origGid);//Should be RAII but it's probably useless if we got here
	    throw runtime_error{"seteuid() failed"s};
	  }
	dropped = true;
      }

  }
  ~privDropper()
  {
    if (dropped)
      {
	if (seteuid(origUid) != 0 || setegid(origGid) != 0)
	  {
	    pam_syslog(pamh, LOG_WARNING, "failed regaining privs, remaining pam modules in the stack might misbehave");
	  }
      }
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

//RAII class to hold a MHD_response
class mhdRespRaii {
private:
  struct MHD_Response *response;
public:
  mhdRespRaii(string page)
  {
    response = MHD_create_response_from_buffer (page.length(),
						(void *)(page.c_str()),
						MHD_RESPMEM_MUST_COPY);
  }
  ~mhdRespRaii()
  {
    if (response)
      MHD_destroy_response (response);
  }
  auto get()
  {
    return response;
  }
};

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

  unique_ptr<char[]> userRaii(user);
  unique_ptr<char[]> passRaii(pass);

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
class webServerRaii {
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
  if (pam_get_user(pamh, userChar, nullptr)!=PAM_SUCCESS || !userChar)
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
  auto [reciever, trust, signAs, sign, webQr, key, cert] = db.get();
  auto [webQrFlag, tlsFlag] = handleAuthTlsParams(webQr);

  try
    {
      challengeHandler ver{};
      auto gpHomeCstr{pam_getenv(pamh, "GNUPGHOME")};
      string gnupgHome{gpHomeCstr?gpHomeCstr:".gnupg"s};

      //generate challenge
      auto [challenge, pass]{ver.getChallenge(homeDir+"/"s+gnupgHome, reciever, trust, sign, signAs)};
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
      auto response{converse<string>(pamh, challenge + clearMsg)};

      //verify that the user supplied the correct response in time
      auto timeOut{chrono::system_clock::now() + 10min};
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
