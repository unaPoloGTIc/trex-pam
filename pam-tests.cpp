#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <regex>

extern "C" {
#include <security/pam_appl.h>
#include <gpgme.h>
#include <curl/curl.h>
}

using namespace std;

//TODO: refactor to use commonRaii classes

TEST(unitTests, emptyTest)
{
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  string module_name{"mmotd-module"s};//valgrind is giving me much pain, unjustly I think.
  string user_name{"sharon"s};
  ASSERT_EQ(pam_start(module_name.c_str(), user_name.c_str(), &pam_conversation, &pamh), PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, PAM_SILENT), PAM_PERM_DENIED);
  ASSERT_EQ(pam_end(pamh, PAM_SUCCESS), PAM_SUCCESS);
}

class Unit : public ::testing::Test {
protected:
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

public:
  Unit()
  {
    pam_start("mmotd-module", "sharon", &pam_conversation, &pamh);

    gpgme_check_version (NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

    gpgme_new(&ctx);
    gpgme_ctx_set_engine_info(ctx,
			      GPGME_PROTOCOL_OpenPGP,
			      NULL,
			      "/home/sharon/.gnupg");
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
  }
  ~Unit()
  {
    pam_end(pamh, PAM_SUCCESS);
    if (out)
      gpgme_data_release (out);
    if (in)
      gpgme_data_release (in);
    gpgme_release (ctx);
  }
};

TEST_F(Unit, unitFixureTest)
{
  ASSERT_EQ(pam_authenticate(pamh, PAM_SILENT), PAM_PERM_DENIED);
}

TEST_F(Unit, verifyUnusedFunctions)
{
  ASSERT_EQ(pam_setcred(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_acct_mgmt(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_open_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_close_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_chauthtok(pamh, 0), PAM_PERM_DENIED);
}

//TODO: add tests that verify that module throws the right exceptions

vector<string> globalRet{};//TODO: move to fixture

int badConvFunc(int num_msg, const struct pam_message **msg,
	     struct pam_response **resp, void *appdata_ptr)//TODO: move to fixture
{
  globalRet.push_back(string{msg[0]->msg});
  char *deletedByPam = new char[100];
  strcpy(deletedByPam,  "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

int goodConvFunc(int num_msg, const struct pam_message **msg,
	     struct pam_response **resp, void *appdata_ptr)//TODO: move to fixture
{
  char *deletedByPam = new char[100];
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  gpgme_check_version (NULL);//TODO: use a gpgme raii wrapper
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

  gpgme_new(&ctx);
  gpgme_ctx_set_engine_info(ctx,
			    GPGME_PROTOCOL_OpenPGP,
			    NULL,
			    "/home/sharon/.gnupg");
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

  gpgme_data_new_from_mem(&in,
			  msg[0]->msg,
			  strlen(msg[0]->msg),
			  1);
  gpgme_data_new (&out);
  gpgme_op_decrypt_ext(ctx, flags, in, out);
  char buf[501] = "";
  int ret = gpgme_data_seek (out, 0, SEEK_SET);
  stringstream ss{};
  while ((ret = gpgme_data_read (out, buf, 500)) > 0)
    {
      ss<<string{buf};
    }
  string pre{ss.str()};
  pre.replace(pre.end()-1,pre.end(),"");
  strcpy(deletedByPam, ss.str().c_str());
  gpgme_data_release (out);
  gpgme_data_release (in);
  gpgme_release (ctx);

  return PAM_SUCCESS;
}

TEST_F(Unit, testUserWithNoAuth_gpg)
{
  //make sure you have avahi in /etc/passwd and it has no .auth_gpg
  ASSERT_EQ(pam_set_item(pamh, PAM_USER,"avahi"),PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0),PAM_PERM_DENIED);
}

TEST_F(Unit, testSettingNonexistingInSystemUser)
{
  //make sure you don't have a user called nouserInSystem
  ASSERT_EQ(pam_set_item(pamh, PAM_USER,"nouserInSystem"),PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testBadResponse)
{
  pam_conversation.conv = &badConvFunc;
  char tmp[] = "wrong response";
  pam_conversation.appdata_ptr = static_cast<void*>(tmp);
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit,  testChallengeDecrypts)
{
  pam_conversation.conv = &badConvFunc;
  char tmp[] = "wrong response";
  pam_conversation.appdata_ptr = static_cast<void*>(tmp);
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(gpgme_data_new_from_mem(&in,globalRet[0].c_str(),
  				    globalRet[0].size()+1,
  				    1),GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_data_new (&out),GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_decrypt_ext(ctx, flags, in, out),GPG_ERR_NO_ERROR);
}

TEST_F(Unit, testGoodResponse)
{
  pam_conversation.conv = &goodConvFunc;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
}

TEST_F(Unit, testDecryptedChallengeUnique)
{
  vector<string> allChallenges{};
  for (int i = 0; i < 3; i++)
    {
      pam_conversation.conv = &badConvFunc;
      pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation));
      globalRet.clear();
      pam_authenticate(pamh, 0);
      gpgme_data_new_from_mem(&in,globalRet[0].c_str(),
			      globalRet[0].size()+1,
			      1);
      gpgme_data_new (&out);
      gpgme_op_decrypt_ext(ctx, flags, in, out);
      char buf[501] = "";
      int ret = gpgme_data_seek (out, 0, SEEK_SET);
      stringstream ss{};
      while ((ret = gpgme_data_read (out, buf, 500)) > 0)
	{
	  ss<<string{buf};
	}
      allChallenges.push_back(ss.str());
    }
  sort(allChallenges.begin(),allChallenges.end());
  vector<string>  uniq(allChallenges.begin(),unique(allChallenges.begin(),allChallenges.end()));
  ASSERT_EQ(allChallenges.size(),uniq.size());
}

TEST_F(Unit, testChallengeIsSignedByAppliance)
{
  pam_conversation.conv = &badConvFunc;
  char tmp[] = "v1 legalV1Resp";
  pam_conversation.appdata_ptr = static_cast<void*>(tmp);
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);

  ASSERT_EQ(gpgme_data_new_from_mem(&in,globalRet[0].c_str(),
  				    globalRet[0].size()+1,
  				    1),GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_data_new (&out),GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_decrypt_verify(ctx, in, out),GPG_ERR_NO_ERROR);
  auto res {gpgme_op_verify_result(ctx)};
  ASSERT_NE(res->signatures, nullptr);
  ASSERT_EQ(res->signatures->status,GPG_ERR_NO_ERROR);
  ASSERT_EQ(res->signatures->validity,GPGME_VALIDITY_FULL);//this just means we trust the key
  ASSERT_NE(res->signatures->fpr ,nullptr);
  ASSERT_STREQ(res->signatures->fpr ,"F546A72A7A1D59E8753958AB358F22DA9DB0B9F0");//replace as needed
  ASSERT_TRUE(res->signatures->next == nullptr);
}

//TODO: test that timeout fails

class curly{
private:
public:
  CURL *curl;
  stringstream ss;
  curly(string host, string name, string pass):curl{curl_easy_init()}
  {
    ss.clear();
    if (!curl)
      throw runtime_error{"can't init curl\n"s};
    //TODO: remove if unneeded
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ss);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, string{name+":"+pass}.c_str());
    auto res{curl_easy_perform(curl)};
  }

  ~curly()
  {
    curl_easy_cleanup(curl);
  }

  static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
  {
    auto streamPtr{static_cast<stringstream*>(userp)};
    *streamPtr << string{static_cast<char*>(buffer)};
    return nmemb;
  }

  string get()
  {
    return ss.str();
  }
};

int curlyConvFunc(int num_msg, const struct pam_message **msg,
	     struct pam_response **resp, void *appdata_ptr)//can't move to fixture
{
  string chal{msg[0]->msg};
  chal = chal.substr(chal.find(">:"));
  chal = chal.substr(0, chal.find_last_of("'"));

  string host{static_cast<char*>(appdata_ptr)};
  string port{chal.substr(chal.find(":")+1, chal.find("\n")-2)};
  string name{chal.substr(chal.find(" '")+2)};
  name = name.substr(0, name.find("' "));
  string pass{chal.substr(chal.rfind(" '")+2)};

  curly c{host+port, name, pass};
  globalRet.push_back(c.get());

  char *deletedByPam = new char[100];
  strcpy(deletedByPam,  "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

int curlyWrongPassConvFunc(int num_msg, const struct pam_message **msg,
	     struct pam_response **resp, void *appdata_ptr)//can't move to fixture
{
  string chal{msg[0]->msg};
  chal = chal.substr(chal.find(">:"));
  chal = chal.substr(0, chal.find_last_of("'"));

  string port{chal.substr(chal.find(":")+1, chal.find("\n")-2)};
  string name{chal.substr(chal.find(" '")+2)};
  name = name.substr(0, name.find("' "));

  curly c{"https://localhost:"s+port, name, "wrong password"s};
  globalRet.push_back(c.get());

  char *deletedByPam = new char[100];
  strcpy(deletedByPam,  "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

TEST_F(Unit, getQR)
{
  pam_conversation.conv = &curlyConvFunc;
  char host[] = "https://localhost:";
  pam_conversation.appdata_ptr = host;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);

  string qr{globalRet[0]};

  ASSERT_GE(qr.size(), 100'000);
  ASSERT_NE(qr.find("<svg xmlns=\"http://www.w3.org/2000/svg\""), string::npos);
  ASSERT_NE(qr.find("</svg>"), string::npos);
}

TEST_F(Unit, qrFailHttp)
{
  pam_conversation.conv = &curlyConvFunc;
  char host[] = "http://localhost:";
  pam_conversation.appdata_ptr = host;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);

  string qr{globalRet[0]};

  ASSERT_EQ(qr.size(), 0);
}

TEST_F(Unit, qrFailWrongPass)
{
  pam_conversation.conv = &curlyWrongPassConvFunc;
  pam_conversation.appdata_ptr = nullptr;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation)), PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);

  string err{globalRet[0]};
  ASSERT_EQ(err,"<html><body>Invalid credentials</body></html>"s);
}

class globalRaii{
public:
  globalRaii()
  {
    curl_global_init(CURL_GLOBAL_ALL);
  }
  ~globalRaii()
  {
    curl_global_cleanup();
  }
};

int main(int argc, char **argv) {
  globalRaii init{};
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
