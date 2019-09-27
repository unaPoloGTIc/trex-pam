#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include <curl/curl.h>
#include <gpgme.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <sys/types.h>
}

using namespace std;
namespace fs = std::filesystem;

// TODO: refactor to use commonRaii classes

TEST(unitTests, emptyTest) {
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  auto pw{getpwuid(geteuid())};
  string user_name{pw->pw_name};
  ASSERT_EQ(
      pam_start("mmotd-module", user_name.c_str(), &pam_conversation, &pamh),
      PAM_SUCCESS);
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
  Unit() {
    auto pw{getpwuid(geteuid())};
    pam_start("mmotd-module", pw->pw_name, &pam_conversation, &pamh);

    gpgme_check_version(NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

    gpgme_new(&ctx);
    gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, "~/.gnupg");
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
  }
  ~Unit() {
    pam_end(pamh, PAM_SUCCESS);
    if (out)
      gpgme_data_release(out);
    if (in)
      gpgme_data_release(in);
    gpgme_release(ctx);
  }
};

TEST_F(Unit, unitFixureTest) {
  ASSERT_EQ(pam_authenticate(pamh, PAM_SILENT), PAM_PERM_DENIED);
}

TEST_F(Unit, verifyUnusedFunctions) {
  ASSERT_EQ(pam_setcred(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_acct_mgmt(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_open_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_close_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_chauthtok(pamh, 0), PAM_PERM_DENIED);
}

vector<string> globalRet{};

int badConvFunc(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr) {
  globalRet.push_back(string{msg[0]->msg});
  char *deletedByPam = new char[100];
  strcpy(deletedByPam, "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

int goodConvFunc(int num_msg, const struct pam_message **msg,
                 struct pam_response **resp, void *appdata_ptr) {
  char *deletedByPam = new char[100];
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  gpgme_check_version(NULL); // TODO: use a gpgme raii wrapper
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

  gpgme_new(&ctx);
  gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, "~/.gnupg");
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

  gpgme_data_new_from_mem(&in, msg[0]->msg, strlen(msg[0]->msg), 1);
  gpgme_data_new(&out);
  gpgme_op_decrypt_ext(ctx, flags, in, out);
  char buf[501] = "";
  int ret = gpgme_data_seek(out, 0, SEEK_SET);
  stringstream ss{};
  while ((ret = gpgme_data_read(out, buf, 500)) > 0) {
    ss << string{buf};
  }
  strcpy(deletedByPam, ss.str().c_str());
  gpgme_data_release(out);
  gpgme_data_release(in);
  gpgme_release(ctx);

  return PAM_SUCCESS;
}

TEST_F(Unit, testUserWithNoAuth_gpg) {
  // make sure you have avahi in /etc/passwd and it has no .auth_gpg
  ASSERT_EQ(pam_set_item(pamh, PAM_USER, "avahi"), PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testSettingNonexistingUser) {
  // make sure you don't have a user called nouserInSystem
  ASSERT_EQ(pam_set_item(pamh, PAM_USER, "nouserInSystem"), PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testBadResponse) {
  pam_conversation.conv = &badConvFunc;
  char tmp[] = "wrong response";
  pam_conversation.appdata_ptr = static_cast<void *>(tmp);
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  globalRet.clear();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testChallengeDecrypts) {
  pam_conversation.conv = &badConvFunc;
  char tmp[] = "wrong response";
  pam_conversation.appdata_ptr = static_cast<void *>(tmp);
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  globalRet.clear();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
  ASSERT_NE(0, globalRet.size());
  ASSERT_EQ(gpgme_data_new_from_mem(&in, globalRet[0].c_str(),
                                    globalRet[0].size() + 1, 1),
            GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_data_new(&out), GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_decrypt_ext(ctx, flags, in, out), GPG_ERR_NO_ERROR);
}

TEST_F(Unit, testGoodResponse) {
  pam_conversation.conv = &goodConvFunc;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
}

TEST_F(Unit, testDecryptedChallengeUnique) {
  vector<string> allChallenges{};
  for (int i = 0; i < 3; i++) {
    pam_conversation.conv = &badConvFunc;
    pam_set_item(pamh, PAM_CONV, static_cast<const void *>(&pam_conversation));
    globalRet.clear();
    pam_authenticate(pamh, 0);
    ASSERT_NE(0, globalRet.size());
    gpgme_data_new_from_mem(&in, globalRet[0].c_str(), globalRet[0].size() + 1,
                            1);
    gpgme_data_new(&out);
    gpgme_op_decrypt_ext(ctx, flags, in, out);
    char buf[501] = "";
    int ret = gpgme_data_seek(out, 0, SEEK_SET);
    stringstream ss{};
    while ((ret = gpgme_data_read(out, buf, 500)) > 0) {
      ss << string{buf};
    }
    allChallenges.push_back(ss.str());
  }
  sort(allChallenges.begin(), allChallenges.end());
  vector<string> uniq(allChallenges.begin(),
                      unique(allChallenges.begin(), allChallenges.end()));
  ASSERT_EQ(allChallenges.size(), uniq.size());
}

// TODO: test that timeout fails

class curly {
private:
public:
  CURL *curl;
  stringstream ss;
  curly(string host, string name, string pass) : curl{curl_easy_init()} {
    ss.clear();
    if (!curl)
      throw runtime_error{"can't init curl\n"s};
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ss);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, string{name + ":" + pass}.c_str());
    auto res{curl_easy_perform(curl)};
  }

  ~curly() { curl_easy_cleanup(curl); }

  static size_t write_data(void *buffer, size_t size, size_t nmemb,
                           void *userp) {
    auto streamPtr{static_cast<stringstream *>(userp)};
    *streamPtr << string{static_cast<char *>(buffer)};
    return nmemb;
  }

  string get() { return ss.str(); }
};

int curlyConvFunc(int num_msg, const struct pam_message **msg,
                  struct pam_response **resp, void *appdata_ptr) {
  string chal{msg[0]->msg};
  chal = chal.substr(chal.find(">:"));
  chal = chal.substr(0, chal.find_last_of("'"));

  string host{static_cast<char *>(appdata_ptr)};
  string port{chal.substr(chal.find(":") + 1, chal.find("\n") - 2)};
  string name{chal.substr(chal.find(" '") + 2)};
  name = name.substr(0, name.find("' "));
  string pass{chal.substr(chal.rfind(" '") + 2)};

  curly c{host + port, name, pass};
  globalRet.push_back(c.get());

  char *deletedByPam = new char[100];
  strcpy(deletedByPam, "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

int curlyWrongPassConvFunc(int num_msg, const struct pam_message **msg,
                           struct pam_response **resp, void *appdata_ptr) {
  string chal{msg[0]->msg};
  chal = chal.substr(chal.find(">:"));
  chal = chal.substr(0, chal.find_last_of("'"));

  string port{chal.substr(chal.find(":") + 1, chal.find("\n") - 2)};
  string name{chal.substr(chal.find(" '") + 2)};
  name = name.substr(0, name.find("' "));

  curly c{"https://localhost:"s + port, name, "wrong password"s};
  globalRet.push_back(c.get());

  char *deletedByPam = new char[100];
  strcpy(deletedByPam, "bad_response");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

TEST_F(Unit, getQR) {
  pam_conversation.conv = &curlyConvFunc;
  char host[] = "https://localhost:";
  pam_conversation.appdata_ptr = host;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);
  ASSERT_NE(0, globalRet.size());
  string qr{globalRet[0]};

  ASSERT_GE(qr.size(), 100'000);
  ASSERT_NE(qr.find("<svg xmlns=\"http://www.w3.org/2000/svg\""), string::npos);
  ASSERT_NE(qr.find("</svg>"), string::npos);
}

TEST_F(Unit, qrFailHttp) {
  pam_conversation.conv = &curlyConvFunc;
  char host[] = "http://localhost:";
  pam_conversation.appdata_ptr = host;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);
  ASSERT_NE(0, globalRet.size());
  string qr{globalRet[0]};

  ASSERT_EQ(qr.size(), 0);
}

TEST_F(Unit, qrFailWrongPass) {
  pam_conversation.conv = &curlyWrongPassConvFunc;
  pam_conversation.appdata_ptr = nullptr;
  ASSERT_EQ(pam_set_item(pamh, PAM_CONV,
                         static_cast<const void *>(&pam_conversation)),
            PAM_SUCCESS);
  globalRet.clear();
  pam_authenticate(pamh, 0);
  ASSERT_NE(0, globalRet.size());
  string err{globalRet[0]};
  ASSERT_EQ(err, "<html><body>Invalid credentials</body></html>"s);
}

class globalRaii {
public:
  globalRaii() { curl_global_init(CURL_GLOBAL_ALL); }
  ~globalRaii() { curl_global_cleanup(); }
};

int main(int argc, char **argv) {
  globalRaii init{};
  string cwd{fs::current_path().string() + "/"s};
  {
    ofstream cnf{cwd + "config/mmotd-module"s};
    cnf << "auth    sufficient   "s << cwd << "trex-pam.so"s << endl;
  }
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
