/*
 * Copyright 2019 Google Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto/openssl_init.h"

#if !defined(OPENSSL_IS_BORINGSSL)
#include <mutex>

#include "crypto/openssl.inc"
#include "glog/logging.h"
#endif

namespace private_join_and_compute {
#if !defined(OPENSSL_IS_BORINGSSL)
namespace {

void CryptoNewThreadID(CRYPTO_THREADID* tid);
void CryptoLockingCallback(int mode, int n, const char* file, int line);

class OpenSSLInit {
 public:
  OpenSSLInit() : mutexes(CRYPTO_num_locks()) {}

  void LoadErrStrings() {
    ERR_load_BN_strings();
    ERR_load_BUF_strings();
    ERR_load_CRYPTO_strings();
    ERR_load_EC_strings();
    ERR_load_ERR_strings();
    ERR_load_EVP_strings();
    ERR_load_RAND_strings();
  }

  void InitLocking() {
    CRYPTO_THREADID_set_callback(CryptoNewThreadID);
    CRYPTO_set_locking_callback(CryptoLockingCallback);
  }

  ~OpenSSLInit() {
    CRYPTO_set_locking_callback(nullptr);
    ERR_free_strings();
  }

  std::vector<std::mutex> mutexes;
};

static std::once_flag init_flag;
static OpenSSLInit openssl_init;

void CryptoNewThreadID(CRYPTO_THREADID* tid) {
#if defined(OS_NACL)  // pthread_t is a pointer type in native client.
  CRYPTO_THREADID_set_pointer(tid, std::thread::native_handle());
#else
  CRYPTO_THREADID_set_numeric(
      tid, static_cast<uint64_t>(std::thread::native_handle()));
#endif
}

// See crypto/threads/mmtest.c for usage in OpenSSL library.
void CryptoLockingCallback(int mode, int n, const char* file, int line) {
  CHECK_GE(n, 0);
  auto& mutex = openssl_init.mutexes[n];
  if (mode & CRYPTO_LOCK) {
    mutex.lock();
  } else {
    mutex.unlock();
  }
}

static void OpenSSLInitHelper() {
  openssl_init.LoadErrStrings();
  openssl_init.InitLocking();
}

}  // namespace
#endif

void OpenSSLInit() {
#if !defined(OPENSSL_IS_BORINGSSL)
  std::call_once(init_flag, OpenSSLInitHelper);
#endif
}

}  // namespace private_join_and_compute
