// Copyright 2020 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <thread>
#include <vector>
#include <iostream>

#include "clock_traits.hpp"
#include "types.hpp"
#include "crypto.hpp"
#include "log.hpp"
using std::cout;
using std::string;
using std::vector;


int main() {
  vector<Log> logs;
  for(uint8_t idx = 0x00; idx < 0x20; idx++) {
    vector<uint8_t> seed(32, idx);
    logs.emplace_back(Log(idx, "127.0.0.1", seed));
  }

  vector<msg_t> all_msgs;
  for(uint8_t i = 0; i < logs.size(); i++) {
    all_msgs.emplace_back(msg_t(4096, i));
  }

  vector<signature_t> sigs;
  for(int i = 0; i < logs.size(); i++) {
    Log log = logs[i];
    msg_t msg = all_msgs[i];
    auto before_sig = clock_traits::clock_type_t::now();
    sigs.emplace_back(log.sign(msg));
    auto after_sig = clock_traits::clock_type_t::now();
    auto dur0 = std::chrono::duration_cast<clock_traits::time_unit>(after_sig-before_sig);
    cout << "Sign took: " << dur0.count() << " " << clock_traits::suffix << "\n";
  }

  vector<pk_t> pks;
  pks.reserve(logs.size());
  for(const auto& log : logs) {
    pks.emplace_back(log.getPublicKey());
  }

  auto before_sverify = clock_traits::clock_type_t::now();
  bool ver = crypto::verify(logs[0].getPublicKeyVec(), all_msgs[0], sigs[0].Serialize());
  auto after_sverify = clock_traits::clock_type_t::now();
  auto dur = std::chrono::duration_cast<clock_traits::time_unit>(after_sverify-before_sverify);
  cout << "Verify (" << ver << ") took: " << dur.count() << " " << clock_traits::suffix << "\n";

  auto log_count = logs.size();
  auto before_agg = clock_traits::clock_type_t::now();
  aggsig_t aggsig = crypto::aggregate(sigs);
  auto after_agg = clock_traits::clock_type_t::now();
  auto dur1 = std::chrono::duration_cast<clock_traits::time_unit>(after_agg-before_agg);
  cout << "Agg (" << log_count << ") took: " << dur1.count() << " " << clock_traits::suffix << "\n";
  auto before_verify = clock_traits::clock_type_t::now();
  bool verify = crypto::verify_aggsig(pks, all_msgs, aggsig);
  auto after_verify = clock_traits::clock_type_t::now();
  auto dur2 = std::chrono::duration_cast<clock_traits::time_unit>(after_verify-before_verify);
  cout << "Verify (" << log_count << ") took: " <<  dur2.count() << " " << clock_traits::suffix << "\n";
  cout << "Can Verify aggsig: " << verify << "\n";
//
//  vector<uint8_t> msg2 = {10, 11, 12};
//  vector<uint8_t> seed1(32, 0x04);
//  vector<uint8_t> seed2(32, 0x05);
//  vector<uint8_t> msg1 = {7, 8, 9};
//  vector<vector<uint8_t>> msgs = {msg1, msg2};
//
//  PrivateKey sk1 = BasicSchemeMPL::KeyGen(seed1);
//  G1Element pk1 = BasicSchemeMPL::SkToG1(sk1);
//  vector<uint8_t> pk1v = BasicSchemeMPL::SkToPk(sk1);
//  G2Element sig1 = BasicSchemeMPL::Sign(sk1, msg1);
//  vector<uint8_t> sig1v = BasicSchemeMPL::Sign(sk1, msg1).Serialize();
//
//
//  bool verify = BasicSchemeMPL::Verify(pk1v, msg1, sig1v);
//  cout << "Can Verify pk1v, msg1, sig1v: " << verify << "\n";
//
//  PrivateKey sk2 = BasicSchemeMPL::KeyGen(seed2);
//  G1Element pk2 = BasicSchemeMPL::SkToG1(sk2);
//  vector<uint8_t> pk2v = BasicSchemeMPL::SkToPk(sk2);
//  G2Element sig2 = BasicSchemeMPL::Sign(sk2, msg2);
//  vector<uint8_t> sig2v = BasicSchemeMPL::Sign(sk2, msg2).Serialize();
//
//  verify = BasicSchemeMPL::Verify(pk2v, msg2, sig2v);
//  cout << "Can Verify pk2v, msg2, sig2v: " << verify << "\n";
//
//  // Wrong G2Element
//  verify = BasicSchemeMPL::Verify(pk1, msg1, sig2);
//  cout << "Can Verify pk1, msg1, sig2: " << verify << "\n";
//  verify = BasicSchemeMPL::Verify(pk1v, msg1, sig2v);
//  cout << "Can Verify pk1v, msg1, sig2v: " << verify << "\n";
//  // Wrong msg
//  verify = BasicSchemeMPL::Verify(pk1, msg2, sig1);
//  cout << "Can Verify pk1, msg2, sig1: " << verify << "\n";
//  verify = BasicSchemeMPL::Verify(pk1v, msg2, sig1v);
//  cout << "Can Verify pk1v, msg2, sig1v: " << verify << "\n";
//  // Wrong pk
//  verify = BasicSchemeMPL::Verify(pk2, msg1, sig1);
//  cout << "Can Verify pk2, msg1, sig1: " << verify << "\n";
//  verify = BasicSchemeMPL::Verify(pk2v, msg1, sig1v);
//  cout << "Can Verify pk2v, msg1, sig1v: " << verify << "\n";
//
//  G2Element aggsig = BasicSchemeMPL::Aggregate({sig1, sig2});
//  vector<uint8_t> aggsigv = BasicSchemeMPL::Aggregate({sig1v, sig2v});
//  verify = BasicSchemeMPL::AggregateVerify({pk1, pk2}, msgs, aggsig);
//
//  cout << "Can Verify {pk1, pk2}, msgs, aggisg: " << verify << "\n";
//  verify = BasicSchemeMPL::AggregateVerify({pk1v, pk2v}, msgs, aggsigv);
//  cout << "Can Verify {pk1v, pk2v}, msgs, aggisgv: " << verify << "\n";

}
