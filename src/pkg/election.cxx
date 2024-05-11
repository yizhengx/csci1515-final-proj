#include "../../include/pkg/election.hpp"
#include "../../include-shared/logger.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Generate Vote and ZKP.
 */

std::tuple<Vote_Ciphertext, VoteZKP_Struct, CryptoPP::Integer>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!

  // // Struct for a vote, v, as an
  // // ElGamal ciphertext (a, b) := (g^r, pk^r * g^v)
  // struct Vote_Ciphertext : public Serializable {
  //   CryptoPP::Integer a;
  //   CryptoPP::Integer b;

  //   void serialize(std::vector<unsigned char> &data);
  //   int deserialize(std::vector<unsigned char> &data);
  // };
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 1, DL_Q-1);
  Vote_Ciphertext vote_cipher;
  vote_cipher.a = a_exp_b_mod_c(DL_G, r, DL_P);
  vote_cipher.b = a_times_b_mod_c(
    a_exp_b_mod_c(pk, r, DL_P),
    a_exp_b_mod_c(DL_G, vote, DL_P),
    DL_P
  );
  
  // Struct for a dcp zkp of vote (a, b):
  // (aβ, bβ, cβ, rβ) = (g^r, pk^r, cβ, r''β)
  // struct VoteZKP_Struct : public Serializable {
  //   CryptoPP::Integer a0;
  //   CryptoPP::Integer a1;
  //   CryptoPP::Integer b0;
  //   CryptoPP::Integer b1;
  //   CryptoPP::Integer c0;
  //   CryptoPP::Integer c1;
  //   CryptoPP::Integer r0;
  //   CryptoPP::Integer r1;
  VoteZKP_Struct vote_zpk;
  if (vote == 1) {
    // random sample r0, r1, c0 (fake)
    CryptoPP::Integer r0(prng, 1, DL_Q-1);
    CryptoPP::Integer r1_p(prng, 1, DL_Q-1);
    CryptoPP::Integer c0(prng, 1, DL_Q);
    CryptoPP::Integer a0 = a_times_b_mod_c(
      a_exp_b_mod_c(DL_G, r0, DL_P),
      CryptoPP::EuclideanMultiplicativeInverse(
        a_exp_b_mod_c(vote_cipher.a, c0, DL_P), 
        DL_P
      ),
      DL_P
    );
    CryptoPP::Integer b0 = a_times_b_mod_c(
      a_exp_b_mod_c(pk, r0, DL_P),
      CryptoPP::EuclideanMultiplicativeInverse(
        a_exp_b_mod_c(vote_cipher.b, c0, DL_P), 
        DL_P
      ),
      DL_P
    );
    CryptoPP::Integer a1 = a_exp_b_mod_c(DL_G, r1_p, DL_P);
    CryptoPP::Integer b1 = a_exp_b_mod_c(pk, r1_p, DL_P);
    // // Hasher.
    // CryptoPP::Integer hash_vote_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
    //                                 CryptoPP::Integer b, CryptoPP::Integer a0_p,
    //                                 CryptoPP::Integer b0_p, CryptoPP::Integer a1_p,
    //                                 CryptoPP::Integer b1_p);
    CryptoPP::Integer c_sum = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, a0, b0, a1, b1) % DL_Q;
    CryptoPP::Integer c1 = (c_sum - c0) % DL_Q;
    CryptoPP::Integer r1 = (r1_p+a_times_b_mod_c(c1, r, DL_Q)) % DL_Q;
    vote_zpk.a0 = a0;
    vote_zpk.a1 = a1;
    vote_zpk.b0 = b0;
    vote_zpk.b1 = b1;
    vote_zpk.c0 = c0;
    vote_zpk.c1 = c1;
    vote_zpk.r0 = r0;
    vote_zpk.r1 = r1;
  } else {
    // random sample r0, r1, c1 (fake)
    CryptoPP::Integer r0_p(prng, 1, DL_Q-1);
    CryptoPP::Integer r1(prng, 1, DL_Q-1);
    CryptoPP::Integer c1(prng, 1, DL_Q);
    CryptoPP::Integer a1 = a_times_b_mod_c(
      a_exp_b_mod_c(DL_G, r1, DL_P),
      CryptoPP::EuclideanMultiplicativeInverse(
        a_exp_b_mod_c(vote_cipher.a, c1, DL_P), 
        DL_P
      ),
      DL_P
    );
    CryptoPP::Integer bp = a_times_b_mod_c(
      vote_cipher.b,
      CryptoPP::EuclideanMultiplicativeInverse(
        a_exp_b_mod_c(DL_G, 1, DL_P), 
        DL_P
      ),
      DL_P
    );
    CryptoPP::Integer b1 = a_times_b_mod_c(
      a_exp_b_mod_c(pk, r1, DL_P),
      CryptoPP::EuclideanMultiplicativeInverse(
        a_exp_b_mod_c(bp, c1, DL_P), 
        DL_P
      ),
      DL_P
    );
    CryptoPP::Integer a0 = a_exp_b_mod_c(DL_G, r0_p, DL_P);
    CryptoPP::Integer b0 = a_exp_b_mod_c(pk, r0_p, DL_P);
    // // Hasher.
    // CryptoPP::Integer hash_vote_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
    //                                 CryptoPP::Integer b, CryptoPP::Integer a0_p,
    //                                 CryptoPP::Integer b0_p, CryptoPP::Integer a1_p,
    //                                 CryptoPP::Integer b1_p);
    CryptoPP::Integer c_sum = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, a0, b0, a1, b1) % DL_Q;
    CryptoPP::Integer c0 = (c_sum - c1) % DL_Q;
    CryptoPP::Integer r0 = (r0_p+a_times_b_mod_c(c0, r, DL_Q)) % DL_Q;
    vote_zpk.a0 = a0;
    vote_zpk.a1 = a1;
    vote_zpk.b0 = b0;
    vote_zpk.b1 = b1;
    vote_zpk.c0 = c0;
    vote_zpk.c1 = c1;
    vote_zpk.r0 = r0;
    vote_zpk.r1 = r1;
  }
  
  //   void serialize(std::vector<unsigned char> &data);
  //   int deserialize(std::vector<unsigned char> &data);
  // };

  return std::make_tuple(vote_cipher, vote_zpk, r);
}

/**
 * Verify vote zkp.
 */
bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext vote_cipher;
  VoteZKP_Struct vote_zpk;
  std::tie(vote_cipher, vote_zpk) = vote;
  CryptoPP::Integer c_sum = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, vote_zpk.a0, vote_zpk.b0, vote_zpk.a1, vote_zpk.b1) % DL_Q;
  if ((vote_zpk.c0+vote_zpk.c1) % DL_Q != c_sum){
    return false;
  }
  if (a_exp_b_mod_c(DL_G, vote_zpk.r0, DL_P) != 
    a_times_b_mod_c(vote_zpk.a0, a_exp_b_mod_c(vote_cipher.a, vote_zpk.c0, DL_P), DL_P)){
    return false;
  }
  if (a_exp_b_mod_c(DL_G, vote_zpk.r1, DL_P) != 
    a_times_b_mod_c(vote_zpk.a1, a_exp_b_mod_c(vote_cipher.a, vote_zpk.c1, DL_P), DL_P)){
    return false;
  }
  if (a_exp_b_mod_c(pk, vote_zpk.r0, DL_P) != 
    a_times_b_mod_c(vote_zpk.b0, a_exp_b_mod_c(vote_cipher.b, vote_zpk.c0, DL_P), DL_P)){
    return false;
  }
  if (a_exp_b_mod_c(pk, vote_zpk.r1, DL_P) != 
      a_times_b_mod_c(vote_zpk.b1, a_exp_b_mod_c(a_times_b_mod_c(
        vote_cipher.b, 
        CryptoPP::EuclideanMultiplicativeInverse(a_exp_b_mod_c(DL_G, 1, DL_P), DL_P),
        DL_P), vote_zpk.c1, DL_P), DL_P)){
    return false;
  }
  return true;
}


/**
 * Generate exactly k votes ZKP.
*/

ExactK_Vote_ZKP ElectionClient::GenerateExactKVotesZKP(
    std::vector<Vote_Ciphertext> votes,
    CryptoPP::Integer pk, CryptoPP::Integer R) {
  initLogger();

  CryptoPP::Integer C1 = 1;
  CryptoPP::Integer C2 = 1;

  for (size_t i = 0; i < votes.size(); ++i) {
    C1 = a_times_b_mod_c(C1, votes[i].a, DL_P);
    C2 = a_times_b_mod_c(C2, votes[i].b, DL_P);
  }

  ExactK_Vote_ZKP exact_k_vote_zkp;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 1, DL_Q - 1);
  CryptoPP::Integer A = a_exp_b_mod_c(DL_G, r, DL_P);
  CryptoPP::Integer B = a_exp_b_mod_c(pk, r, DL_P);

  CryptoPP::Integer sigma = hash_exact_k_vote_zkp(pk, C1, C2, A, B);

  CryptoPP::Integer r_prime = (r + a_times_b_mod_c(sigma, R, DL_Q)) % DL_Q;

  exact_k_vote_zkp.C1 = C1;
  exact_k_vote_zkp.C2 = C2;
  exact_k_vote_zkp.A = A;
  exact_k_vote_zkp.B = B;
  exact_k_vote_zkp.r = r_prime;

  return exact_k_vote_zkp;

}

/*
  Verify exactly k votes ZKP.
*/

bool ElectionClient::VerifyExactKVotesZKP(
    ExactK_Vote_ZKP zkp, CryptoPP::Integer pk, int k) {
  initLogger();

  CryptoPP::Integer sigma = hash_exact_k_vote_zkp(pk, zkp.C1, zkp.C2, zkp.A, zkp.B);

  if (CryptoPP::ModularExponentiation(DL_G, zkp.r, DL_P) != a_times_b_mod_c(zkp.A, CryptoPP::ModularExponentiation(zkp.C1, sigma, DL_P), DL_P)) {
    return false;
  }

  CryptoPP::Integer pk_r = CryptoPP::ModularExponentiation(pk, zkp.r, DL_P);

  CryptoPP::Integer g_k = CryptoPP::ModularExponentiation(DL_G, k, DL_P);
  CryptoPP::Integer g_k_inv = CryptoPP::EuclideanMultiplicativeInverse(g_k, DL_P);
  CryptoPP::Integer C2_div_g_k = a_times_b_mod_c(zkp.C2, g_k_inv, DL_P);

  if (pk_r != a_times_b_mod_c(zkp.B, CryptoPP::ModularExponentiation(C2_div_g_k, sigma, DL_P), DL_P)) {
    std::cout << "pk_r != B * (C2 / g^k)^sigma" << std::endl;
    return false;
  }

  return true;
}


/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext combined_vote,
                               CryptoPP::Integer pk, CryptoPP::Integer sk) {
  initLogger();
  // TODO: implement me!
  PartialDecryption_Struct partial_de;
  partial_de.aggregate_ciphertext = combined_vote;
  partial_de.d = a_exp_b_mod_c(combined_vote.a, sk, DL_P);

  DecryptionZKP_Struct zpk_de;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 1, DL_Q-1);
  CryptoPP::Integer v = a_exp_b_mod_c(DL_G, r, DL_P);
  CryptoPP::Integer u = a_exp_b_mod_c(combined_vote.a, r, DL_P);
  CryptoPP::Integer c = hash_dec_zkp(pk, combined_vote.a, combined_vote.b, u, v);
  // CryptoPP::Integer hash_dec_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
  //                              CryptoPP::Integer b, CryptoPP::Integer u,
  //                              CryptoPP::Integer v)
  CryptoPP::Integer s = (r + a_times_b_mod_c(sk, c, DL_Q)) % DL_Q;
  // s = r + ski· σ
  zpk_de.u = u;
  zpk_de.v = v;
  zpk_de.s = s;

  return std::make_pair(partial_de, zpk_de);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  // struct ArbiterToWorld_PartialDecryption_Message : public Serializable {
  // std::string arbiter_id;
  // std::string arbiter_vk_path;
  // PartialDecryption_Struct dec;
  // DecryptionZKP_Struct zkp;

  // struct PartialDecryption_Struct : public Serializable {
  //   CryptoPP::Integer d;
  //   Vote_Ciphertext aggregate_ciphertext;
  // struct DecryptionZKP_Struct : public Serializable {
  //   CryptoPP::Integer u;
  //   CryptoPP::Integer v;
  //   CryptoPP::Integer s;
  // };

  // TODO: implement me!
  CryptoPP::Integer c = hash_dec_zkp(pki, 
    a2w_dec_s.dec.aggregate_ciphertext.a, 
    a2w_dec_s.dec.aggregate_ciphertext.b,
    a2w_dec_s.zkp.u,
    a2w_dec_s.zkp.v) % DL_Q;
  if (a_exp_b_mod_c(a2w_dec_s.dec.aggregate_ciphertext.a, a2w_dec_s.zkp.s, DL_P) !=
    a_times_b_mod_c(a2w_dec_s.zkp.u, a_exp_b_mod_c(a2w_dec_s.dec.d, c, DL_P), DL_P)){
    return false;
  }
  if (a_exp_b_mod_c(DL_G, a2w_dec_s.zkp.s, DL_P) !=
    a_times_b_mod_c(a2w_dec_s.zkp.v, a_exp_b_mod_c(pki, c, DL_P), DL_P)){
    return false;
  }

  return true;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext combined_vote;
  combined_vote.a = 1;
  combined_vote.b = 1;
  for (size_t i = 0; i < all_votes.size(); ++i) {
    combined_vote.a = a_times_b_mod_c(combined_vote.a, all_votes[i].vote.a, DL_P);
    combined_vote.b = a_times_b_mod_c(combined_vote.b, all_votes[i].vote.b, DL_P);
  }
  return combined_vote;
}

/**
 * Combine partial decryptions into final result.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Ciphertext combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer c1 = 1;
  for (size_t i = 0; i < all_partial_decryptions.size(); ++i) {
    c1 = a_times_b_mod_c(c1, all_partial_decryptions[i].dec.d, DL_P);
  }
  CryptoPP::Integer gm = a_times_b_mod_c(combined_vote.b, 
    CryptoPP::EuclideanMultiplicativeInverse(c1, DL_P), DL_P);
  for (CryptoPP::Integer i = 0; i <= DL_P; ++i) {
    if (a_exp_b_mod_c(DL_G, i, DL_P) == gm){
      return i;
    }
  }
  return 0;
}
