#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    Vote_Ciphertext vote;
    LoadVote(this->voter_config.voter_vote_path, vote);
    this->vote = vote;

    VoteZKP_Struct zkp;
    LoadVoteZKP(this->voter_config.voter_vote_zkp_path, zkp);
    this->vote_zkp = zkp;

    CryptoPP::Integer registrar_signature;
    LoadInteger(this->voter_config.voter_registrar_signature_path,
                registrar_signature);
    this->registrar_signature = registrar_signature;

    CryptoPP::Integer blind;
    LoadInteger(this->voter_config.voter_blind_path, blind);
    this->blind = blind;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0, 1}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 2) Blind the vote and send it to the registrar.
 * 3) Receive the blind signature from the registrar and save it.
 * 3) Receives and saves the signature from the server.
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() < 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <n> <vote_0> ... <vote_n>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;

  /* ========================= OLD VERSION =========================*/
  // CryptoPP::Integer raw_vote = CryptoPP::Integer(std::stoi(args[3]));
  /* ======================== OLD VERSION END =======================*/

  CryptoPP::Integer num_votes = CryptoPP::Integer(std::stoi(args[3]));
  if (args.size() != 4 + num_votes){
    this->cli_driver->print_warning("usage: wrong number of votes ");
    return;
  }
  std::vector<CryptoPP::Integer> raw_votes;
  for (size_t i = 4; i < args.size(); ++i){
    raw_votes.push_back(CryptoPP::Integer(std::stoi(args[i])));
  }

  // TODO: implement me!  
  //  1) Handle key exchange.
  CryptoPP::SecByteBlock AES_key, HMAC_key;
  std::tie(AES_key, HMAC_key) = this->HandleKeyExchange(this->RSA_registrar_verification_key);

  //  2) ElGamal encrypt the raw vote and generate a ZKP for it
  //     through `ElectionClient::GenerateVote`.
  // for each vote in raw votes, generate a vector of vote_s and vote_zkp
  std::vector<Vote_Ciphertext> vote_s_vec;
  std::vector<VoteZKP_Struct> vote_zkp_vec;
  // ZKP for exactly k votes in t candidates
  CryptoPP::Integer R;
  for (size_t i = 0; i < raw_votes.size(); ++i){
    Vote_Ciphertext vote_s;
    VoteZKP_Struct vote_zkp;
    CryptoPP::Integer r;
    std::tie(vote_s, vote_zkp, r) = ElectionClient::GenerateVote(raw_votes[i], this->EG_arbiter_public_key);
    R = (R + r) % DL_P;
    vote_s_vec.push_back(vote_s);
    vote_zkp_vec.push_back(vote_zkp);
  }
  /* ========================= OLD VERSION =========================*/
  // Vote_Ciphertext vote_s;
  // VoteZKP_Struct vote_zpk;
  // std::tie(vote_s, vote_zkp) = ElectionClient::GenerateVote(raw_vote, this->EG_arbiter_public_key);
  /* ======================== OLD VERSION END =======================*/


  //  2) Blind the vote and send it to the registrar.
  // generate a list of blind_msg and blind_factor for each vote in vote_s, send the list of blind_msg to registrar
  std::vector<CryptoPP::Integer> blind_msg_vec, blind_factor_vec;
  for (size_t i = 0; i < vote_s_vec.size(); ++i){
    CryptoPP::Integer blind_msg, blind_factor;
    std::tie(blind_msg, blind_factor) = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_s_vec[i]);
    blind_msg_vec.push_back(blind_msg);
    blind_factor_vec.push_back(blind_factor);
  }
  VoterToRegistrar_Register_Message v2r_reg_s;
  v2r_reg_s.id = voter_id;
  v2r_reg_s.votes = blind_msg_vec;

  /* ========================= OLD VERSION =========================*/
  // CryptoPP::Integer blind_msg, blind_factor;
  // std::tie(blind_msg, blind_factor) = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_s);
  // VoterToRegistrar_Register_Message v2r_reg_s;
  // v2r_reg_s.id = voter_id;
  // v2r_reg_s.vote = blind_msg;
  /* ======================== OLD VERSION END =======================*/
  std::vector<unsigned char> data_to_send;
  data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2r_reg_s);
  this->network_driver->send(data_to_send);

  //  3) Receive the blind signature from the registrar and save it.
  RegistrarToVoter_Blind_Signature_Message r2v_sig_s;
  std::vector<unsigned char> raw_data, decrypted_data;
  bool valid;
  raw_data = this->network_driver->read();
  std::tie(decrypted_data, valid) = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, raw_data);
  if (!valid){
    throw std::runtime_error("CryptoDriver decrypt_and_verify failed [VoterClient::HandleRegister].");
  }
  r2v_sig_s.deserialize(decrypted_data);
  
  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
  // to both memory and disk
  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  

  // save vectors
  this->votes = vote_s_vec;
  this->vote_zkps = vote_zkp_vec;
  this->registrar_signatures = r2v_sig_s.registrar_signatures;
  this->blinds = blind_factor_vec;

  /* ========================= OLD VERSION =========================*/
  // this->vote = vote_s;
  // this->vote_zkp = vote_zkp;
  // this->registrar_signature = r2v_sig_s.registrar_signature;
  // this->blind = blind_factor;
  /* ======================== OLD VERSION END =======================*/

  // save the number of votes
  SaveInteger(this->voter_config.voter_vote_path + voter_id + "_num_votes", num_votes);
  // save all votes for blind_msgs with a path with this->voter_config.voter_vote_path+"id"
  for (size_t i = 0; i < blind_msg_vec.size(); ++i){
    SaveVote(this->voter_config.voter_vote_path + voter_id + "_" + std::to_string(i), vote_s_vec[i]);
    SaveVoteZKP(this->voter_config.voter_vote_zkp_path + voter_id + "_" + std::to_string(i), vote_zkp_vec[i]);
    SaveInteger(this->voter_config.voter_registrar_signature_path + voter_id + "_" + std::to_string(i), r2v_sig_s.registrar_signature);
    SaveInteger(this->voter_config.voter_blind_path + voter_id + "_" + std::to_string(i), blind_factor_vec[i]);
  }
  /* ========================= OLD VERSION =========================*/
  // SaveVote(this->voter_config.voter_vote_path, vote_s);
  // SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  // SaveInteger(this->voter_config.voter_registrar_signature_path,
  //             r2v_sig_s.registrar_signature);
  // SaveInteger(this->voter_config.voter_blind_path, blind);
  /* ======================== OLD VERSION END =======================*/

  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in
 * `this->registrar_signature`. 3) Sends the vote, ZKP, and unblinded signature
 * to the tallyer.
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!

  //  1) Handle key exchange.
  CryptoPP::SecByteBlock AES_key, HMAC_key;
  std::tie(AES_key, HMAC_key) = this->HandleKeyExchange(this->RSA_tallyer_verification_key);
  
  /* ========================= OLD VERSION =========================*/
  // //  2) Unblinds the registrar signature that is stored in `this->registrar_signature`.
  // CryptoPP::Integer unblind_s = this->crypto_driver->RSA_BLIND_unblind(
  //   this->RSA_registrar_verification_key, 
  //   this->registrar_signature, 
  //   this->blind);
  // //  3) Sends the vote, ZKP, and unblinded signature to the tallyer.
  // VoterToTallyer_Vote_Message vote_msg;
  // vote_msg.vote = this->vote;
  // vote_msg.unblinded_signature = unblind_s;
  // vote_msg.zkp = this->vote_zkp;
  // std::vector<unsigned char> data_to_send;
  // data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_msg);
  // this->network_driver->send(data_to_send);
  // // Exit cleanly.
  // this->network_driver->disconnect();
  /* ======================== OLD VERSION END =======================*/


  //  2) Creates a list of unblind_s 
  // unblinds the vector of registrar signatures that is stored in `this->registrar_signatures`.
  std::vector<CryptoPP::Integer> unblind_s_vec;
  for (size_t i = 0; i < this->registrar_signatures.size(); ++i){
    CryptoPP::Integer unblind_s = this->crypto_driver->RSA_BLIND_unblind(
      this->RSA_registrar_verification_key, 
      this->registrar_signatures[i], 
      this->blinds[i]);
    unblind_s_vec.push_back(unblind_s);
  }

  //  3) Sends the votes, ZKPs, and unblinded signatures to the tallyer.
  VoterToTallyer_Vote_Message vote_msg;
  vote_msg.votes = this->votes;
  vote_msg.unblinded_signatures = unblind_s_vec;
  vote_msg.zkps = this->vote_zkps;
  std::vector<unsigned char> data_to_send;
  data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_msg);
  this->network_driver->send(data_to_send);
  // Exit cleanly.
  this->network_driver->disconnect();

}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<1>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  // this->cli_driver->print_success("Number of votes for 0: " +
  //                                 CryptoPP::IntToString(std::get<0>(result)));
  // this->cli_driver->print_success("Number of votes for 1: " +
                                  // CryptoPP::IntToString(std::get<1>(result)));
  
  // TODO: implement me! 
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::pair<std::vector<CryptoPP::Integer>, bool> VoterClient::DoVerify() {
  // // 1) Verifies all vote ZKPs and their signatures
  // // 2) Verifies all partial decryption ZKPs
  // std::vector<VoteRow> all_votes = this->db_driver->all_votes();
  // std::vector<VoteRow> valid_votes;
  // bool valid;
  // for (size_t i = 0; i < all_votes.size(); ++i) {
  //   VoteRow vote;
  //   vote = all_votes[i];
  //   valid = this->crypto_driver->RSA_BLIND_verify(
  //     this->RSA_registrar_verification_key,
  //     vote.vote,
  //     vote.unblinded_signature
  //   );
  //   if (!valid){
  //     continue;
  //   }
  //   valid = ElectionClient::VerifyVoteZKP(std::make_pair(vote.vote, vote.zkp), this->EG_arbiter_public_key);
  //   if (!valid){
  //     continue;
  //   }
  //   valid = this->crypto_driver->RSA_verify(
  //     this->RSA_tallyer_verification_key,
  //     concat_vote_zkp_and_signature(vote.vote, vote.zkp, vote.unblinded_signature),
  //     vote.tallyer_signature
  //   );
  //   if (!valid){
  //     continue;
  //   }
  //   valid_votes.push_back(vote);
  // }

  std::vector<VoteRow> all_votes = this->db_driver->all_votes();
  std::vector<VoteRow> valid_votes;
  std::map<int, std::vector<VoteRow>> vote_map;
  bool valid;
  for (size_t i = 0; i < all_votes.size(); ++i) {
    valid = true;
    for (size_t j = 0; j < all_votes[i].votes.size(); ++j) {
      Vote_Ciphertext vote = all_votes[i].votes[j];
      VoteZKP_Struct zkp = all_votes[i].zkps[j];
      bool valid_signature = this->crypto_driver->RSA_verify(
        this->RSA_tallyer_verification_key,
        concat_vote_zkp_and_signature(vote, zkp, all_votes[i].unblinded_signature),
        all_votes[i].tallyer_signature
      );
      bool valid_vote = ElectionClient::VerifyVoteZKP(std::make_pair(vote, zkp), this->EG_arbiter_public_key);
      if (!valid_signature || !valid_vote) {
        valid = false;
        break;
      }
    }
    if (valid) {
      valid_votes.push_back(all_votes[i]);
      for (size_t j = 0; i < all_votes[i].votes.size(); ++j){
        if (vote_map.find(j) == vote_map.end()){
          vote_map[j] = std::vector<VoteRow>();
        }
        VoteRow vote_row;
        vote_row.vote = all_votes[i].votes[j];
        vote_row.zkp = all_votes[i].zkps[j];
        vote_map[j].push_back(vote_row);
      }
    }
  }

  // // 3) Combines the partial decryptions to retrieve the final result
  // Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_votes);
  // std::vector<PartialDecryptionRow> all_partial_dec = this->db_driver->all_partial_decryptions();
  // CryptoPP::Integer pki;
  // for (size_t i = 0; i < all_partial_dec.size(); ++i) {
  //   PartialDecryptionRow partial_dec = all_partial_dec[i];
  //   LoadInteger(partial_dec.arbiter_vk_path, pki);
  //   valid = ElectionClient::VerifyPartialDecryptZKP(partial_dec, pki);
  //   if (!valid){
  //     return std::make_tuple(0,0,false);
  //   }
  // }

  // 3) Create a list of combine votes, each corresponds to a comnbine of the same index of valid.votes[i] 
  std::vector<PartialDecryptionRow> all_partial_dec = this->db_driver->all_partial_decryptions();
  std::map<int, std::vector<PartialDecryptionRow>> partial_dec_map;
  for (size_t i = 0; i < all_partial_dec.size(); ++i){
    if (partial_dec_map.find(all_partial_dec[i].candidate_id) == partial_dec_map.end()){
      partial_dec_map[all_partial_dec[i].candidate_id] = std::vector<PartialDecryptionRow>();
    }
    partial_dec_map[all_partial_dec[i].candidate_id].push_back(all_partial_dec[i]);
  }

  // check all partial decryptions in the map
  CryptoPP::Integer pki;
  for (auto it = partial_dec_map.begin(); it != partial_dec_map.end(); ++it){
    for (size_t i = 0; i < it->second.size(); ++i){
      PartialDecryptionRow partial_dec = it->second[i];
      LoadInteger(partial_dec.arbiter_vk_path, pki);
      valid = ElectionClient::VerifyPartialDecryptZKP(partial_dec, pki);
      if (!valid){
        // return a empty list and false pair
        return std::make_pair(std::vector<CryptoPP::Integer>(), false);
      }
    }
  }


  std::vector<CryptoPP::Integer> num_votes;
  // for each vector in map, combine them and insert to the list, with an order from 0 the the size of the map
  for (auto it = partial_dec_map.begin(); it != partial_dec_map.end(); ++it){
    Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(vote_map[it->first]);
    num_votes.push_back(ElectionClient::CombineResults(combined_vote, it->second));
  }
  return std::make_pair(num_votes, true);

  // // 4) Returns a tuple of <0-votes, 1-votes, success>
  // CryptoPP::Integer num_votes = ElectionClient::CombineResults(combined_vote, all_partial_dec);
  // CryptoPP::Integer num_zeros = valid_votes.size() - num_votes;
  // std::cout << valid_votes.size() << " - " << num_votes << " - " << num_zeros << std::endl;
  // return std::make_tuple(num_zeros, num_votes, true);

  



  

}
