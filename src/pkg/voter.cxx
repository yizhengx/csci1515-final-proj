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
  if (args.size() != 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;
  CryptoPP::Integer raw_vote = CryptoPP::Integer(std::stoi(args[3]));

  // TODO: implement me!
  std::cout << "Voter: " << voter_id << " && Vote: " << raw_vote << std::endl;
  
  //  1) Handle key exchange.
  CryptoPP::SecByteBlock AES_key, HMAC_key;
  std::tie(AES_key, HMAC_key) = this->HandleKeyExchange(this->RSA_registrar_verification_key);
  //  2) ElGamal encrypt the raw vote and generate a ZKP for it
  //     through `ElectionClient::GenerateVote`.
  Vote_Ciphertext vote_s;
  VoteZKP_Struct vote_zpk;
  std::tie(vote_s, vote_zkp) = ElectionClient::GenerateVote(raw_vote, this->EG_arbiter_public_key);
  // std::cout << "Vote_s -> " << vote_s.a << " || " << vote_s.b << std::endl;
  //  2) Blind the vote and send it to the registrar.
  CryptoPP::Integer blind_msg, blind_factor;
  std::tie(blind_msg, blind_factor) = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_s);
  // std::cout << "Blind msg -> " << blind_msg << " && Blind factor -> " << blind_factor << std::endl;
  VoterToRegistrar_Register_Message v2r_reg_s;
  v2r_reg_s.id = voter_id;
  v2r_reg_s.vote = blind_msg;
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
  // std::cout << "Signature -> " << r2v_sig_s.registrar_signature << std::endl;
  
  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
  // to both memory and disk
  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  this->vote = vote_s;
  this->vote_zkp = vote_zkp;
  this->registrar_signature = r2v_sig_s.registrar_signature;
  this->blind = blind_factor;
  SaveVote(this->voter_config.voter_vote_path, vote_s);
  SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  SaveInteger(this->voter_config.voter_registrar_signature_path,
              r2v_sig_s.registrar_signature);
  SaveInteger(this->voter_config.voter_blind_path, blind);

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
  // --------------------------------
  //  1) Handle key exchange.
  CryptoPP::SecByteBlock AES_key, HMAC_key;
  std::tie(AES_key, HMAC_key) = this->HandleKeyExchange(this->RSA_tallyer_verification_key);
  //  2) Unblinds the registrar signature that is stored in `this->registrar_signature`.
  CryptoPP::Integer unblind_s = this->crypto_driver->RSA_BLIND_unblind(
    this->RSA_registrar_verification_key, 
    this->registrar_signature, 
    this->blind);
  // std::cout << "Sig -> " << this->registrar_signature << std::endl;
  // std::cout << "Unblind sig -> " << unblind_s << std::endl;
  //  3) Sends the vote, ZKP, and unblinded signature to the tallyer.
  VoterToTallyer_Vote_Message vote_msg;
  vote_msg.vote = this->vote;
  vote_msg.unblinded_signature = unblind_s;
  vote_msg.zkp = this->vote_zkp;
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
  if (!std::get<2>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  this->cli_driver->print_success("Number of votes for 0: " +
                                  CryptoPP::IntToString(std::get<0>(result)));
  this->cli_driver->print_success("Number of votes for 1: " +
                                  CryptoPP::IntToString(std::get<1>(result)));
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> VoterClient::DoVerify() {
  // TODO: implement me!
  // 1) Verifies all vote ZKPs and their signatures
  // 2) Verifies all partial decryption ZKPs
  // 3) Combines the partial decryptions to retrieve the final result
  // 4) Returns a tuple of <0-votes, 1-votes, success>
  // If a vote is invalid, simply *ignore* it: do not throw an error.

  // 2) Gets all of the votes from the database.
  // std::vector<VoteRow> DBDriver::all_votes() 
  std::vector<VoteRow> all_votes = this->db_driver->all_votes();

  // 3) Verifies all of the vote ZKPs and their signatures.
  //    If a vote is invalid, simply ignore it.
  // VoteRow vote;
  std::vector<VoteRow> valid_votes;
  bool valid;
  for (size_t i = 0; i < all_votes.size(); ++i) {
    VoteRow vote;
    vote = all_votes[i];
    // bool CryptoDriver::RSA_verify(const RSA::PublicKey &verification_key,
    //                           std::vector<unsigned char> message,
    //                           std::string signature)
    valid = this->crypto_driver->RSA_BLIND_verify(
      this->RSA_registrar_verification_key,
      vote.vote,
      vote.unblinded_signature
    );
    if (!valid){
      continue;
    }
    valid = ElectionClient::VerifyVoteZKP(std::make_pair(vote.vote, vote.zkp), this->EG_arbiter_public_key);
    if (!valid){
      continue;
    }
    valid = this->crypto_driver->RSA_verify(
      this->RSA_tallyer_verification_key,
      concat_vote_zkp_and_signature(vote.vote, vote.zkp, vote.unblinded_signature),
      vote.tallyer_signature
    );
    if (!valid){
      continue;
    }
    valid_votes.push_back(vote);
  }
  Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_votes);
  std::vector<PartialDecryptionRow> all_partial_dec = this->db_driver->all_partial_decryptions();
  CryptoPP::Integer pki;
  for (size_t i = 0; i < all_partial_dec.size(); ++i) {
    PartialDecryptionRow partial_dec = all_partial_dec[i];
    // bool CryptoDriver::RSA_verify(const RSA::PublicKey &verification_key,
    //                           std::vector<unsigned char> message,
    //                           std::string signature)
    LoadInteger(partial_dec.arbiter_vk_path, pki);
    valid = ElectionClient::VerifyPartialDecryptZKP(partial_dec, pki);
    if (!valid){
      return std::make_tuple(0,0,false);
    }
  }
  CryptoPP::Integer num_votes = ElectionClient::CombineResults(combined_vote, all_partial_dec);
  CryptoPP::Integer num_zeros = valid_votes.size() - num_votes;
  std::cout << valid_votes.size() << " - " << num_votes << " - " << num_zeros << std::endl;
  return std::make_tuple(num_zeros, num_votes, true);
}
