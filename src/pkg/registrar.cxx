#include "../../include/pkg/registrar.hpp"
#include "../../include-shared/keyloaders.hpp"
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
 * Constructor
 */
RegistrarClient::RegistrarClient(RegistrarConfig registrar_config,
                                 CommonConfig common_config) {
  // Make shared variables.
  this->registrar_config = registrar_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load registrar keys.
  try {
    LoadRSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->RSA_registrar_signing_key);
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find registrar keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_registrar_signing_key = keys.first;
    this->RSA_registrar_verification_key = keys.second;

    SaveRSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->RSA_registrar_signing_key);
    SaveRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  }

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
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
}

void RegistrarClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&RegistrarClient::ListenForConnections, this,
                              port);
  listener_thread.detach();

  // Wait for a sign to exit.
  std::string message;
  this->cli_driver->print_info("enter \"exit\" to exit");
  while (std::getline(std::cin, message)) {
    if (message == "exit") {
      this->db_driver->close();
      return;
    }
  }
}

/**
 * Listen for new connections
 */
void RegistrarClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&RegistrarClient::HandleRegister, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle key exchange with voter
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
RegistrarClient::HandleKeyExchange(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Listen for g^a
  std::vector<unsigned char> user_public_value = network_driver->read();
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.deserialize(user_public_value);

  // Respond with m = (g^b, g^a) signed with our private RSA key
  ServerToUser_DHPublicValue_Message public_value_s;
  public_value_s.server_public_value = std::get<2>(dh_values);
  public_value_s.user_public_value = user_public_value_s.public_value;
  public_value_s.server_signature = crypto_driver->RSA_sign(
      this->RSA_registrar_signing_key,
      concat_byteblocks(public_value_s.server_public_value,
                        public_value_s.user_public_value));

  // Sign and send message
  std::vector<unsigned char> message_bytes;
  public_value_s.serialize(message_bytes);
  network_driver->send(message_bytes);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      user_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle new registration. This function:
 * 1) Handles key exchange.
 * 2) Gets user info and verifies that the user hasn't already registered.
 *    (if already registered, return existing signature).
 * 3) Blindly signs the user's message and sends it to the user.
 * 4) Adds the user to the database and disconnects.
 * Disconnect and throw an error if any MACs are invalid.
 */
void RegistrarClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!
  //1) Handles key exchange.
  CryptoPP::SecByteBlock AES_key, HMAC_key;
  std::tie(AES_key, HMAC_key) = this->HandleKeyExchange(network_driver, crypto_driver);
  // this->cli_driver->print_warning("Registrar Finish KeyExchange");
  //2) Gets user info and verifies that the user hasn't already registered.
  //   (if already registered, return existing signature).
  VoterToRegistrar_Register_Message v2r_reg_msg;
  std::vector<unsigned char> raw_data, decrypted_data;
  bool valid;
  raw_data = network_driver->read();
  std::tie(decrypted_data, valid) = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, raw_data);
  if (!valid){
    throw std::runtime_error("CryptoDriver decrypt_and_verify failed [RegistrarClient::HandleRegister].");
  }
  v2r_reg_msg.deserialize(decrypted_data);
    
  VoterRow voter = this->db_driver->find_voter(v2r_reg_msg.id);
  if (voter.id == v2r_reg_msg.id){
    // user found
    RegistrarToVoter_Blind_Signature_Message msg;
    msg.id = voter.id;
    msg.registrar_signature = voter.registrar_signature;
    std::vector<unsigned char> data_to_send;
    data_to_send = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &msg);
    network_driver->send(data_to_send);
  } else {
    /* ========================= OLD VERSION =========================*/
    // //3) Blindly signs the user's message and sends it to the user.
    // CryptoPP::Integer signature = crypto_driver->RSA_BLIND_sign(this->RSA_registrar_signing_key, v2r_reg_msg.vote);
    // RegistrarToVoter_Blind_Signature_Message msg;
    // msg.id = v2r_reg_msg.id;
    // msg.registrar_signature = signature;
    // std::vector<unsigned char> data_to_send;
    // data_to_send = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &msg);
    // network_driver->send(data_to_send);

    // //4) Adds the user to the database and disconnects.
    // voter.id = v2r_reg_msg.id;
    // voter.registrar_signature = signature;
    // this->db_driver->insert_voter(voter);
    /* ======================== OLD VERSION END =======================*/

    //3) Blindly signs the vector of user's message and sends the vector of signautres to the user.
    RegistrarToVoter_Blind_Signature_Message msg;
    std::vector<CryptoPP::Integer> signatures;
    for (auto vote : v2r_reg_msg.votes){
      CryptoPP::Integer signature = crypto_driver->RSA_BLIND_sign(this->RSA_registrar_signing_key, vote);
      signatures.push_back(signature);
    }
    msg.registrar_signatures = signatures;
    std::vector<unsigned char> data_to_send;
    data_to_send = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &msg);
    network_driver->send(data_to_send);

    //4) Adds the user to the database and disconects
    voter.id = v2r_reg_msg.id;
    voter.registrar_signatures = signatures;
    this->db_driver->insert_voter(voter);
  }

  // --------------------------------
  // Exit cleanly
  network_driver->disconnect();
}
