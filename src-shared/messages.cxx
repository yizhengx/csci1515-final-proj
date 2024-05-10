#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the nest bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the nest string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

// ================================================
// KEY EXCHANGE
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  std::string user_public_string = byteblock_to_string(this->user_public_value);
  put_string(server_public_string, data);
  put_string(user_public_string, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  std::string server_public_string;
  std::string user_public_string;
  int n = 1;
  n += get_string(&server_public_string, data, n);
  n += get_string(&user_public_string, data, n);
  n += get_string(&this->server_signature, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);
  this->user_public_value = string_to_byteblock(user_public_string);
  return n;
}

// ================================================
// VOTER <==> REGISTRAR
// ================================================

/**
 * serialize ExactK_Vote_ZKP.
 */

/*

struct ExactK_Vote_ZKP : public Serializable {
  CryptoPP::Integer c1;
  CryptoPP::Integer c2;
  CryptoPP::Integer A;
  CryptoPP::Integer B;
  CryptoPP::Integer r;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

 
*/
void ExactK_Vote_ZKP::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ExactK_Vote_ZKP);

  // Add fields.
  put_integer(this->C1, data);
  put_integer(this->C2, data);
  put_integer(this->A, data);
  put_integer(this->B, data);
  put_integer(this->r, data);
}

/**
 * deserialize ExactK_Vote_ZKP.
 */

int ExactK_Vote_ZKP::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ExactK_Vote_ZKP);

  // Get fields.
  int n = 1;
  n += get_integer(&this->C1, data, n);
  n += get_integer(&this->C2, data, n);
  n += get_integer(&this->A, data, n);
  n += get_integer(&this->B, data, n);
  n += get_integer(&this->r, data, n);
  return n;
}

/**
 * serialize VoterToRegistrar_Register_Message.
 */
void VoterToRegistrar_Register_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoterToRegistrar_Register_Message);

  // Add fields.
  put_string(this->id, data);
  put_integer(this->vote, data);

  // Add votes
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t votes_size = this->votes.size();
  std::memcpy(&data[idx], &votes_size, sizeof(size_t));
  for (int i = 0; i < votes_size; i++){
    put_integer(this->votes[i], data);
  }
}

/**
 * deserialize VoterToRegistrar_Register_Message.
 */
int VoterToRegistrar_Register_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoterToRegistrar_Register_Message);

  // Get fields.
  std::string user_verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_integer(&this->vote, data, n);

  // Get number of votes.
  size_t votes_size;
  std::memcpy(&votes_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < votes_size; i++) {
    CryptoPP::Integer vote;
    n += get_integer(&vote, data, n);
    this->votes.push_back(vote);
  }

  return n;
}

/**
 * serialize RegistrarToVoter_Blind_Signature_Message.
 */
void RegistrarToVoter_Blind_Signature_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::RegistrarToVoter_Blind_Signature_Message);

  // Add fields.
  put_string(this->id, data);
  put_integer(this->registrar_signature, data);

  // Add votes
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t registrar_signatures_size = this->registrar_signatures.size();
  std::memcpy(&data[idx], &registrar_signatures_size, sizeof(size_t));
  for (int i = 0; i < registrar_signatures_size; i++){
    put_integer(this->registrar_signatures[i], data);
  }
}

/**
 * deserialize RegistrarToVoter_Blind_Signature_Message.
 */
int RegistrarToVoter_Blind_Signature_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::RegistrarToVoter_Blind_Signature_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_integer(&this->registrar_signature, data, n);

  // Get number of votes.
  size_t registrar_signatures_size;
  std::memcpy(&registrar_signatures_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  // Get each vote.
  for (int i = 0; i < registrar_signatures_size; i++) {
    std::string registrar_signatures_str;
    n += get_string(&registrar_signatures_str, data, n);
    this->registrar_signatures.push_back(string_to_integer(registrar_signatures_str));
  }

  return n;
}

// ================================================
// VOTER <==> TALLYER
// ================================================

/**
 * serialize Vote_Ciphertext.
 */
void Vote_Ciphertext::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Vote_Ciphertext);

  // Add fields.
  put_integer(this->a, data);
  put_integer(this->b, data);
}

/**
 * deserialize Vote_Ciphertext.
 */
int Vote_Ciphertext::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Vote_Ciphertext);

  // Get fields.
  int n = 1;
  n += get_integer(&this->a, data, n);
  n += get_integer(&this->b, data, n);
  return n;
}

/**
 * serialize VoteZKP_Struct.
 */
void VoteZKP_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoteZKP_Struct);

  // Add fields.
  put_integer(this->a0, data);
  put_integer(this->a1, data);
  put_integer(this->b0, data);
  put_integer(this->b1, data);
  put_integer(this->c0, data);
  put_integer(this->c1, data);
  put_integer(this->r0, data);
  put_integer(this->r1, data);
}

/**
 * deserialize VoteZKP_Struct.
 */
int VoteZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoteZKP_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->a0, data, n);
  n += get_integer(&this->a1, data, n);
  n += get_integer(&this->b0, data, n);
  n += get_integer(&this->b1, data, n);
  n += get_integer(&this->c0, data, n);
  n += get_integer(&this->c1, data, n);
  n += get_integer(&this->r0, data, n);
  n += get_integer(&this->r1, data, n);
  return n;
}

/**
 * serialize VoterToTallyer_Vote_Message.
 */
void VoterToTallyer_Vote_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoterToTallyer_Vote_Message);

  // Add fields.

  std::vector<unsigned char> vote_data;
  this->vote.serialize(vote_data);
  data.insert(data.end(), vote_data.begin(), vote_data.end());

  put_integer(this->unblinded_signature, data);

  std::vector<unsigned char> zkp_data;
  this->zkp.serialize(zkp_data);
  data.insert(data.end(), zkp_data.begin(), zkp_data.end());

  // Add votes
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t votes_size = this->votes.size();
  std::memcpy(&data[idx], &votes_size, sizeof(size_t));
  for (int i = 0; i < votes_size; i++){
    std::vector<unsigned char> vote_data;
    this->votes[i].serialize(vote_data);
    data.insert(data.end(), vote_data.begin(), vote_data.end());
  }

  // add zkps
  idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t zkps_size = this->zkps.size();
  std::memcpy(&data[idx], &zkps_size, sizeof(size_t));
  for (int i = 0; i < zkps_size; i++){
    std::vector<unsigned char> zkp_data;
    this->zkps[i].serialize(zkp_data);
    data.insert(data.end(), zkp_data.begin(), zkp_data.end());
  }

  // add signs 
  idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t unblinded_signatures_size = this->unblinded_signatures.size();
  std::memcpy(&data[idx], &unblinded_signatures_size, sizeof(size_t));
  for (int i = 0; i < unblinded_signatures_size; i++){
    put_integer(this->unblinded_signatures[i], data);
  }

  // add exact_k_vote_zkp
  std::vector<unsigned char> exact_k_vote_zkp_data;
  this->exact_k_vote_zkp.serialize(exact_k_vote_zkp_data);
  data.insert(data.end(), exact_k_vote_zkp_data.begin(), exact_k_vote_zkp_data.end());
}

/**
 * deserialize VoterToTallyer_Vote_Message.
 */
int VoterToTallyer_Vote_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoterToTallyer_Vote_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> vote_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->vote.deserialize(vote_slice);

  n += get_integer(&this->unblinded_signature, data, n);

  std::vector<unsigned char> zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkp.deserialize(zkp_slice);
  
  // Get number of votes.
  size_t votes_size;
  std::memcpy(&votes_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  // Get each vote.
  for (int i = 0; i < votes_size; i++) {
    // std::string votes_str;
    // n += get_string(&votes_str, data, n);
    // this->votes.push_back(string_to_integer(votes_str));
    std::vector<unsigned char> vote_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
    Vote_Ciphertext vote;
    n += vote.deserialize(vote_slice);
    this->votes.push_back(vote);
  }

  // deserialize zkps
  size_t zkps_size;
  std::memcpy(&zkps_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < zkps_size; i++) {
    VoteZKP_Struct zkp;
    std::vector<unsigned char> zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
    n += zkp.deserialize(zkp_slice);
    this->zkps.push_back(zkp);
  }

  // deserialize signs
  size_t unblinded_signatures_size;
  std::memcpy(&unblinded_signatures_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < unblinded_signatures_size; i++) {
    CryptoPP::Integer unblinded_signature;
    n += get_integer(&unblinded_signature, data, n);
    this->unblinded_signatures.push_back(unblinded_signature);
  }

  // deserialize exact_k_vote_zkp
  std::vector<unsigned char> exact_k_vote_zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());

  n += this->exact_k_vote_zkp.deserialize(exact_k_vote_zkp_slice);
  return n;
}

/**
 * serialize TallyerToWorld_Vote_Message.
 */
void TallyerToWorld_Vote_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::TallyerToWorld_Vote_Message);

  // Add fields.
  std::vector<unsigned char> vote_data;
  this->vote.serialize(vote_data);
  data.insert(data.end(), vote_data.begin(), vote_data.end());

  std::vector<unsigned char> zkp_data;
  this->zkp.serialize(zkp_data);
  data.insert(data.end(), zkp_data.begin(), zkp_data.end());

  put_integer(this->unblinded_signature, data);

  put_string(this->tallyer_signature, data);


  // Add votes
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t votes_size = this->votes.size();
  std::memcpy(&data[idx], &votes_size, sizeof(size_t));
  for (int i = 0; i < votes_size; i++){
    std::vector<unsigned char> vote_data;
    this->votes[i].serialize(vote_data);
    data.insert(data.end(), vote_data.begin(), vote_data.end());
  }

  // add zkps
  idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t zkps_size = this->zkps.size();
  std::memcpy(&data[idx], &zkps_size, sizeof(size_t));
  for (int i = 0; i < zkps_size; i++){
    std::vector<unsigned char> zkp_data;
    this->zkps[i].serialize(zkp_data);
    data.insert(data.end(), zkp_data.begin(), zkp_data.end());
  }

  // add signs 
  idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t unblinded_signatures_size = this->unblinded_signatures.size();
  std::memcpy(&data[idx], &unblinded_signatures_size, sizeof(size_t));
  for (int i = 0; i < unblinded_signatures_size; i++){
    put_integer(this->unblinded_signatures[i], data);
  }

  // serialize tallyer_signatures
  idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t tallyer_signatures_size = this->tallyer_signatures.size();
  std::memcpy(&data[idx], &tallyer_signatures_size, sizeof(size_t));
  for (int i = 0; i < tallyer_signatures_size; i++){
    put_string(this->tallyer_signatures[i], data);
  }
}

/**
 * deserialize TallyerToWorld_Vote_Message.
 */
int TallyerToWorld_Vote_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::TallyerToWorld_Vote_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> vote_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->vote.deserialize(vote_slice);

  std::vector<unsigned char> zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkp.deserialize(zkp_slice);

  n += get_integer(&this->unblinded_signature, data, n);

  n += get_string(&this->tallyer_signature, data, n);
    
  // deserialize votes
  size_t votes_size;
  std::memcpy(&votes_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < votes_size; i++) {
    // std::string votes_str;
    // n += get_string(&votes_str, data, n);
    // this->votes.push_back(string_to_integer(votes_str));
    std::vector<unsigned char> vote_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
    Vote_Ciphertext vote;
    n += vote.deserialize(vote_slice);
    this->votes.push_back(vote);
  }

  // deserialize zkps
  size_t zkps_size;
  std::memcpy(&zkps_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < zkps_size; i++) {
    VoteZKP_Struct zkp;
    std::vector<unsigned char> zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
    n += zkp.deserialize(zkp_slice);
    this->zkps.push_back(zkp);
  }

  // deserialize signs
  size_t unblinded_signatures_size;
  std::memcpy(&unblinded_signatures_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < unblinded_signatures_size; i++) {
    CryptoPP::Integer unblinded_signature;
    n += get_integer(&unblinded_signature, data, n);
    this->unblinded_signatures.push_back(unblinded_signature);
  }

  // deserialize tallyer_signatures
  size_t tallyer_signatures_size;
  std::memcpy(&tallyer_signatures_size, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  for (int i = 0; i < tallyer_signatures_size; i++) {
    std::string tallyer_signature;
    n += get_string(&tallyer_signature, data, n);
    this->tallyer_signatures.push_back(tallyer_signature);
  }
  return n;
}

// ================================================
// ARBITER <==> WORLD
// ================================================

/**
 * serialize PartialDecryption_Struct.
 */
void PartialDecryption_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::PartialDecryption_Struct);

  // Add fields.
  put_integer(this->d, data);
  std::vector<unsigned char> aggregate_ciphertext_data;
  this->aggregate_ciphertext.serialize(aggregate_ciphertext_data);
  data.insert(data.end(), aggregate_ciphertext_data.begin(),
              aggregate_ciphertext_data.end());
}

/**
 * deserialize PartialDecryption_Struct.
 */
int PartialDecryption_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::PartialDecryption_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->d, data, n);
  std::vector<unsigned char> aggregate_ciphertext_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->aggregate_ciphertext.deserialize(aggregate_ciphertext_slice);
  return n;
}

/**
 * serialize DecryptionZKP_Struct.
 */
void DecryptionZKP_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DecryptionZKP_Struct);

  // Add fields.
  put_integer(this->u, data);
  put_integer(this->v, data);
  put_integer(this->s, data);
}

/**
 * deserialize DecryptionZKP_Struct.
 */
int DecryptionZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DecryptionZKP_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->u, data, n);
  n += get_integer(&this->v, data, n);
  n += get_integer(&this->s, data, n);
  return n;
}

/**
 * serialize ArbiterToWorld_PartialDecryption_Message.
 */
void ArbiterToWorld_PartialDecryption_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ArbiterToWorld_PartialDecryption_Message);

  // Add fields.
  put_string(this->arbiter_id, data);

  put_string(this->arbiter_vk_path, data);

  std::vector<unsigned char> dec_data;
  this->dec.serialize(dec_data);
  data.insert(data.end(), dec_data.begin(), dec_data.end());

  std::vector<unsigned char> zkp_data;
  this->zkp.serialize(zkp_data);
  data.insert(data.end(), zkp_data.begin(), zkp_data.end());

  // serialize cnadidate_id
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  std::memcpy(&data[idx], &this->candidate_id, sizeof(size_t));

}

/**
 * deserialize ArbiterToWorld_PartialDecryption_Message.
 */
int ArbiterToWorld_PartialDecryption_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ArbiterToWorld_PartialDecryption_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->arbiter_id, data, n);

  n += get_string(&this->arbiter_vk_path, data, n);

  std::vector<unsigned char> dec_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->dec.deserialize(dec_slice);

  std::vector<unsigned char> zkp_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkp.deserialize(zkp_slice);

  // deserialize candidate_id
  std::memcpy(&this->candidate_id, &data[n], sizeof(size_t));
  n += sizeof(size_t);
  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a vote and zkp into vector of unsigned char
 */
std::vector<unsigned char>
concat_vote_zkp_and_signature(Vote_Ciphertext &vote, VoteZKP_Struct &zkp,
                              CryptoPP::Integer &signature) {
  // Serialize vote and zkp.
  std::vector<unsigned char> vote_data;
  vote.serialize(vote_data);
  std::vector<unsigned char> zkp_data;
  zkp.serialize(zkp_data);
  std::vector<unsigned char> signature_data =
      str2chvec(integer_to_string(signature));

  // Concat data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), vote_data.begin(), vote_data.end());
  v.insert(v.end(), zkp_data.begin(), zkp_data.end());
  v.insert(v.end(), signature_data.begin(), signature_data.end());
  return v;
}
