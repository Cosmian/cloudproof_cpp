#include "cloudproof.h"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#define MAX_BUFFER_SIZE 8192

int main() {
    /* Create Policy */
    std::string policy_axis_sec =
        "{ \"name\": \"Security Level\", \"attributes_properties\": ["
        "{ \"name\": \"Protected\", \"encryption_hint\": \"Classic\" },"
        "{ \"name\": \"Confidential\", \"encryption_hint\": \"Classic\" },"
        "{ \"name\": \"Top Secret\", \"encryption_hint\": \"Hybridized\" }"
        "], \"hierarchical\": true }";

    std::string policy_axis_dep = "{ \"name\": \"Department\", \"attributes_properties\": ["
                                  "{ \"name\": \"FIN\", \"encryption_hint\": \"Classic\" },"
                                  "{ \"name\": \"MKG\", \"encryption_hint\": \"Classic\" },"
                                  "{ \"name\": \"HR\", \"encryption_hint\": \"Classic\" }"
                                  "], \"hierarchical\": false }";

    int buffer_size = MAX_BUFFER_SIZE;
    std::vector<int8_t> buffer(buffer_size);

    if (h_policy(buffer.data(), &buffer_size, 100) != 0) {
        std::cerr << "Error creating policy." << std::endl;
        exit(1);
    }
    std::vector<int8_t> policy(buffer.begin(), buffer.begin() + buffer_size);

    // Add axis Security Level
    buffer_size = MAX_BUFFER_SIZE;
    if (h_add_policy_axis(buffer.data(), &buffer_size, policy.data(), policy.size(),
                          (int8_t *)policy_axis_sec.c_str()) != 0) {
        std::cerr << "Error adding policy axis." << std::endl;
        exit(1);
    }
    policy.assign(buffer.begin(), buffer.begin() + buffer_size);

    // Add axis Department
    buffer_size = MAX_BUFFER_SIZE;
    if (h_add_policy_axis(buffer.data(), &buffer_size, policy.data(), policy.size(),
                          (int8_t *)policy_axis_dep.c_str()) != 0) {
        std::cerr << "Error adding policy axis." << std::endl;
        exit(1);
    }
    policy.assign(buffer.begin(), buffer.begin() + buffer_size);

    /* Create Master Keys */
    int master_private_key_size = MAX_BUFFER_SIZE;
    std::vector<int8_t> master_private_key(master_private_key_size);
    int public_key_size = MAX_BUFFER_SIZE;
    std::vector<int8_t> public_key(public_key_size);

    int ret_code =
        h_generate_master_keys(master_private_key.data(), &master_private_key_size,
                               public_key.data(), &public_key_size, policy.data(), policy.size());

    if (ret_code != 0) {
        // Retry with correct allocated size
        master_private_key.resize(master_private_key_size);
        public_key.resize(public_key_size);

        if (h_generate_master_keys(master_private_key.data(), &master_private_key_size,
                                   public_key.data(), &public_key_size, policy.data(),
                                   policy.size()) != 0) {
            std::cerr << "Error creating master keys." << std::endl;
            exit(1);
        }
    }
    // Resize vectors to the actual size of the master keys
    master_private_key.resize(master_private_key_size);
    public_key.resize(public_key_size);

    /* Encrypt Messages */
    // Empty metadata and authentication data
    std::vector<int8_t> header_metadata;
    std::vector<int8_t> authentication_data;

    // Protected marketing message
    std::string protected_mkg_data = "protected_mkg_message";
    std::string protected_mkg_policy = "Department::MKG && Security Level::Protected";

    int ciphertext_size = MAX_BUFFER_SIZE + header_metadata.size() + protected_mkg_data.size() +
                          2 * h_symmetric_encryption_overhead();
    std::vector<int8_t> protected_mkg_ciphertext(ciphertext_size);

    if (h_hybrid_encrypt(
            protected_mkg_ciphertext.data(), &ciphertext_size, policy.data(), policy.size(),
            public_key.data(), public_key_size, (int8_t *)protected_mkg_policy.c_str(),
            (int8_t *)protected_mkg_data.c_str(), protected_mkg_data.size(), header_metadata.data(),
            header_metadata.size(), authentication_data.data(), authentication_data.size()) != 0) {
        std::cerr << "Error encrypting message." << std::endl;
        exit(1);
    }
    // Resize vector to the actual size of the ciphertext
    protected_mkg_ciphertext.resize(ciphertext_size);

    // Top secret marketing message
    std::string topsecret_mkg_data = "top_secret_mkg_message";
    std::string topsecret_mkg_policy = "Department::MKG && Security Level::Top Secret";

    ciphertext_size = MAX_BUFFER_SIZE + header_metadata.size() + topsecret_mkg_data.size() +
                      2 * h_symmetric_encryption_overhead();
    std::vector<int8_t> topsecret_mkg_ciphertext(ciphertext_size);

    if (h_hybrid_encrypt(
            topsecret_mkg_ciphertext.data(), &ciphertext_size, policy.data(), policy.size(),
            public_key.data(), public_key_size, (int8_t *)topsecret_mkg_policy.c_str(),
            (int8_t *)topsecret_mkg_data.c_str(), topsecret_mkg_data.size(), header_metadata.data(),
            header_metadata.size(), authentication_data.data(), authentication_data.size()) != 0) {
        std::cerr << "Error encrypting message." << std::endl;
        exit(1);
    }
    // Resize vector to the actual size of the ciphertext
    topsecret_mkg_ciphertext.resize(ciphertext_size);

    /* Create User Key */
    std::string user_policy = "Department::MKG && Security Level::Confidential";
    std::vector<int8_t> user_private_key(MAX_BUFFER_SIZE);
    int user_private_key_size = MAX_BUFFER_SIZE;

    ret_code = h_generate_user_secret_key(
        user_private_key.data(), &user_private_key_size, master_private_key.data(),
        master_private_key_size, (int8_t *)user_policy.c_str(), policy.data(), policy.size());

    // Resize vector to the actual size of the user key
    user_private_key.resize(user_private_key_size);
    if (ret_code != 0) {
        // Retry with the correct allocated size
        if (h_generate_user_secret_key(user_private_key.data(), &user_private_key_size,
                                       master_private_key.data(), master_private_key_size,
                                       (int8_t *)user_policy.c_str(), policy.data(),
                                       policy.size()) != 0) {
            std::cerr << "Error creating user key." << std::endl;
            exit(1);
        }
    }

    /* Decrypt Messages */
    // No header metadata in our ciphertext
    int header_size = 0;
    std::vector<int8_t> header_buffer(header_size);

    // Our user key can decrypt the protected marketing message
    int plaintext_size =
        protected_mkg_ciphertext.size(); // plaintext should be smaller than ciphertext
    std::vector<int8_t> plaintext_out(plaintext_size);

    if (h_hybrid_decrypt(plaintext_out.data(), &plaintext_size, header_buffer.data(), &header_size,
                         protected_mkg_ciphertext.data(), protected_mkg_ciphertext.size(),
                         authentication_data.data(), authentication_data.size(),
                         user_private_key.data(), user_private_key.size()) != 0) {
        std::cerr << "Error decrypting protected marketing message." << std::endl;
        exit(1);
    }
    // Resize vector to the actual size of the plaintext
    plaintext_out.resize(plaintext_size);
    std::string plaintext_out_str(plaintext_out.begin(), plaintext_out.end());
    assert(plaintext_out_str == protected_mkg_data);

    std::cout << "Successfully decrypted protected marketing message: '" << plaintext_out_str
              << "'." << std::endl;

    // But we can't decrypt the top secret marketing message
    plaintext_size = topsecret_mkg_ciphertext.size();
    std::vector<int8_t> plaintext_out2(plaintext_size);

    if (h_hybrid_decrypt(plaintext_out2.data(), &plaintext_size, header_buffer.data(), &header_size,
                         topsecret_mkg_ciphertext.data(), topsecret_mkg_ciphertext.size(),
                         authentication_data.data(), authentication_data.size(),
                         user_private_key.data(), user_private_key.size()) != 0) {
        std::cerr << "Error decrypting top secret marketing message." << std::endl;
        exit(1);
    }

    return 0;
}