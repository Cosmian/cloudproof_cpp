#include "cloudproof.h"
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

    std::vector<int8_t> buffer(MAX_BUFFER_SIZE);
    int buffer_size = MAX_BUFFER_SIZE;

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

    // Print the policy
    for (const auto &element : policy) {
        std::cout << element;
    }
    std::cout << std::endl;

    /* Create Master Keys */
    std::vector<int8_t> master_private_key(MAX_BUFFER_SIZE);
    int master_private_key_size = MAX_BUFFER_SIZE;
    std::vector<int8_t> public_key(MAX_BUFFER_SIZE);
    int public_key_size = MAX_BUFFER_SIZE;

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
    master_private_key.resize(master_private_key_size);
    public_key.resize(public_key_size);

    /* Encrypt Message */
    std::string plaintext = "Hello world";
    std::string encryption_policy = "Department::FIN && Security Level::Protected";
    std::vector<int8_t> header_metadata;
    std::vector<int8_t> authentication_data;
    int ciphertext_size = MAX_BUFFER_SIZE + header_metadata.size() + plaintext.size() +
                          2 * h_symmetric_encryption_overhead();
    std::vector<int8_t> ciphertext(ciphertext_size);

    if (h_hybrid_encrypt(ciphertext.data(), &ciphertext_size, policy.data(), policy.size(),
                         public_key.data(), public_key_size, (int8_t *)encryption_policy.c_str(),
                         (int8_t *)plaintext.c_str(), plaintext.size(), header_metadata.data(),
                         header_metadata.size(), authentication_data.data(),
                         authentication_data.size()) != 0) {
        std::cerr << "Error encrypting message." << std::endl;
        exit(1);
    }

    /* Create User Key */
    std::string user_policy = "Department::FIN && Security Level::Protected";
    std::vector<int8_t> user_private_key(MAX_BUFFER_SIZE);
    int user_private_key_size = MAX_BUFFER_SIZE;

    ret_code = h_generate_user_secret_key(
        user_private_key.data(), &user_private_key_size, master_private_key.data(),
        master_private_key_size, (int8_t *)user_policy.c_str(), policy.data(), policy.size());

    if (ret_code != 0) {
        // Retry with the correct allocated size
        user_private_key.resize(user_private_key_size);
        if (h_generate_user_secret_key(user_private_key.data(), &user_private_key_size,
                                       master_private_key.data(), master_private_key_size,
                                       (int8_t *)user_policy.c_str(), policy.data(),
                                       policy.size()) != 0) {
            std::cerr << "Error creating user key." << std::endl;
            exit(1);
        }
    }

    /* Decrypt Message */
    std::vector<int8_t> plaintext_out(
        ciphertext_size); // plaintext should be smaller than ciphertext
    int plaintext_size = ciphertext_size;
    std::vector<int8_t> header_buffer(MAX_BUFFER_SIZE);
    int header_size = MAX_BUFFER_SIZE;

    ret_code = h_hybrid_decrypt(plaintext_out.data(), &plaintext_size, header_buffer.data(),
                                &header_size, ciphertext.data(), ciphertext_size,
                                authentication_data.data(), authentication_data.size(),
                                user_private_key.data(), user_private_key_size);

    if (ret_code != 0) {
        // Retry with correct allocation size for the header metadata
        header_buffer.resize(header_size);
        if (h_hybrid_decrypt(plaintext_out.data(), &plaintext_size, header_buffer.data(),
                             &header_size, ciphertext.data(), ciphertext_size,
                             authentication_data.data(), authentication_data.size(),
                             user_private_key.data(), user_private_key_size) != 0) {
            std::cerr << "Error decrypting message." << std::endl;
            exit(1);
        }
    }

    std::cout << "Decrypted Message: "
              << std::string(plaintext_out.data(), plaintext_out.data() + plaintext_size)
              << std::endl;

    return 0;
}