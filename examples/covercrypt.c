#include "cloudproof.h"
#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 8192

int main() {
    /*  Create Policy  */
    int8_t policy_axis_sec[] = "{ \"name\": \"Security Level\", \"attributes_properties\": ["
                               "{ \"name\": \"Protected\", \"encryption_hint\": \"Classic\" },"
                               "{ \"name\": \"Confidential\", \"encryption_hint\": \"Classic\" },"
                               "{ \"name\": \"Top Secret\", \"encryption_hint\": \"Hybridized\" }"
                               "], \"hierarchical\": true }";

    int8_t policy_axis_dep[] = "{ \"name\": \"Department\", \"attributes_properties\": ["
                               "{ \"name\": \"FIN\", \"encryption_hint\": \"Classic\" },"
                               "{ \"name\": \"MKG\", \"encryption_hint\": \"Classic\" },"
                               "{ \"name\": \"HR\", \"encryption_hint\": \"Classic\" }"
                               "], \"hierarchical\": false }";

    int8_t policy[MAX_BUFFER_SIZE];
    int policy_size = 0;

    int8_t buffer[MAX_BUFFER_SIZE];
    int buffer_size = MAX_BUFFER_SIZE;

    if (h_policy(buffer, &buffer_size, 100) != 0) {
        fprintf(stderr, "Error creating policy.\n");
        exit(1);
    }

    memcpy(policy, buffer, buffer_size);
    policy_size = buffer_size;

    // Add axis Security Level
    buffer_size = MAX_BUFFER_SIZE;
    if (h_add_policy_axis(buffer, &buffer_size, policy, policy_size, policy_axis_sec) != 0) {
        fprintf(stderr, "Error adding policy axis.\n");
        exit(1);
    }
    memcpy(policy, buffer, buffer_size);
    policy_size = buffer_size;

    // Add axis Department
    buffer_size = MAX_BUFFER_SIZE;
    if (h_add_policy_axis(buffer, &buffer_size, policy, policy_size, policy_axis_dep) != 0) {
        fprintf(stderr, "Error adding policy axis.\n");
        exit(1);
    }
    memcpy(policy, buffer, buffer_size);
    policy_size = buffer_size;

    /*  Create Master Keys  */
    int master_private_key_size = MAX_BUFFER_SIZE;
    int8_t *master_private_key = malloc(master_private_key_size);
    int public_key_size = MAX_BUFFER_SIZE;
    int8_t *public_key = malloc(public_key_size);

    int ret_code = h_generate_master_keys(master_private_key, &master_private_key_size, public_key,
                                          &public_key_size, policy, policy_size);

    if (ret_code != 0) {
        // Retry with correct allocated size
        master_private_key = realloc(master_private_key, master_private_key_size);
        public_key = realloc(public_key, public_key_size);
        if (h_generate_master_keys(master_private_key, &master_private_key_size, public_key,
                                   &public_key_size, policy, policy_size) != 0) {
            fprintf(stderr, "Error creating master keys.\n");
            exit(1);
        }
    }

    /*  Encrypt Messages  */
    // Empty metadata and authentication data
    int8_t header_metadata[0];
    int8_t authentication_data[0];

    // Protected marketing message
    int8_t protected_mkg_data[] = "protected_mkg_message";
    int8_t protected_mkg_policy[] = "Department::MKG && Security Level::Protected";
    int protected_mkg_ciphertext_size = MAX_BUFFER_SIZE + sizeof(header_metadata) +
                                        sizeof(protected_mkg_data) +
                                        2 * h_symmetric_encryption_overhead();
    int8_t protected_mkg_ciphertext[protected_mkg_ciphertext_size];

    if (h_hybrid_encrypt(protected_mkg_ciphertext, &protected_mkg_ciphertext_size, policy,
                         policy_size, public_key, public_key_size, protected_mkg_policy,
                         protected_mkg_data, sizeof(protected_mkg_data), header_metadata,
                         sizeof(header_metadata), authentication_data,
                         sizeof(authentication_data)) != 0) {
        fprintf(stderr, "Error encrypting message.\n");
        exit(1);
    }

    // Top secret marketing message
    int8_t topsecret_mkg_data[] = "top_secret_mkg_message";
    int8_t topsecret_mkg_policy[] = "Department::MKG && Security Level::Top Secret";
    int topsecret_mkg_ciphertext_size = MAX_BUFFER_SIZE + sizeof(header_metadata) +
                                        sizeof(topsecret_mkg_data) +
                                        2 * h_symmetric_encryption_overhead();
    int8_t topsecret_mkg_ciphertext[topsecret_mkg_ciphertext_size];

    if (h_hybrid_encrypt(topsecret_mkg_ciphertext, &topsecret_mkg_ciphertext_size, policy,
                         policy_size, public_key, public_key_size, topsecret_mkg_policy,
                         topsecret_mkg_data, sizeof(topsecret_mkg_data), header_metadata,
                         sizeof(header_metadata), authentication_data,
                         sizeof(authentication_data)) != 0) {
        fprintf(stderr, "Error encrypting message.\n");
        exit(1);
    }

    /*  Create User Key  */
    int8_t user_policy[] = "Department::MKG && Security Level::Confidential";
    int user_private_key_size = MAX_BUFFER_SIZE;
    int8_t *user_private_key = malloc(user_private_key_size);

    ret_code =
        h_generate_user_secret_key(user_private_key, &user_private_key_size, master_private_key,
                                   master_private_key_size, user_policy, policy, policy_size);

    if (ret_code != 0) {
        // Retry with the correct allocated size
        user_private_key = realloc(user_private_key, user_private_key_size);
        if (h_generate_user_secret_key(user_private_key, &user_private_key_size, master_private_key,
                                       master_private_key_size, user_policy, policy,
                                       policy_size) != 0) {
            fprintf(stderr, "Error creating user key.\n");
            exit(1);
        }
    }

    /*  Decrypt Messages  */
    // No header metadata in our ciphertext
    int8_t header_buffer[0];
    int header_size = 0;

    // Our user key can decrypt the protected marketing message
    int plaintext_size =
        protected_mkg_ciphertext_size; // plaintext should be smaller than ciphertext
    int8_t *plaintext_out = malloc(plaintext_size);

    if (h_hybrid_decrypt(plaintext_out, &plaintext_size, header_buffer, &header_size,
                         protected_mkg_ciphertext, protected_mkg_ciphertext_size,
                         authentication_data, sizeof(authentication_data), user_private_key,
                         user_private_key_size) != 0) {
        fprintf(stderr, "Error decrypting protected marketing message.\n");
        exit(1);
    }
    printf("Successfully decrypted protected marketing message: '%s'.\n", plaintext_out);

    // But we can't decrypt the top secret marketing message
    plaintext_size = topsecret_mkg_ciphertext_size;
    int8_t *plaintext_out2 = malloc(plaintext_size);

    if (h_hybrid_decrypt(plaintext_out2, &plaintext_size, header_buffer, &header_size,
                         topsecret_mkg_ciphertext, topsecret_mkg_ciphertext_size,
                         authentication_data, sizeof(authentication_data), user_private_key,
                         user_private_key_size) == 0) {
        fprintf(stderr, "We should not be able to decrypt top secret marketing message.\n");
        exit(1);
    }
    printf("As expected, we can't decrypt a top secret marketing message.\n");

    free(plaintext_out);
    free(plaintext_out2);

    free(user_private_key);
    free(public_key);
    free(master_private_key);

    return 0;
}
