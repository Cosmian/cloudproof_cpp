#include "cloudproof.h"
#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 8192

int main() {
    /*  Create Policy  */
    char policy_axis_sec[] = "{ \"name\": \"Security Level\", \"attributes_properties\": ["
                             "{ \"name\": \"Protected\", \"encryption_hint\": \"Classic\" },"
                             "{ \"name\": \"Confidential\", \"encryption_hint\": \"Classic\" },"
                             "{ \"name\": \"Top Secret\", \"encryption_hint\": \"Hybridized\" }"
                             "], \"hierarchical\": true }";

    char policy_axis_dep[] = "{ \"name\": \"Department\", \"attributes_properties\": ["
                             "{ \"name\": \"FIN\", \"encryption_hint\": \"Classic\" },"
                             "{ \"name\": \"MKG\", \"encryption_hint\": \"Classic\" },"
                             "{ \"name\": \"HR\", \"encryption_hint\": \"Classic\" }"
                             "], \"hierarchical\": false }";

    char policy[MAX_BUFFER_SIZE];
    int policy_size = 0;

    char buffer[MAX_BUFFER_SIZE];
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
    char master_private_key[MAX_BUFFER_SIZE];
    int master_private_key_size = MAX_BUFFER_SIZE;
    char public_key[MAX_BUFFER_SIZE];
    int public_key_size = MAX_BUFFER_SIZE;

    int ret_code = h_generate_master_keys(master_private_key, &master_private_key_size, public_key,
                                          &public_key_size, policy, policy_size);

    if (ret_code != 0) {
        // Retry with correct allocated size
        char master_private_key[master_private_key_size];
        char public_key[public_key_size];
        if (h_generate_master_keys(master_private_key, &master_private_key_size, public_key,
                                   &public_key_size, policy, policy_size) != 0) {
            fprintf(stderr, "Error creating master keys.\n");
            exit(1);
        }
    }

    /*  Encrypt Message  */
    char plaintext[] = "Hello world";
    char encryption_policy[] = "Department::FIN && Security Level::Protected";
    char header_metadata[] = {};
    char authentication_data[] = {};
    int ciphertext_size = MAX_BUFFER_SIZE + sizeof(header_metadata) + sizeof(plaintext) +
                          2 * h_symmetric_encryption_overhead();
    char ciphertext[ciphertext_size];

    if (h_hybrid_encrypt(ciphertext, &ciphertext_size, policy, policy_size, public_key,
                         public_key_size, encryption_policy, plaintext, sizeof(plaintext),
                         header_metadata, sizeof(header_metadata), authentication_data,
                         sizeof(authentication_data)) != 0) {
        fprintf(stderr, "Error encrypting message.\n");
        exit(1);
    }

    /*  Create User Key  */
    char user_policy[] = "Department::FIN && Security Level::Protected";
    char user_private_key[MAX_BUFFER_SIZE];
    int user_private_key_size = MAX_BUFFER_SIZE;

    ret_code =
        h_generate_user_secret_key(user_private_key, &user_private_key_size, master_private_key,
                                   master_private_key_size, user_policy, policy, policy_size);

    if (ret_code != 0) {
        // Retry with the correct allocated size
        char user_private_key[user_private_key_size];
        if (h_generate_user_secret_key(user_private_key, &user_private_key_size, master_private_key,
                                       master_private_key_size, user_policy, policy,
                                       policy_size) != 0) {
            fprintf(stderr, "Error creating user key.\n");
            exit(1);
        }
    }

    /*  Decrypt Message  */
    char *plaintext_out =
        (char *)malloc(ciphertext_size); // plaintext should be smaller than cipher text
    int plaintext_size = ciphertext_size;
    char header_buffer[MAX_BUFFER_SIZE];
    int header_size = MAX_BUFFER_SIZE;

    ret_code = h_hybrid_decrypt(
        plaintext_out, &plaintext_size, header_buffer, &header_size, ciphertext, ciphertext_size,
        authentication_data, sizeof(authentication_data), user_private_key, user_private_key_size);
    if (ret_code != 0) {
        // retry with correct allocation size for the header metadata
        char header_buffer[header_size];
        if (h_hybrid_decrypt(plaintext_out, &plaintext_size, header_buffer, &header_size,
                             ciphertext, ciphertext_size, authentication_data,
                             sizeof(authentication_data), user_private_key,
                             user_private_key_size) != 0) {
            fprintf(stderr, "Error decrypting message.\n");
            exit(1);
        }
    }

    printf("Decrypted Message: %s\n", plaintext_out);

    free(plaintext_out);

    return 0;
}
