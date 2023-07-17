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

    char my_policy[MAX_BUFFER_SIZE];
    int my_policy_size = 0;

    char buffer[MAX_BUFFER_SIZE];
    int buffer_size = MAX_BUFFER_SIZE;

    int ret = h_policy(buffer, &buffer_size, 100);
    memcpy(my_policy, buffer, buffer_size);
    my_policy_size = buffer_size;
    printf("%d, %d\n", ret, my_policy_size);

    buffer_size = MAX_BUFFER_SIZE;
    ret = h_add_policy_axis(buffer, &buffer_size, my_policy, my_policy_size, policy_axis_sec);
    memcpy(my_policy, buffer, buffer_size);
    my_policy_size = buffer_size;
    printf("%d, %d\n", ret, my_policy_size);

    buffer_size = MAX_BUFFER_SIZE;
    ret = h_add_policy_axis(buffer, &buffer_size, my_policy, my_policy_size, policy_axis_dep);
    memcpy(my_policy, buffer, buffer_size);
    my_policy_size = buffer_size;
    printf("%d, %d\n", ret, my_policy_size);

    /*  Create Master Keys  */
    char masterPrivateKey[MAX_BUFFER_SIZE];
    int masterPrivateKeySize = MAX_BUFFER_SIZE;
    char masterPublicKey[MAX_BUFFER_SIZE];
    int masterPublicKeySize = MAX_BUFFER_SIZE;

    ret = h_generate_master_keys(masterPrivateKey, &masterPrivateKeySize, masterPublicKey,
                                 &masterPublicKeySize, my_policy, my_policy_size);

    printf("%d, %d, %d\n", ret, masterPrivateKeySize, masterPublicKeySize);

    /*  Encrypt Message  */
    char plaintext[] = "Hello world";
    char encryption_policy[] = "Department::FIN && Security Level::Protected";
    char ciphertext[MAX_BUFFER_SIZE];
    int ciphertext_size = MAX_BUFFER_SIZE;
    char header_metadata[] = {};
    char authentication_data[] = {};

    ret = h_hybrid_encrypt(ciphertext, &ciphertext_size, my_policy, my_policy_size, masterPublicKey,
                           masterPublicKeySize, encryption_policy, plaintext, sizeof(plaintext),
                           header_metadata, 0, authentication_data, 0);

    printf("Enc Message: %d, %d, %d\n", ret, sizeof(plaintext), ciphertext_size);

    /*  Create User Key  */
    char user_policy[] = "Department::FIN && Security Level::Protected";
    char user_private_key[MAX_BUFFER_SIZE];
    int user_private_key_size = MAX_BUFFER_SIZE;

    ret = h_generate_user_secret_key(user_private_key, &user_private_key_size, masterPrivateKey,
                                     masterPrivateKeySize, user_policy, my_policy, my_policy_size);

    printf("User Key: %d, %d\n", ret, user_private_key_size);

    /*  Decrypt Message  */
    char *plaintext_out = (char *)malloc(ciphertext_size);
    int plaintext_size = ciphertext_size;
    char header_buffer[MAX_BUFFER_SIZE];
    int header_size = MAX_BUFFER_SIZE;
    h_hybrid_decrypt(plaintext_out, &plaintext_size, header_buffer, &header_size, ciphertext,
                     ciphertext_size, authentication_data, 0, user_private_key,
                     user_private_key_size);

    printf("Dec Message: %d, %d, %s\n", ret, plaintext_size, plaintext_out);

    free(plaintext_out);

    return 0;
}
