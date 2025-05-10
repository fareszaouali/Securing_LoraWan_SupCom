/*
                    LoraXploit Framework                   
                                                          
              Master CS 2024/2025 - Sup'COM               
       Authors: Fares Zaouali & Nour Elhouda Lajnef       
*/

#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include "headers/loracrack.h"

#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink

// Signature printing function 
void print_centered_line(const char* text) {
    int length = strlen(text);
    int spaces = 58 - length;

    // Print the leading asterisk and space
    printf("*");

    // Print left padding
    for (int i = 0; i < spaces / 2; i++) {
        printf(" ");
    }

    // Print the actual text
    printf("%s", text);

    // Print right padding
    for (int i = 0; i < spaces / 2; i++) {
        printf(" ");
    }

    // If the length of text is odd, add one more space to the right side
    if (spaces % 2 != 0) {
        printf(" ");
    }

    // Print the closing asterisk and newline
    printf(" *\n");
}
// End printing 

int verbose = 0;

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {
    decoding_table = malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

void base64_cleanup() {
    free(decoding_table);
}

char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (decoding_table == NULL) build_decoding_table();
    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) +
                         (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

char *string2hexString(unsigned char* input, size_t input_len) {
    char *buffer = malloc(input_len*2 + 1);
    buffer[input_len*2] = '\0';

    for(int i = 0; i < input_len; i++) {
        sprintf(&buffer[2*i], "%02X", input[i]);
    }

    return buffer;
}

// Global variables
volatile bool cracked = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned char *AppKey;
unsigned char *packet;
unsigned char MIC[4];
unsigned char *MIC_data;
unsigned short dev_nonce = 0;
bool dev_nonce_given = false;
unsigned int net_id = 19;
size_t MIC_data_len = 0;

void *loracrack_thread(void *vargp) {
    EVP_CIPHER_CTX *ctx_aes128 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_aes128_buf = EVP_CIPHER_CTX_new();
    CMAC_CTX *ctx_aes128_cmac = CMAC_CTX_new();

    unsigned char NwkSKey[16];
    unsigned char cmac_result[16];
    size_t cmac_result_len;
    int outlen;

    unsigned int thread_ID = ((struct thread_args*)vargp)->thread_ID;
    unsigned int AppNonce_current = ((struct thread_args*)vargp)->AppNonce_start;
    unsigned int AppNonce_end = ((struct thread_args*)vargp)->AppNonce_end;
    unsigned int NetID_start = ((struct thread_args*)vargp)->NetID_start;
    unsigned short DevNonce = 0;

    if (verbose)
        printf("Thread %i cracking from AppNonce %i to %i\n", thread_ID, AppNonce_current, AppNonce_end);

    unsigned char message[16];
    memset(message, 0, 16);
    message[0] = 0x01;

    EVP_EncryptInit_ex(ctx_aes128_buf, EVP_aes_128_ecb(), NULL, AppKey, NULL);

    while (AppNonce_current < AppNonce_end && !cracked) {
        if (dev_nonce_given)
            DevNonce = dev_nonce;
        else
            DevNonce = 0;

        if (verbose == 2)
            printf("Thread %i @ AppNonce %i\n", thread_ID, AppNonce_current);

        message[1] = (AppNonce_current >> (8*0)) & 0xff;
        message[2] = (AppNonce_current >> (8*1)) & 0xff;
        message[3] = (AppNonce_current >> (8*2)) & 0xff;

        while (DevNonce < 0xffff) {
            message[7] = (DevNonce >> (8*0)) & 0xff;
            message[8] = (DevNonce >> (8*1)) & 0xff;

            EVP_CIPHER_CTX_copy(ctx_aes128, ctx_aes128_buf);
            EVP_EncryptUpdate(ctx_aes128, NwkSKey, &outlen, message, 16);

            CMAC_Init(ctx_aes128_cmac, NwkSKey, 16, EVP_aes_128_cbc(), NULL);
            CMAC_Update(ctx_aes128_cmac, MIC_data, MIC_data_len);
            CMAC_Final(ctx_aes128_cmac, cmac_result, &cmac_result_len);

            if (memcmp(cmac_result, MIC, 4) == 0) {
                if (verbose)
                    printf("\nFound a pair of possible session keys\n");

                unsigned char AppSKey[16];
                message[0] = 0x02;
                EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
                EVP_EncryptUpdate(ctx_aes128, AppSKey, &outlen, message, 16);

                if (verbose)
                    printf("\nAppSKey,");
                printBytes(AppSKey, 16);
                printf(" ");

                if (verbose)
                    printf("\nNwkSKey,");
                printBytes(NwkSKey, 16);

                if (verbose) {
                    printf("\nAppNonce,%x (%d)\n", AppNonce_current, AppNonce_current);
                    printf("DevNonce,%x (%d)\n", DevNonce, DevNonce);
                }

                message[0] = 0x01;
            }

            if (dev_nonce_given) {
                break;
            } else {
                DevNonce += 1;
            }
        }
        AppNonce_current += 1;
    }

    EVP_CIPHER_CTX_free(ctx_aes128);
    EVP_CIPHER_CTX_free(ctx_aes128_buf);
    CMAC_CTX_free(ctx_aes128_cmac);
    return NULL;
}

int main(int argc, char **argv) {
    char *AppKey_hex = NULL, *packet_b64 = NULL, *net_id_hex = NULL;
    unsigned int n_threads = 1;
    unsigned int max_AppNonce = 16777216;

    int c;
    while ((c = getopt(argc, argv, "v:p:k:t:m:n:i:")) != -1) {
        switch (c) {
            case 'k': AppKey_hex = optarg; break;
            case 'p': packet_b64 = optarg; break;
            case 'v': verbose = atoi(optarg); break;
            case 't': n_threads = atoi(optarg); break;
            case 'm': max_AppNonce = atoi(optarg); break;
            case 'n': dev_nonce = atoi(optarg); dev_nonce_given = true; break;
            case 'i': net_id_hex = optarg; break;
        }
    }

    if (AppKey_hex == NULL || packet_b64 == NULL)
        error_die("Usage: ./loracrack -k <AppKey> -p <B64 PHYPayload> [-t <threads> -m <max AppNonce> -n <DevNonce> -v <verbose>]");

    size_t b64_len = strlen(packet_b64);
    size_t bytes_len;
    unsigned char *bytes = base64_decode(packet_b64, b64_len, &bytes_len);
    char *packet_hex = string2hexString(bytes, bytes_len);

    validate_hex_input(AppKey_hex);
    validate_hex_input(packet_hex);

    if (net_id_hex != NULL) {
        validate_hex_input(net_id_hex);
        size_t net_id_len = strlen(net_id_hex) / 2;
        if (net_id_len != 3)
            error_die("Net ID must be 3 bytes in hex format");
        net_id = (int)strtol(net_id_hex, NULL, 16);
    }

    size_t AppKey_len = strlen(AppKey_hex) / 2;
    size_t packet_len = strlen(packet_hex) / 2;

    if (AppKey_len != 16)
        error_die("AppKey must be 16 bytes");
    if (packet_len <= 13)
        printf("Packet data too small");
    if (dev_nonce_given && (dev_nonce < 0 || dev_nonce > 65535))
        error_die("Dev Nonce must be between 0 and 65,535");

    AppKey = hexstr_to_char(AppKey_hex);
    packet = hexstr_to_char(packet_hex);

    char MHDR = packet[0];
    int MType = bitExtracted(MHDR, 3, 6);

    if (MType < 2 || MType > 5)
        error_die("Packet not of type Data Up or Data Down");

    char Dir = (MType == 2 || MType == 4) ? MType_UP : MType_DOWN;
    unsigned int DevAddr = 0;
    memcpy(&DevAddr, packet+1, 4);

    int FCtrl = packet[5];
    int FOptsLen = bitExtracted(FCtrl, 4, 4);
    short FCnt = 0;
    memcpy(&FCnt, packet+6, 2);

    size_t FRMPayload_index = 9 + FOptsLen;
    if (packet_len - 4 <= FRMPayload_index)
        error_die("No FRMPayload data");

    size_t FRMPayload_len = (packet_len - 4) - FRMPayload_index;
    unsigned char *FRMPayload = malloc(FRMPayload_len);
    memcpy(FRMPayload, packet+FRMPayload_index, FRMPayload_len);

    int msg_len = packet_len - 4;
    char B0[16] = {
        0x49, 0x00, 0x00, 0x00, 0x00,
        Dir,
        (DevAddr >> (8*0)) & 0xff,
        (DevAddr >> (8*1)) & 0xff,
        (DevAddr >> (8*2)) & 0xff,
        (DevAddr >> (8*3)) & 0xff,
        (FCnt >> (8*0)) & 0xff,
        (FCnt >> (8*1)) & 0xff,
        0x00, 0x00, 0x00,
        msg_len
    };

    MIC_data_len = 16 + msg_len;
    MIC_data = malloc(MIC_data_len+1);
    memcpy(MIC_data, B0, 16);
    memcpy(MIC_data+16, packet, msg_len);

    MIC[0] = *(packet + (packet_len - 4));
    MIC[1] = *(packet + (packet_len - 3));
    MIC[2] = *(packet + (packet_len - 2));
    MIC[3] = *(packet + (packet_len - 1));

    if (verbose) {

        printf("************************************************************\n");

    // Print the centered lines
        print_centered_line("");
        print_centered_line("LoraXploit Framework");
        print_centered_line(argv[0]);  // The name of the script (program) being executed
        print_centered_line("");
        print_centered_line("Master CS 2024/2025 - Sup'COM");
        print_centered_line("Authors: Fares Zaouali & Nour Elhouda Lajnef");
        print_centered_line("");

    // Print the bottom border
        printf("************************************************************\n");

    // Additional section after the border
        print_centered_line("");
        print_centered_line("Based on LoRaWAN Security Framework by IOActive Inc.");
        print_centered_line("Modified for educational use under academic project.");
        print_centered_line("");
        printf("************************************************************\n");

        printf("------. L o R a C r a c k  ------\n");
        printf("Cracking with AppKey:\t");
        printBytes(AppKey, 16);
        printf("\nTrying to find MIC:\t");
        printBytes(MIC, 4);
    }

    unsigned int per_thread = max_AppNonce / n_threads;
    pthread_t tids[n_threads];

    if (verbose) {
        printf("\n\nUsing %i threads, %i nonces per thread\n", n_threads, per_thread);
        printf("max AppNonce = %u\nSearch space: %lu\n\n", max_AppNonce, (unsigned long)max_AppNonce * 0xffff);
    }

    for (int i = 0; i < n_threads; i++) {
        struct thread_args *thread_args = malloc(sizeof(struct thread_args));
        thread_args->thread_ID = i;
        thread_args->AppNonce_start = i*per_thread;
        thread_args->AppNonce_end = (i*per_thread)+per_thread;
        thread_args->NetID_start = net_id;

        pthread_t tid;
        pthread_create(&tid, NULL, loracrack_thread, (void *)thread_args);
        tids[i] = tid;
    }

    for (int i = 0; i < n_threads; i++)
        pthread_join(tids[i], NULL);

    free(bytes);
    free(packet_hex);
    free(FRMPayload);
    free(MIC_data);
    base64_cleanup();

    return 0;
}
