#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

const int PASS_LEN = 20;  // Maximum password length
const int HASH_LEN = 33;  // MD5 hash string length

// This function tries to find a match for a hashed plaintext in a file of hashes
char *tryWord(char *plaintext, char *hashFilename) {
    // Hash the plaintext word
    char *hash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *file = fopen(hashFilename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", hashFilename);
        free(hash);  // Free the hash memory if file opening fails
        return NULL;
    }

    // Read each line (hash) from the file
    char fileHash[HASH_LEN];
    while (fgets(fileHash, HASH_LEN, file) != NULL) {
        // Remove newline if present
        fileHash[strcspn(fileHash, "\n")] = '\0';

        // Compare file hash to our generated hash
        if (strcmp(fileHash, hash) == 0) {
            fclose(file);  // Close the file before returning
            return hash;   // Return hash if match found
        }
    }

    // Clean up and close if no match found
    fclose(file);
    free(hash);
    return NULL;  // Return NULL if no match
}

int main(int argc, char *argv[]) {
    // Check for correct arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        return 1;
    }

    char *hashFile = argv[1];
    char *dictFile = argv[2];

    // Open the dictionary file for reading
    FILE *dict = fopen(dictFile, "r");
    if (dict == NULL) {
        fprintf(stderr, "Error opening dictionary file %s\n", dictFile);
        return 1;
    }

    // Track cracked hashes
    int crackedCount = 0;
    char word[PASS_LEN];

    // Read each word from the dictionary
    while (fgets(word, PASS_LEN, dict) != NULL) {
        // Remove newline character
        word[strcspn(word, "\n")] = '\0';

        // Try each word to see if it matches any hash
        char *foundHash = tryWord(word, hashFile);
        if (foundHash != NULL) {
            printf("%s %s\n", foundHash, word);  // Print matching hash and word
            crackedCount++;
        }
    }

    // Close the dictionary file
    fclose(dict);

    // Display total cracked hashes
    printf("%d hashes cracked!\n", crackedCount);
    return 0;
}

