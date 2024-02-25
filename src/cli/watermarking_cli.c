#include "../algorithms/advanced_sampling.h"
#include "../algorithms/rejection_sampling.h"
#include "../anamorphic_ecdsa/ecdsa.h"
#include "../logger/logger.h"
#include "../utils.h"
#include <assert.h>
#include <string.h>


int main(int argc, char *argv[]) {   
    if (argc != 5) {
        printf("Usage: %s [decrypt]\n", argv[0]);
        return 0;
    }
}