#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f;
    size_t flagSize;
    unsigned int seed;
    f = fopen("flag.enc", "rb");
    // seek until the end of the file to get the size
    fseek(f, 0, SEEK_END);
    flagSize = ftell(f);
    // seek to the beginning
    fseek(f, 0, SEEK_SET);

    fread(&seed, 1, 4, f);
    fclose(f);

    printf("seed: %d\n", seed);
    srand(seed);

    for(int i = 0; i < (long)flagSize; i++) {
        printf("%d\n", rand());
    }

    return 0;
}
