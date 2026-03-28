#include <stdlib.h>
#include <stdio.h>
#include <stdint.h> 
#include <string.h>

#define msg 40 //tamanho máximo do texto
#define buffer (msg + 16) //tamanho máximo de capacidade de espaço (para padding)

// AES-256 constantes
#define AES_KEY_SIZE 32
#define AES_ROUNDS 14
#define AES_ROUND_KEYS 15


// S-BOX - Tabela de substituição do AES
static const uint8_t sbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
};

// S-BOX INVERSA (para descriptografia)
static const uint8_t invSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


//printa os bytes em hexadecimial
void printHex(const uint8_t *data, int tam){
    for(int i = 0; i <  tam; i++){
        printf("%02x ", data[i]);

        // a cada 16 bytees imprime quebra de linha
        if((i + 1) % 16 == 0){
            printf("\n");
        }
    } printf("\n");
}

//sub bytes invertida 
void invSubBytes(uint8_t estado[4][4]) {
    for(int linha = 0; linha < 4; linha++) {
        for(int coluna = 0; coluna < 4; coluna++) {
            estado[linha][coluna] = invSbox[estado[linha][coluna]];
        }
    }
}

//cada byte do estado sbox
void sub_bytes(uint8_t estado[4][4]){
    //percorre linhas
    for(int linha = 0; linha < 4; linha++){
        //percorre colunas
        for(int coluna = 0; coluna < 4; coluna++){
            estado[linha][coluna] = sbox[estado[linha][coluna]];
        }
    }
}

//shift rows mas agora pra direita
void invShiftRows(uint8_t estado[4][4]) {
    uint8_t temp;
    
    // Linha 1: desloca 1 para DIREITA
    temp = estado[1][3];
    estado[1][3] = estado[1][2];
    estado[1][2] = estado[1][1];
    estado[1][1] = estado[1][0];
    estado[1][0] = temp ;
    
    // Linha 2: desloca 2 para DIREITA
    temp = estado[2][0];
    estado[2][0] = estado[2][2];
    estado[2][2] = temp;
    temp = estado[2][1];
    estado[2][1] = estado[2][3];
    estado[2][3] = temp;
    
    // Linha 3: desloca 3 para direita (ou 1 para ESQUERDA)
    temp = estado[3][0];
    estado[3][0] = estado[3][1];
    estado[3][1] = estado[3][2];
    estado[3][2] = estado[3][3];
    estado[3][3] = temp;
}

//desloca linhas da matriz
void shiftRows(uint8_t estado[4][4]){
    uint8_t temp; //variavel temp pra guardar valores

    //deloca 1 posicao
    temp = estado[1][0];
    estado [1][0] = estado[1][1];
    estado [1][1] = estado[1][2];
    estado [1][2] = estado[1][3];
    estado [1][3] = temp;

    //linha 2, desloca 2 posições
    temp = estado[2][0];
    estado[2][0] = estado[2][2];
    estado[2][2] = temp;

    temp = estado[2][1];
    estado[2][1] = estado[2][3];
    estado[2][3] = temp;

    //linha 3, desloca 3 posições(1 pra direita);
    temp = estado[3][3];
    estado[3][3] = estado[3][2];
    estado[3][2] = estado[3][1];
    estado[3][1] = estado[3][0];
    estado[3][0] = temp;
}

//função calculo de galois
uint8_t gmul(uint8_t a, uint8_t b){
    uint8_t res = 0;

    for(int i = 0; i < 8; i++){

        //verifica se o menos significativo de b é 1;
        if(b & 1){
            res ^= a; //XOR
        }

        //teste pra estouro
        uint8_t carry = a & 0x80; //guarda o bit mais esquerda;

        a <<= 1; //multiplica por 2

        if(carry) a ^= 0x1b;

        b >>= 1; //divide b por 2
    }

    return res;
}

//multiplicacao invertida tambem
void invMixColumns(uint8_t estado[4][4]) {
    uint8_t a, b, c, d;
    
    for(int coluna = 0; coluna < 4; coluna++) {
        a = estado[0][coluna];
        b = estado[1][coluna];
        c = estado[2][coluna];
        d = estado[3][coluna];
        
        // Fórmula inversa do AES
        estado[0][coluna] = gmul(0x0e, a) ^ gmul(0x0b, b) ^ gmul(0x0d, c) ^ gmul(0x09, d);
        estado[1][coluna] = gmul(0x09, a) ^ gmul(0x0e, b) ^ gmul(0x0b, c) ^ gmul(0x0d, d);
        estado[2][coluna] = gmul(0x0d, a) ^ gmul(0x09, b) ^ gmul(0x0e, c) ^ gmul(0x0b, d);
        estado[3][coluna] = gmul(0x0b, a) ^ gmul(0x0d, b) ^ gmul(0x09, c) ^ gmul(0x0e, d);
    }
}

//função que mistura colunas, e multiplica os valores usando gmul e XOR
void mixColumns(uint8_t estado[4][4]){
    uint8_t a, b, c, d; //valores da matriz estado

    for(int coluna = 0; coluna < 4; coluna++){
        //4 bytes da coluna atual
        a = estado[0][coluna];
        b = estado[1][coluna];
        c = estado[2][coluna];
        d = estado[3][coluna];

        //aplica formula do AES (documentação governo EUA)
        estado[0][coluna] = gmul(0x02, a) ^ gmul(0x03, b) ^ c ^ d;
        estado[1][coluna] = a ^ gmul(0x02, b) ^ gmul(0x03, c) ^ d;
        estado[2][coluna] = a ^ b ^ gmul(0x02, c) ^ gmul(0x03, d);
        estado[3][coluna] = gmul(0x03, a) ^ b ^ c ^ gmul(0x02, d);
    }
}

void keyDerive(){

}

// Faz XOR do estado com a chave da rodad
void add_round_key(uint8_t estado[4][4], const uint8_t roundKey[16]) {
    for(int coluna = 0; coluna < 4; coluna++) {
        for(int linha = 0; linha < 4; linha++) {
            estado[linha][coluna] ^= roundKey[coluna * 4 + linha];
        }
    }
}

//constante de rodada, usado para que elas não sejam iguais
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Key Expansion para AES-256
void keyExpansion(const uint8_t *chave, uint8_t roundKey[AES_ROUND_KEYS][16]) {
    // Copia chave original (32 bytes) para as primeiras 8 palavras (32 bytes)
    for(int i = 0; i < AES_KEY_SIZE; i++) {
        roundKey[0][i] = chave[i];
    }
    
    uint8_t temp[4];  // para manipular palavras de 4 bytes
    int palavra_atual = 8;  // já temos 8 palavras (32 bytes)
    
    // Gera as palavras restantes até ter 60 palavras (15 round keys * 4 palavras)
    while(palavra_atual < AES_ROUND_KEYS * 4) {
        // Copia a palavra anterior
        for(int i = 0; i < 4; i++) {
            temp[i] = roundKey[(palavra_atual - 1) / 4][((palavra_atual - 1) % 4) * 4 + i];
        }
        
        // A cada 8 palavras (32 bytes), aplica transformação especial
        if(palavra_atual % 8 == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for(int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
            
            // XOR com Rcon (usa rcon[palavra_atual/8])
            temp[0] ^= rcon[palavra_atual / 8];
        }
        // Para AES-256, também aplica SubWord a cada 4 palavras (16 bytes) após a primeira metade
        else if(palavra_atual % 8 == 4) {
            for(int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
        }
        
        // Gera a nova palavra
        int bloco = palavra_atual / 4;
        int offset = (palavra_atual % 4) * 4;
        int bloco_anterior = (palavra_atual - 8) / 4;
        int offset_anterior = ((palavra_atual - 8) % 4) * 4;
        
        for(int i = 0; i < 4; i++) {
            roundKey[bloco][offset + i] = roundKey[bloco_anterior][offset_anterior + i] ^ temp[i];
        }
        
        palavra_atual++;
    }
}


//adiciona a quantia de "cópias" que falta pra fechar um numero multipo de 56
int padding(uint8_t *mensagem, int tam){
    int block = 16;
    int less = block - (tam % 16);

    if(less == 0){
        less = 16;
    }

    if(!((tam + less) <= buffer)){
        printf("\n\nERRO! A palavra excede o tamanho máximo!");
        return -1;
    }

    for(int i = 0; i < less; i++){
        mensagem[tam + i] = (uint8_t)less;
    }

    return tam + less;
}

int invPadding(uint8_t *cripto, int tam){
   uint8_t value = cripto[tam-1];
   
   if((value > buffer) || value < 1){
    printf("ERRO! Padding inválido!\n\n");
    return -1;
   } else if(value > tam){
    printf("\n\nERRO! Padding maior que a mensagem!\n");
    return -1;
   }


   for(int i = 0; i > tam; i++){
        if(cripto[tam - i - value] != value){
            printf("\nERRO! Ultimo byte diferente!\n");
        }
   }
}

//funcao principal da descripto (AES-256)
void invAES(const uint8_t *cripto, const uint8_t roundKeys[AES_ROUND_KEYS][16], uint8_t *text) {
    uint8_t estado[4][4];
    
    // 1- Copiar ciphertext para estado
    for(int coluna = 0; coluna < 4; coluna++) {
        for(int linha = 0; linha < 4; linha++) {
            estado[linha][coluna] = cripto[coluna * 4 + linha];
        }
    }
    
    // 2- AddRoundKey inicial (rodada 14 - última chave)
    add_round_key(estado, roundKeys[AES_ROUNDS]);
    
    // 3- 13 rodadas principais (inverso)
    for(int rodada = AES_ROUNDS - 1; rodada >= 1; rodada--) {
        invShiftRows(estado);
        invSubBytes(estado);
        add_round_key(estado, roundKeys[rodada]);
        invMixColumns(estado);
    }
    
    // 4- Rodada final (sem inv_mix_columns)
    invShiftRows(estado);
    invSubBytes(estado);
    add_round_key(estado, roundKeys[0]);
    
    // 5- Copiar estado para plaintext
    for(int coluna = 0; coluna < 4; coluna++) {
        for(int linha = 0; linha < 4; linha++) {
            text[coluna * 4 + linha] = estado[linha][coluna];
        }
    }
}

//funcao principal (AES-256)
void AES(const uint8_t *text, const uint8_t roundKeys[AES_ROUND_KEYS][16], uint8_t *cripto) {
    uint8_t estado[4][4];

    // 1- Copiar texto para o estado (por coluna)
    for(int coluna = 0; coluna < 4; coluna++) {
        for(int linha = 0; linha < 4; linha++) {
            estado[linha][coluna] = text[coluna * 4 + linha];
        }
    }

    // 2- AddRoundKey inicial (rodada 0)
    add_round_key(estado, roundKeys[0]);

    // 3- 13 rodadas principais
    for(int rodada = 1; rodada <= AES_ROUNDS - 1; rodada++) {
        sub_bytes(estado);
        shiftRows(estado);
        mixColumns(estado);
        add_round_key(estado, roundKeys[rodada]);
    }

    // 4- Rodada final (sem mixColumns)
    sub_bytes(estado);
    shiftRows(estado);
    add_round_key(estado, roundKeys[AES_ROUNDS]);

    // 5- Copiar estado para ciphertext
    for(int coluna = 0; coluna < 4; coluna++) {
        for(int linha = 0; linha < 4; linha++) {
            cripto[coluna * 4 + linha] = estado[linha][coluna];
        }
    }
}

int main() {
    printf("=== TESTE AES-256 ===\n\n");
    
    // Chave de teste (32 bytes) para AES-256
    uint8_t chave[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Texto claro (16 bytes)
    uint8_t text_original[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    uint8_t roundKeys[AES_ROUND_KEYS][16];
    uint8_t cripto[16];
    uint8_t text[16];
    
    // Expande a chave
    keyExpansion(chave, roundKeys);
    
    printf("Chave (32 bytes):\n");
    printHex(chave, 32);
    
    printf("\nTexto original:\n");
    printHex(text_original, 16);
    
    // CRIPTOGRAFAR
    AES(text_original, roundKeys, cripto);
    
    printf("\nTexto cifrado:\n");
    printHex(cripto, 16);
    
    // DESCRIPTOGRAFAR
    invAES(cripto, roundKeys, text);
    
    printf("\nTexto decifrado:\n");
    printHex(text, 16);
    
    // Verifica se voltou ao original
    if(memcmp(text_original, text, 16) == 0) {
        printf("\n✅ DESCRIPTOGRAFIA FUNCIONOU! AES-256 CORRETO!\n");
    } else {
        printf("\nDESCRIPTOGRAFIA FALHOU\n");
    }
    
    return 0;
}