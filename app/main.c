#include <stdio.h>
#include <string.h>
#include "od.h"
#include "aes.h"

static aes_context AesContext;

/*!
 * Encryption aBlock and sBlock
 */
static uint8_t aBlock[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                          };
static uint8_t sBlock[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                          };

void kl_aes_encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer )
{
    uint16_t i;
    uint8_t bufferIndex = 0;
    uint16_t ctr = 1;

    memset( AesContext.ksch, '\0', 240 );
    aes_set_key( key, 16, &AesContext );

    while( size >= 16 )
    {
        aBlock[15] = ( ( ctr ) & 0xFF );
        ctr++;
        aes_encrypt( aBlock, sBlock, &AesContext );
        for( i = 0; i < 16; i++ )
        {
            encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i];
        }
        size -= 16;
        bufferIndex += 16;
    }

    if( size > 0 )
    {
        aBlock[15] = ( ( ctr ) & 0xFF );
        aes_encrypt( aBlock, sBlock, &AesContext );
        for( i = 0; i < size; i++ )
        {
            encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i];
        }
    }
}

void kl_aes_decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer )
{
    kl_aes_encrypt(buffer, size, key, decBuffer);
}

static uint8_t Key[] =
{
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t en_in_data[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    0x11,0x12,0x13
};

uint8_t en_out_data[20];
uint8_t de_out_data[20];

int main(void)
{
    uint32_t len = sizeof(en_in_data);

    kl_aes_encrypt(en_in_data, len, Key, en_out_data);
    printf("encrypt :\r\n");
    od_hex_dump(en_out_data, len, 0);

    kl_aes_decrypt(en_out_data, len, Key, de_out_data);
    printf("decrypt :\r\n");
    od_hex_dump(de_out_data, len, 0);

    return 0;
}
