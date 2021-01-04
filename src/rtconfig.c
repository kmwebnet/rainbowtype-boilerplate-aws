
#include "rtconfig.h"


static uint8_t secdata[32] = {};

extern uint8_t iokeyrandom[32];


void get_atecc608cfg(ATCAIfaceCfg *cfg)
{
                cfg->iface_type             = ATCA_I2C_IFACE;
                cfg->devtype                = ATECC608A;
                cfg->atcai2c.slave_address  = 0XC0;
                cfg->atcai2c.bus            = 1;
                cfg->atcai2c.baud           = 100000;
                cfg->wake_delay             = 1500;
                cfg->rx_retries             = 20;

return;
}


int atca_mbedtls_ecdh_slot_cb(void)
{
    return 0xFFFF;
}

int atca_mbedtls_ecdh_ioprot_cb(uint8_t secret[32])
{

    if (ATCA_SUCCESS != atcab_random(iokeyrandom))
    {
        printf("Failed to generate IO Prot Key");
        return 1;
    }

    if (ATCA_SUCCESS != atcab_write_zone(ATCA_ZONE_DATA, 6, 0, 0, iokeyrandom, ATCA_BLOCK_SIZE))
    {
        printf("Failed to write IO Prot Key");
        return 1;
    }
    memcpy(secret, iokeyrandom, ATCA_BLOCK_SIZE);

    return 0;
}



static void restoredevstatus (uint8_t * data)
{
    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
    }

    atca_mbedtls_ecdh_ioprot_cb(iokeyrandom);
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

    if (ATCA_SUCCESS != atcab_read_enc(8 , 4 , data ,iokeyrandom ,  6 , num_in)) {
   	printf("read data to slot8 failed");
    }
return;
}


void savemiscdata (uint8_t * data)
{
    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
    }

    atca_mbedtls_ecdh_ioprot_cb(iokeyrandom);
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

    for (int i = 0 ;  i < 8 ; i++)
    {
        if (ATCA_SUCCESS != atcab_write_enc(8 , 5 + i , &data[32 * i] ,iokeyrandom ,  6 , num_in)) 
        {
   	    printf("read data to slot8 failed");
        }
    }

return;
}

void restoremiscdata (uint8_t * data)
{

    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
    }

    atca_mbedtls_ecdh_ioprot_cb(iokeyrandom);
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

    for (int i = 0 ;  i < 8 ; i++)
    {
        if (ATCA_SUCCESS != atcab_read_enc(8 , 5 + i , &data[32 * i] ,iokeyrandom ,  6 , num_in)) 
        {
   	    printf("read data to slot8 failed");
        }
    }

return;
}



uint8_t sysinit(void)
{
    restoredevstatus(secdata);
    g_cert_def_2_device.public_key_dev_loc.slot = secdata[0];
    return secdata[0] ;

}

static void restorecredentials (char * wifissid, char * wifipass)
{

    atca_mbedtls_ecdh_ioprot_cb(iokeyrandom);
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

    if (ATCA_SUCCESS != atcab_read_enc(8 , 0 , (uint8_t *)wifissid ,iokeyrandom ,  6 , num_in)) {
   	printf("read ssid to slot8 failed");
    }

    if (ATCA_SUCCESS != atcab_read_enc(8 , 1 , (uint8_t *)wifipass , iokeyrandom ,  6 , num_in)) {
   	printf("read pass1 to slot8 failed");
    }

    if (ATCA_SUCCESS != atcab_read_enc(8 , 2 , (uint8_t *)&wifipass[32] , iokeyrandom ,  6 , num_in)) {
   	printf("read pass2 to slot8 failed");
    }

return;
}



void wifiinit(char * wifissid, char * wifipass)
{

    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
    }
	restorecredentials(wifissid,  wifipass);
return;
}
