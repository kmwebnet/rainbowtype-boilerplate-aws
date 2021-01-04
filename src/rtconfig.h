#ifndef RTCONFIG_H
#define RTCONFIG_H


#include "stdio.h"
#include "stdlib.h"

#include "cryptoauthlib.h"

#include "cert_chain.h"

ATCAIfaceCfg cfg;
#define MAX_SSID_SIZE		32
#define MAX_PASSWORD_SIZE	64


void get_atecc608cfg(ATCAIfaceCfg *cfg);


void savemiscdata (uint8_t * data);
void restoremiscdata (uint8_t * data);

uint8_t sysinit(void);

void wifiinit(char * wifissid, char * wifipass);

#endif