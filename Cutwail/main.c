/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.c
 * Author: Levis
 *
 * Created on August 18, 2017, 11:07 AM
 */

#include "botinfo.h"

// Ripped code from original binary
int msgScramble(BYTE* start, int len, int seed)
{
	int v3, v4, v5, v6, v9, v10;
	void* v7;
	v9 = 0;
	v3 = 0;
	if(start && len && seed)
	{
		 v4 = 1664525 * seed + 1013904223;
		 v5 = len / 4;
		 if ( len / 4 > 0 )
	  		{
		    	v9 = 4 * v5;
		    	do
		    	{
		        	*(DWORD *)(start + 4 * v3) ^= v4;
		        	v4 = 1664525 * v4 + 1013904223;
		        	++v3;
		      	}
		    	while ( v3 < v5 );
		    }
		v6 = len % 4;
	 	if ( len % 4 )
	    {
	    	v10 = 0;
	    	v7 = (void *)(start + 4 * v3);
	    	memcpy(&v10, (const void *)(start + 4 * v3), v6);
	    	v10 ^= v4;
	    	memcpy(v7, &v10, v6);
	    	v9 += v6;
	    }
	}
	return v9;
}

//Ripped code from original binary but not very true. Need to be fixed
int get_checksum(BYTE* data , int len)
{
	signed int count, loop;
    unsigned int seed, result; //count, seed, loop, result;
	BYTE* buffer;
	int table[0x100];
	count = 0;
	do
	{
		seed = count;
		loop = 8;
		do {
			if(seed & 1)
				seed = (seed >> 1) ^ 0xEDB88320;
			else
				seed >>= 1;
			--loop;
		}
		while(loop);
		table[count++] = seed;
	}
	while(count<0x100);
	result = -1;
	if (len) {
		buffer = data;
		do {
			--len;
			result = table[(unsigned __int8)(result ^ *buffer++)] ^ (result >> 8);
		}
		while(len);
	}
	return result;
}

// Parse flags for infection status
char* getState(DWORD status, DWORD indicator)
{
	if(status & indicator) return (char*)"TRUE"; else return (char*)"FALSE";
}

BOOL parseStatus(DWORD status, char* output)
{
	sprintf(output, "ShellPrime and Zap reg keys written: %s\n"
					"Mutex Created: %s\nAppManagement key written: %s\n"
					"Found ComObj GZIP and TEXT: %s\n"
					"Dummy Compare: %s\n"
					"!WSAStartup: %s\n",
			getState(status, IDC_WRITE_KEY_SHELL_ZAP),
			getState(status, IDC_MUTEX_CREATED),
			getState(status, IDC_WRITE_KEY_APPMGNT),
			getState(status, IDC_COMOBJ_GZIP_TEXT),
			getState(status,IDC_DUMMY_COMPARE),
			getState(status, IDC_NET_CONNECTED));
}

BOOL decryptMessage(BYTE* encryptedData, DWORD encryptedDataLen, BYTE* sessionKey, DWORD sessionKeyLen, BYTE* rsaKey, DWORD rsaKeyLen)
{
	BOOL result = FALSE;
	HCRYPTPROV hProv;
	//Store Session key blob
	HCRYPTKEY hkey;
	// Store RSA key blob
	HCRYPTKEY rsa;
	if(encryptedData && encryptedDataLen && sessionKey && sessionKeyLen && rsaKey && rsaKeyLen) {
		hProv = 0;
		if(CryptAcquireContextA(&hProv, 0, crypt_prov_name, 1, 0) && GetLastError() == ERROR_SUCCESS) {
			if(hProv) {
				rsa = 0;
				//Import RSA key blob
				if(CryptImportKey(hProv, rsaKey, rsaKeyLen, 0, 1, &rsa)) {
					hkey = 0;
					//Use RSA key blob to decrypt encrypted session key
					if(CryptImportKey(hProv, sessionKey, sessionKeyLen, rsa, 1, &hkey)) {
						// Decrypt Data with decrypted session Key
						result = CryptDecrypt(hkey, 0, 1, 0, encryptedData, encryptedDataLen);
						CryptDestroyKey(hkey);
					}
				CryptDestroyKey(rsa);
				}
			CryptReleaseContext(hProv);
			}
		}
	return result;
	}
	return FALSE;
}

BOOL msgDeserialize(BYTE* in, int inLen , msgStruct* out)
{
    BOOL result;
    //First 4 bytes is seed #1 generated by GetPerformanceCounter()
    out->seed_1 = *(DWORD*)in;
    //Next 4 bytes is seed  #2 generated by GetPerformanceCounter()
    out->seed_2 = *(DWORD*)(in + 4);
    //Next 4 bytes is whole message checksum 
    out->checksum = *(DWORD*)(in + 8);
    /*  Next  144 bytes contains:
    	4 bytes  for exported key length (Should be equal to 140
    	140 bytes for exported key data blob
    */
    BYTE* keyChunk = (BYTE*)malloc(144);
    memcpy(keyChunk, in + 8, 144);
    msgScramble(keyChunk, 144, out->seed_2);
    out->exportedKeyLen = *(DWORD*)keyChunk;
    if(out->exportedKeyLen == 0x8C) {
        memcpy(out->exportedKey, keyChunk + 4, out->exportedKeyLen);
        /*
         * 4 bytes (seed_1) + 4 bytes(seed_2) + 4 bytes (checksum) + 4 bytes (key len) + 140 bytes (exported Key) = 152 bytes
         */
        //THe remain is encrypted Data
        memcpy(out->encryptedData,in + 156,inLen - 156);
        result = TRUE;
    } else {
        printf("Undefined data");
        result = FALSE;
    }
    free(keyChunk);
    return result;
}

int main(int argc, char** argv) {

    return (EXIT_SUCCESS);
}

