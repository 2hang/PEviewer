#include "PEheaders.h"
#include <stdio.h>
#include <stdlib.h>

#define PATH "C:/Users/HY/Desktop/01_기초_리버싱/02_Hello_World!_리버싱/bin/HelloWorld.exe"

int main() {
	FILE *in;
	BYTE ch;
	WORD mz;
	int count = 0;

	//읽기 전용으로 열기
	if ((in = fopen(PATH, "rb")) == NULL) {
		fputs("FOPEN ERROR\n", stderr);
		exit(999);
	}

	//little endian -> big endian 으로 저장
	BYTE *ptr = (BYTE *)&mz;
	for (int i = 0; i < 2; i++) {
		ch = fgetc(in);
		*ptr = ch;
		ptr++;
		//printf("%c", ch);
	}
	printf("%X", mz);

	/*
	while ((ch = fgetc(in)) != EOF) {
		
		// 프린트하기
		printf("%02X ", ch);
		if (count == 14) {
			printf("\n");
		}
		count = (count + 1) % 15;
		
	}
	*/
	fclose(in);
	return 0;
}