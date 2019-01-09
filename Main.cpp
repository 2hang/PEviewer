#include "PEheaders.h"
#include <stdio.h>
#include <stdlib.h>

#define PATH "C:/Users/HY/Desktop/01_����_������/02_Hello_World!_������/bin/HelloWorld.exe"

int main() {
	FILE *in;
	BYTE ch;
	WORD mz;
	int count = 0;

	//�б� �������� ����
	if ((in = fopen(PATH, "rb")) == NULL) {
		fputs("FOPEN ERROR\n", stderr);
		exit(999);
	}

	//little endian -> big endian ���� ����
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
		
		// ����Ʈ�ϱ�
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