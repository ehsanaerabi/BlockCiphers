
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des.h"


static void ComputeRoundKey(bool roundKey[56], bool key[56]);
static void RotateRoundKeyLeft(bool roundKey[56]);
static void RotateRoundKeyRight(bool roundKey[56]);
static void ComputeIP(bool L[32], bool R[32], bool inBlk[64]);
static void ComputeFP(bool outBlk[64], bool L[32], bool R[32]);
static void ComputeF(bool fout[32], bool R[32], bool roundKey[56]);
static void ComputeP(bool output[32], bool input[32]);
static void ComputeS_Lookup(int k, bool output[4], bool input[6]);
static void ComputePC2(bool subkey[48], bool roundKey[56]);
static void ComputeExpansionE(bool expandedBlock[48], bool R[32]);
static void DumpBin(char *str, bool *b, int bits);
static void Exchange_L_and_R(bool L[32], bool R[32]);

static int EnableDumpBin = 0;

static int table_DES_PC1[56] = {
    27, 19, 11, 31, 39, 47, 55,
    26, 18, 10, 30, 38, 46, 54,
    25, 17,  9, 29, 37, 45, 53,
    24, 16,  8, 28, 36, 44, 52,
    23, 15,  7,  3, 35, 43, 51,
    22, 14,  6,  2, 34, 42, 50,
    21, 13,  5,  1, 33, 41, 49,
    20, 12,  4,  0, 32, 40, 48
};
int table_DES_PC2[48] = {
    24, 27, 20,  6, 14, 10,  3, 22,
     0, 17,  7, 12,  8, 23, 11,  5,
    16, 26,  1,  9, 19, 25,  4, 15,
    54, 43, 36, 29, 49, 40, 48, 30,
    52, 44, 37, 33, 46, 35, 50, 41,
    28, 53, 51, 55, 32, 45, 39, 42
};
static int table_DES_E[48] = {
    31,  0,  1,  2,  3,  4,  3,  4,
     5,  6,  7,  8,  7,  8,  9, 10,
    11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24, 23, 24, 25, 26,
    27, 28, 27, 28, 29, 30, 31,  0
};

static int table_DES_P[32] = {
    11, 17,  5, 27, 25, 10, 20,  0,
    13, 21,  3, 28, 29,  7, 18, 24,
    31, 22, 12,  6, 26,  2, 16,  8,
    14, 30,  4, 19,  1,  9, 15, 23
};
static int table_DES_S[64] = {
	{14, 5, 7, 2, 11, 8, 1, 15, 0, 10, 9, 4, 6, 13, 12, 3,
	5, 0, 8, 15, 14, 3, 2, 12, 11, 7, 6, 9, 13, 4, 1, 10,
	4, 9, 2, 14, 8, 7, 13, 0, 10, 12, 15, 1, 5, 11, 3, 6,
	9, 6, 15, 5, 3, 8, 4, 11, 7, 1, 12, 2, 0, 14, 10, 13};

void EncryptDES(bool key[56], bool outBlk[64], bool inBlk[64], int verbose) {
  int i,round;
  bool R[32], L[32], fout[32];
  bool roundKey[56];

  EnableDumpBin = verbose;
  ComputeRoundKey(roundKey, key);
  ComputeIP(L,R,inBlk);
  for (round = 0; round < 16; round++) {
    RotateRoundKeyLeft(roundKey);
    if (round != 0 && round != 1 && round != 8 && round != 15)
      RotateRoundKeyLeft(roundKey);
    ComputeF(fout, R, roundKey);
    for (i = 0; i < 32; i++)
      L[i] ^= fout[i];
    Exchange_L_and_R(L,R);
  }
  Exchange_L_and_R(L,R);
  ComputeFP(outBlk,L,R);
}
static void ComputeRoundKey(bool roundKey[56], bool key[56]) {
  int i;

  for (i = 0; i < 56; i++)
    roundKey[table_DES_PC1[i]] = key[i];
}
static void RotateRoundKeyLeft(bool roundKey[56]) {
  bool temp1, temp2;
  int i;

  temp1 = roundKey[27];
  temp2 = roundKey[55];
  for (i = 27; i >= 1; i--) {
    roundKey[i] = roundKey[i-1];
    roundKey[i+28] = roundKey[i+28-1];
  }
  roundKey[ 0] = temp1;
  roundKey[28] = temp2;
}
static void RotateRoundKeyRight(bool roundKey[56]) {
  bool temp1, temp2;
  int i;

  temp1 = roundKey[0];
  temp2 = roundKey[28];
  for (i = 0; i < 27; i++) {
    roundKey[i] = roundKey[i+1];
    roundKey[i+28] = roundKey[i+28+1];
  }
  roundKey[27] = temp1;
  roundKey[55] = temp2;
}
static void ComputeIP(bool L[32], bool R[32], bool inBlk[64]) {
  bool output[64];
  int i;
  for (i = 63; i >= 0; i--)
	   output[i] = inBlk[i];
  for (i = 63; i >= 0; i--) {
    if (i >= 32)
      L[i-32] = output[i];
    else
      R[i] = output[i];
  }
}

static void ComputeFP(bool outBlk[64], bool L[32], bool R[32]) {
  bool input[64];
  int i;
  for (i = 63; i >= 0; i--)
    input[i] = (i >= 32) ? L[i - 32] : R[i];

  for (i = 63; i >= 0; i--)
	  outBlk[i] = input[i];
}
static void ComputeF(bool fout[32], bool R[32], bool roundKey[56]) {
  bool expandedBlock[48], subkey[48], sout[32];
  int i,k;
  ComputeExpansionE(expandedBlock, R);
  DumpBin("expanded E", expandedBlock, 48);
  ComputePC2(subkey, roundKey);
  DumpBin("subkey", subkey, 48);
  for (i = 0; i < 48; i++)
    expandedBlock[i] ^= subkey[i];
  for (k = 0; k < 8; k++)
    ComputeS_Lookup(k, sout+4*k, expandedBlock+6*k);
  ComputeP(fout, sout);
}
static void ComputeP(bool output[32], bool input[32]) {
  int i;
  for (i = 0; i < 32; i++)
    output[table_DES_P[i]] = input[i];
}

static void ComputeS_Lookup(int k, bool output[4], bool input[6]) {
  int inputValue, outputValue;
  inputValue = input[0] + 2*input[1] + 4*input[2] + 8*input[3] +
          16*input[4] + 32*input[5];
  outputValue = table_DES_S[inputValue];
  output[0] = (outputValue & 1) ? 1 : 0;
  output[1] = (outputValue & 2) ? 1 : 0;
  output[2] = (outputValue & 4) ? 1 : 0;
  output[3] = (outputValue & 8) ? 1 : 0;
}
static void ComputePC2(bool subkey[48], bool roundKey[56]) {
  int i;
  for (i = 0; i < 48; i++)
    subkey[i] = roundKey[table_DES_PC2[i]];
}
static void ComputeExpansionE(bool expandedBlock[48], bool R[32]) {
  int i;
  for (i = 0; i < 48; i++)
    expandedBlock[i] = R[table_DES_E[i]];
}
static void Exchange_L_and_R(bool L[32], bool R[32]) {
  int i;
  for (i = 0; i < 32; i++)
    L[i] ^= R[i] ^= L[i] ^= R[i];                 /* exchanges L[i] and R[i] */
}
static void DumpBin(char *str, bool *b, int bits) {
  int i;

  if ((bits % 4)!=0 || bits>48) {
    printf("Bad call to DumpBin (bits > 48 or bit len not a multiple of 4\n");
    exit(1);
  }
}
void DES(unsigned char pt[8],unsigned char k[7],unsigned char out[8]){
	bool key[56],outBlk[64], inBlk[64];
	int i,j;
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			inBlk[8*i+j]=(pt[i]>>(7-j))&0x1;

	for(i=0;i<7;i++)
		for(j=0;j<8;j++)
			key[8*i+j]=(k[i]>>(7-j))&0x1;

	EncryptDES(key,outBlk,inBlk,0);

	for(i=0;i<8;i++){
		out[i]=0x0;
		for(j=0;j<7;j++){
			out[i]^=outBlk[63-(8*i+j)];
			out[i]<<=1;
		}
		out[i]^=outBlk[63-(8*i+j)]&0x1;
	}
}

int main()
{
	//clock_t end,start=clock();
	unsigned char pt[8]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//{0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	unsigned char ct[8],k[7]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//{0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	//for(int i=0;i<100000;i++)
	DES(pt,k,ct);
	//for(int i=0;i<8;i++)
	//	printf("%.2x",ct[i]);
	//printf("%.3f\n",(clock()-start)/1000.0);
	return 0;
}
