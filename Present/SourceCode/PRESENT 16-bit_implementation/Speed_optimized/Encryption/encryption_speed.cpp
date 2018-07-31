/******************************************************************************
Written and Copyright (C) by Dirk Klose
and the EmSec Embedded Security group of Ruhr-Universitaet Bochum. 
All rights reserved.

Contact lightweight@crypto.rub.de for comments & questions.
This program is free software; You may use it or parts of it or
modifiy it under the following terms:

(1) Usage and/or redistribution and/or modification of the software 
or parts of the software is permitted for non-commercial use only.

(2a) If this software or parts are used as part of a new software, you
must license the entire work, as a whole, under this License to anyone
who comes into possession of a copy. This License will therefore
apply, to the whole of the work, and all its parts, regardless of how
they are packaged.

(2b) You may expand this license by your own license. In this case this
license still applies to the software as mentioned in (2a) and must
not be changed. The expansion must be clearly recognizable as such. In
any case of collision between the license and the expansion the
license is superior to the expansion.

(3) If this software or parts are used as part of a new software, you
must provide equivalent access to the source code of the entire work,
as a whole, to anyone who comes into possession of a copy, in the same
way through the same place at no further charge, as for the binary
version.

(4) This program is distributed in the hope that it will be useful,
but   WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
(5) These notices must be retained in any copies of any part of this
documentation and/or software.

(6) If this software is used credit must be given to the
"Embedded Security Group of Ruhr-Universitaet Bochum, Germany" as
the authors of the parts of the software used. This can be in the form
of a textual message at program startup or  at *beginning* of the
documentation (online or textual) provided with the package.

If you are interested in a commercial use 
please contact '''lightweigth@crypto.rub.de'''
******************************************************************************/

// Include-Dateien
#include"Encryption_8bit.inc"				// include Datei mit 8Bit s/p-Boxen

void main(void)
{
// Variablendeklaration
// Eingangswerte
	unsigned long long keyhigh=0x0;
	unsigned long long keylow=0x0;
	volatile unsigned long long state=0x0;	
// Zählvariablen
	int i=1;
// Variablen Key Scheduling
	unsigned long long subkey[32];
	unsigned long long temp;
// Variablen pLayer
	unsigned long long temp_0;
	unsigned long long temp_1;
	unsigned long long temp_2;
	unsigned long long temp_3;
	unsigned long long temp_4;
	unsigned long long temp_5;
	unsigned long long temp_6;
	unsigned long long temp_7;

//	****************** Key Scheduling **********************
	for(i=0;i<32;i++)
	{
		subkey[i] = keyhigh;
		temp = keyhigh;
		keyhigh = (keyhigh &0x7) << 61;
		keyhigh = keyhigh | ((keylow & 0xFFFF)<<45);
		keyhigh |= (temp>>19);
		keylow = (temp>>3)&0xFFFF;

		temp = keyhigh>>60;
		keyhigh &=	0x0FFFFFFFFFFFFFFF;
		temp = sBox4[temp];
		keyhigh |= temp;

		keylow ^= ( ( (i+1) & 0x01 ) << 15 );  
		keyhigh ^= ( (i+1) >> 1 );
	}
//	****************** Key Scheduling Ende *****************
//	****************** Encryption **************************
	for(i=0;i<31;i++)
	{
//	****************** addRoundkey *************************
		state ^= subkey[i];
//	****************** addRoundkey Ende ********************
//	******************* 8Bit pLayer + sBox *****************
		temp_1 = state;
		temp_2 = state;
		temp_3 = state;
		temp_4 = state;
		temp_5 = state;
		temp_6 = state;
		temp_7 = state;
		temp_0 = pBox8_0[state&0xFF];						//put new value to lowest 2 byte (pLayer)
	
		temp_1 = (temp_1 >> 8);								//shift 2 byte
		temp_1 = pBox8_1[temp_1&0xFF];						//put new value to lowest 2 byte (pLayer)
		
		temp_2 = (temp_2 >> 16);								//shift 4 byte
		temp_2 = pBox8_2[temp_2&0xFF];						//put new value to lowest 2 byte (pLayer)
	
		temp_3 = (temp_3 >> 24);								//shift 6 byte
		temp_3 = pBox8_3[temp_3&0xFF];						//put new value to lowest 2 byte (pLayer)

		temp_4 = (temp_4 >> 32);								//shift 6 byte
		temp_4 = pBox8_4[temp_4&0xFF];						//put new value to lowest 2 byte (pLayer)
	
		temp_5 = (temp_5 >> 40);								//shift 2 byte
		temp_5 = pBox8_5[temp_5&0xFF];						//put new value to lowest 2 byte (pLayer)
		
		temp_6 = (temp_6 >> 48);								//shift 4 byte
		temp_6 = pBox8_6[temp_6&0xFF];						//put new value to lowest 2 byte (pLayer)

		temp_7 = (temp_7 >> 56);								//shift 6 byte
		temp_7 = pBox8_7[temp_7&0xFF];						//put new value to lowest 2 byte (pLayer)
	
		state=temp_0|temp_1|temp_2|temp_3|temp_4|temp_5|temp_6|temp_7;						// XOR of the results
//	****************** pLayer Ende *************************
	}	// for(i=1;i<32;i++)
//	****************** addRoundkey *************************
 	state ^= subkey[31];
//	****************** addRoundkey Ende ********************
// 	printf("\nstate (%d): %llu\n",i,state);
// 	printf("%llu",state);
// 	return(0);
}
