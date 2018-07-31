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

// Includedateien
#include"decryption_8bit.inc"
#include"encryption_8bit.inc"
int main(void)
{
// Input values
	unsigned long long keyhigh=0x0;
	unsigned long long keylow=0x0;
	volatile unsigned long long state=0x0;	
// Counter
	int i;
	volatile int position;
	volatile unsigned long long temp_pLayer;
// Variables Key Scheduling
	unsigned long long subkey[32];
	unsigned long long temp;
// Variables pLayer
	unsigned long long temp_0;
	unsigned long long temp_1;
	unsigned long long temp_2;
	unsigned long long temp_3;
	unsigned long long temp_4;
	unsigned long long temp_5;
	unsigned long long temp_6;
	unsigned long long temp_7;
	volatile int eingabe;
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
//	****************** Key Scheduling End ******************
	if(eingabe == 0)
	{
	for(i=0;i<31;i++)
	{
//	****************** addRoundkey *************************
		state ^= subkey[i];
//	****************** addRoundkey End *********************
//	******************* 8Bit pLayer + sBox *****************
		temp_1 = state;
		temp_2 = state;
		temp_3 = state;
		temp_4 = state;
		temp_5 = state;
		temp_6 = state;
		temp_7 = state;
		temp_0 = pBox8_0[state&0xFF];		//put new value to lowest byte
	
		temp_1 = (temp_1 >> 8);				//shift 1 byte
		temp_1 = pBox8_1[temp_1&0xFF];		//put new value to lowest byte
		
		temp_2 = (temp_2 >> 16);			//shift 2 byte
		temp_2 = pBox8_2[temp_2&0xFF];		//put new value to lowest byte
	
		temp_3 = (temp_3 >> 24);			//shift 3 byte
		temp_3 = pBox8_3[temp_3&0xFF];		//put new value to lowest byte

		temp_4 = (temp_4 >> 32);			//shift 4 byte
		temp_4 = pBox8_4[temp_4&0xFF];		//put new value to lowest byte
	
		temp_5 = (temp_5 >> 40);			//shift 5 byte
		temp_5 = pBox8_5[temp_5&0xFF];		//put new value to lowest byte
		
		temp_6 = (temp_6 >> 48);			//shift 6 byte
		temp_6 = pBox8_6[temp_6&0xFF];		//put new value to lowest byte

		temp_7 = (temp_7 >> 56);			//shift 7 byte
		temp_7 = pBox8_7[temp_7&0xFF];		//put new value to lowest byte
	
		state=temp_0|temp_1|temp_2|temp_3|temp_4|temp_5|temp_6|temp_7;	// XOR of the results
//	****************** pLayer End **************************
	}	// for(i=1;i<32;i++)
//	****************** addRoundkey *************************
 	state ^= subkey[31];
//	****************** addRoundkey End *********************
	}
//	****************** Decryption **************************
//	****************** addRoundkey (Round 31) **************
	else if(eingabe == 1)
	{
	state ^= subkey[31];
//	****************** Ende addRoundkey (Round 31) *********
	for(i=30;i>=0;i--)
	{
//	****************** invpLayer ***************************
//			8Bit pLayer

		temp_0=state;
		temp_1=state;
		temp_2=state;
		temp_3=state;
		temp_4=state;
		temp_5=state;
		temp_6=state;
		temp_7=state;
		temp_0 = invpBox8_0[temp_0&0xFF];	//put new value to lowest byte

		temp_1 = (temp_1 >> 8);				//shift 1 byte
		temp_1 = invpBox8_1[temp_1&0xFF];	//put new value to lowest byte
				
		temp_2 = (temp_2 >> 16);			//shift 2 byte
		temp_2 = invpBox8_2[temp_2&0xFF];	//put new value to lowest byte
			
		temp_3 = (temp_3 >> 24);			//shift 3 byte
		temp_3 = invpBox8_3[temp_3&0xFF];	//put new value to lowest byte
			
		temp_4 = (temp_4 >> 32);			//shift 4 byte
		temp_4 = invpBox8_4[temp_4&0xFF];	//put new value to lowest byte

		temp_5 = (temp_5 >> 40);			//shift 5 byte
		temp_5 = invpBox8_5[temp_5&0xFF];	//put new value to lowest byte

		temp_6 = (temp_6 >> 48);			//shift 6 byte
		temp_6 = invpBox8_6[temp_6&0xFF];	//put new value to lowest byte
			
		temp_7 = (temp_7 >> 56);			//shift 7 byte
		temp_7 = invpBox8_7[temp_7&0xFF];	//put new value to lowest byte

		state=temp_0|temp_1|temp_2|temp_3|temp_4|temp_5|temp_6|temp_7;	// XOR of the results
//	****************** Ende invpLayer **********************
//	****************** invsBoxLayer ************************
		temp_1=state;
		temp_2=state;
		temp_3=state;
		temp_4=state;
		temp_5=state;
		temp_6=state;
		temp_7=state;
		temp_0 = invsBox8[state&0xFF];

		temp_1 = temp_1 >> 8;				//shift 1 byte
		temp_1 = invsBox8[temp_1&0xFF]<<8;	//put new value to lowest byte

		temp_2 = temp_2 >> 16;				//shift 2 byte
		temp_2 = invsBox8[temp_2&0xFF]<<16;	//put new value to lowest byte

		temp_3 = temp_3 >> 24;				//shift 3 byte
		temp_3 = invsBox8[temp_3&0xFF]<<24;	//put new value to lowest byte

		temp_4 = temp_4 >> 32;				//shift 4 byte
		temp_4 = invsBox8[temp_4&0xFF]<<32;	//put new value to lowest byte

		temp_5 = temp_5 >> 40;				//shift 5 byte
		temp_5 = invsBox8[temp_5&0xFF]<<40;	//put new value to lowest byte

		temp_6 = temp_6 >> 48;				//shift 6 byte
		temp_6 = invsBox8[temp_6&0xFF]<<48;	//put new value to lowest byte

		temp_7 = temp_7 >> 56;				//shift 7 byte
		temp_7 = invsBox8[temp_7&0xFF]<<56;	//put new value to lowest byte

		state = temp_0|temp_1|temp_2|temp_3|temp_4|temp_5|temp_6|temp_7;	// XOR of the results
//	****************** invsBoxLayer End ********************
//	****************** addRoundkey *************************
		state ^= subkey[i];
	}
//	****************** addRoundkey End *********************
	}
}
