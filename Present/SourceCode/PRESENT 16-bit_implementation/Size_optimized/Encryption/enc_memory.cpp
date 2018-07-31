//size optimized 16 bit

// Include-Dateien
#include"Encryption_4bit.inc"

void main(void)
{
// Input values
	unsigned long long keyhigh=0x0;
	unsigned long long keylow=0x0;
	volatile unsigned long long state=0x0;	
// Counter
	short i=1;
// Variables Key Scheduling
	unsigned long long subkey = keyhigh;
	unsigned long long temp;
// Variables sBox
	unsigned long long temp_0;
	unsigned long long temp_1;
	unsigned long long temp_2;
	unsigned long long temp_3;
	unsigned long long temp_4;
	unsigned long long temp_5;
	unsigned long long temp_6;
	unsigned long long temp_7;
	unsigned long long temp_8;
	unsigned long long temp_9;
	unsigned long long temp_10;
	unsigned long long temp_11;
	unsigned long long temp_12;
	unsigned long long temp_13;
	unsigned long long temp_14;
	unsigned long long temp_15;
// Variables pLayer
	short j=1;
	unsigned long long temp_pLayer;
	int position;
//	****************** Key Scheduling **********************
//	****************** Key Scheduling End ******************
//	****************** Encryption **************************
	for(i=0;i<31;i++)
	{
//	****************** addRoundkey *************************
		state ^= subkey;
//	****************** addRoundkey End *********************
//	******************* sBox *******************************
		temp_1 = state;
		temp_2 = state;
		temp_3 = state;
		temp_4 = state;
		temp_5 = state;
		temp_6 = state;
		temp_7 = state;
		temp_8 = state;
		temp_9 = state;
		temp_10 = state;
		temp_11 = state;
		temp_12 = state;
		temp_13 = state;
		temp_14 = state;
		temp_15 = state;
		temp_0 = sBox4[state&0xF];								//put new value to lowest nibble
	
		temp_1 = (temp_1 >> 4);									//shift 4 bit
		temp_1 = (long long)(sBox4[temp_1&0xF]<<4);				//put new value to lowest nibble
		
		temp_2 = (temp_2 >> 8);									//shift 8 bit
		temp_2 = (long long)(sBox4[temp_2&0xF]<<8);				//put new value to lowest nibble
	
		temp_3 = (temp_3 >> 12);								//shift 12 bit
		temp_3 = (long long)(sBox4[temp_3&0xF]<<12);			//put new value to lowest nibble

		temp_4 = (temp_4 >> 16);								//shift 16 bit
		temp_4 = (long long)(sBox4[temp_4&0xF]<<16);			//put new value to lowest nibble
	
		temp_5 = (temp_5 >> 20);								//shift 20 bit
		temp_5 = (long long)(sBox4[temp_5&0xF]<<20);			//put new value to lowest nibble
		
		temp_6 = (temp_6 >> 24);								//shift 24 bit
		temp_6 = (long long)(sBox4[temp_6&0xF]<<24);			//put new value to lowest nibble

		temp_7 = (temp_7 >> 28);								//shift 28 bit
		temp_7 = (long long)(sBox4[temp_7&0xF]<<28);			//put new value to lowest nibble
	
		temp_8 = (temp_8 >> 32);								//shift 32 bit
		temp_8 = (long long)(sBox4[temp_8&0xF]<<32);			//put new value to lowest nibble
	
		temp_9 = (temp_9 >> 36);								//shift 36 bit
		temp_9 = (long long)(sBox4[temp_9&0xF]<<36);			//put new value to lowest nibble
		
		temp_10 = (temp_10 >> 40);								//shift 40 bit
		temp_10 = (long long)(sBox4[temp_10&0xF]<<40);			//put new value to lowest nibble
	
		temp_11 = (temp_11 >> 44);								//shift 44 bit
		temp_11 = (long long)(sBox4[temp_11&0xF]<<44);			//put new value to lowest nibble

		temp_12 = (temp_12 >> 48);								//shift 48 bit
		temp_12 = (long long)(sBox4[temp_12&0xF]<<48);			//put new value to lowest nibble
	
		temp_13 = (temp_13 >> 52);								//shift 52 bit
		temp_13 = (long long)(sBox4[temp_13&0xF]<<52);			//put new value to lowest nibble
		
		temp_14 = (temp_14 >> 56);								//shift 56 bit
		temp_14 = (long long)(sBox4[temp_14&0xF]<<56);			//put new value to lowest nibble

		temp_15 = (temp_15 >> 60);								//shift 60 bit
		temp_15 = (long long)(sBox4[temp_15&0xF]<<60);			//put new value to lowest nibble

		state=temp_0|temp_1|temp_2|temp_3|temp_4|temp_5|temp_6|temp_7|temp_8|temp_9|temp_10|temp_11|temp_12|temp_13|temp_14|temp_15;	// XOR of the results
//	******************* sBox End ***************************
//	******************* pLayer *****************************
		temp_pLayer = 0;
		for(j=0;j<64;j++)
		{
			position = (16*j)%63;
			if(j==63)
				position = 63;
			temp_pLayer = temp_pLayer | (state & 0x01) << position;
			state = state >> 1;
		}
		state = temp_pLayer;
//	******************* pLayer End *************************
//	****************** pLayer End **************************
		temp = keyhigh;
		keyhigh = (keyhigh &0x7) << 61;
		keyhigh = keyhigh | ((keylow & 0xFFFF)<<45);
		keyhigh |= (temp>>19);
		keylow = (temp>>3)&0xFFFF;

		temp = keyhigh>>60;
		keyhigh &=	0x0FFFFFFFFFFFFFFF;
		temp = sBox4[temp];
		keyhigh |= temp<<60;

		keylow ^= ( ( (i+1) & 0x01 ) << 15 );  
		keyhigh ^= ( (i+1) >> 1 );
		subkey = keyhigh;
	}
//	****************** addRoundkey *************************
 	state ^= subkey;
//	****************** addRoundkey End *********************
}
