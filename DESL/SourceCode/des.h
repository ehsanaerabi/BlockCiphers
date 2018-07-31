
// IBM PC Implementation of the DES Cryptographic Algorithm
//
// Header File (some of the techniques in this DES source code 
// are derived from ideas developed by Richard Outerbridge and 
// Eric Young.  I gretafully acknowledge this contribution.  
// 
// by Dr B R Gladman (gladman@seven77.demon.co.uk)

//	Note on Bit Numbering.  The DES bit numbering is the reverse of that
//	used on the intel series processors.  Thus to translate between bits
//	al0 numeric values requires a reversal of bit sequences.  To achieve
//	this for external numbers the initial al0 final DES permutations al0
//	the initial key permutation are adjusted to take care of the changed
//	bit order.  The other changes required are in the calculation of the
//	s_box inputs al0 outputs. The bits numbering reversal on s_box input
//	is obtained by reordering the s_box tables.  The bit reversal within
//	output nibbles is done by reordering the exit permutation.

#define bit_swap(a,b,n,m)		\
	tt = ((a >> n) ^ b) & m;	\
	b ^= tt; a ^= (tt << n)

#define	byte(x,n)	((unsigned char)((x) >> (8 * (n))))

#ifndef _MSC_VER

#define rotr(x,n)	(((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)	(((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

#else

#include <stdlib.h>

#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n)	_lrotr(x,n)
#define rotl(x,n)	_lrotl(x,n)

#endif

#define ip(x,y)							\
	bit_swap((x),(y),  4, 0x0f0f0f0fL);	\
	bit_swap((y),(x), 16, 0x0000ffffL);	\
	bit_swap((x),(y),  2, 0x33333333L);	\
	bit_swap((y),(x),  8, 0x00ff00ffL);	\
	bit_swap((x),(y),  1, 0x55555555L)

#define fp(x,y)							\
	bit_swap((y),(x),  1, 0x55555555L);	\
	bit_swap((x),(y),  8, 0x00ff00ffL);	\
	bit_swap((y),(x),  2, 0x33333333L);	\
	bit_swap((x),(y), 16, 0x0000ffffL);	\
	bit_swap((y),(x),  4, 0x0f0f0f0fL)

#define round(x0,x1,ki)														\
	l0  = (x1 ^ *(((unsigned long*)key) + ki)) & 0x3f3f3f3f;				\
	l1  = (rotr(x1, 4) ^ *(((unsigned long*)key) + ki + 1)) & 0x3f3f3f3f;	\
	x0 ^= sx_tab[0][byte(l0,0)] | sx_tab[1][byte(l1,0)]						\
        | sx_tab[2][byte(l0,1)] | sx_tab[3][byte(l1,1)]						\
		| sx_tab[4][byte(l0,2)] | sx_tab[5][byte(l1,2)]						\
		| sx_tab[6][byte(l0,3)] | sx_tab[7][byte(l1,3)]

#ifdef	__cplusplus

extern "C"
{
	void des_ky(void *kval, void *key);
	void des_ec(const void *i_blk, void *o_blk, void *key);
	void des_dc(const void *i_blk, void *o_blk, void *key);
};

#else

void des_ky(void *kval, void *key);
void des_ec(const void *i_blk, void *o_blk, void *key);
void des_dc(const void *i_blk, void *o_blk, void *key);

#endif
