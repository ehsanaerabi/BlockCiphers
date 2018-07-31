#include <iostream>
using namespace std;

void encrypt();
void decrypt();
void menu();


void menu()
{
	int choice = 0;
	cout << "##################################################\n"
	 	 << "# THIS PROGRAM WILL ENCRYPT A SENTENCE FOR YOU   #\n"
		 << "# USING THE TINY ENCRYPTION ALGORITHM. PLEASE    #\n"
		 << "# MAKE A SELECTION FROM THE MENU BELOW.          #\n"
		 << "##################################################" << endl;
	cout << endl
		 << "\t\t PLEASE MAKE A SELECTION: \n"
		 << "\t\t\t 1. ENCRYPTION!\n"
		 << "\t\t\t 2. DECRYPTION!\n"
		 << "\t\t\t 3. EXIT!\n"
		 << endl << "\t\t\t\t PLEASE MAKE YOUR SELECTION: ";
	cin >> choice;
	cout << endl;
	if(choice == 1)
		{encrypt();}
	else if(choice == 2)
		{decrypt();}
	else if(choice == 3)
	{}
	else
	{cout << "Not a valid choice! \n\n"; menu();}
}

void encrypt(long* v, long* k)
{
	unsigned long y=v[0],z=v[1], sum=0, /* set up */
		delta=0x9e3779b9, /* a key schedule constant */
		n=32 ;
	while (n-->0) { /* basic cycle start */
		sum += delta ;
		y += ((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1]) ;
		z += ((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3]) ;
	} /* end cycle */
	v[0]=y ; v[1]=z ;
}

void decrypt(long* v,long* k)
{
	unsigned long n=32, sum, y=v[0], z=v[1],
		delta=0x9e3779b9 ;
	sum=delta<<5 ;
	/* start cycle */
	while (n-->0) {
		z-= ((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3]) ;
		y-= ((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1]) ;
		sum-=delta ; }
	/* end cycle */
	v[0]=y ; v[1]=z ;
}

void main()
{
	menu();
}
