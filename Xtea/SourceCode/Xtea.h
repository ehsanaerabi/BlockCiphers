/*
    2 * XTEA
    3 * (C) 1999-2007 Jack Lloyd
    4 *
    5 * Botan is released under the Simplified BSD License (see license.txt)
    6 */
    7 
    8 #ifndef BOTAN_XTEA_H__
    9 #define BOTAN_XTEA_H__
   10 
   11 #include <botan/block_cipher.h>
   12 
   13 namespace Botan {
   14 
   15 /**
   16 * XTEA
   17 */
   18 class BOTAN_DLL XTEA : public Block_Cipher_Fixed_Params<8, 16>
   19    {
   20    public:
   21       void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
   22       void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
   23 
   24       void clear() override;
   25       std::string name() const override { return "XTEA"; }
   26       BlockCipher* clone() const override { return new XTEA; }
   27    protected:
   28       /**
   29       * @return const reference to the key schedule
   30       */
   31       const secure_vector<uint32_t>& get_EK() const { return m_EK; }
   32 
   33    private:
   34       void key_schedule(const uint8_t[], size_t) override;
   35       secure_vector<uint32_t> m_EK;
   36    };
   37 
   38 }
   39 
   40 #endif