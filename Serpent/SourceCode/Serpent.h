/*
    2 * Serpent
    3 * (C) 1999-2007 Jack Lloyd
    4 *
    5 * Botan is released under the Simplified BSD License (see license.txt)
    6 */
    7 
    8 #ifndef BOTAN_SERPENT_H__
    9 #define BOTAN_SERPENT_H__
   10 
   11 #include <botan/block_cipher.h>
   12 
   13 namespace Botan {
   14 
   15 /**
   16 * Serpent is the most conservative of the AES finalists
   17 * http://www.cl.cam.ac.uk/~rja14/serpent.html
   18 */
   19 class BOTAN_DLL Serpent final : public Block_Cipher_Fixed_Params<16, 16, 32, 8>
   20    {
   21    public:
   22       void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
   23       void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
   24 
   25       void clear() override;
   26       std::string provider() const override;
   27       std::string name() const override { return "Serpent"; }
   28       BlockCipher* clone() const override { return new Serpent; }
   29 
   30       size_t parallelism() const override { return 4; }
   31 
   32    protected:
   33 #if defined(BOTAN_HAS_SERPENT_SIMD)
   34       /**
   35       * Encrypt 4 blocks in parallel using SSE2 or AltiVec
   36       */
   37       void simd_encrypt_4(const uint8_t in[64], uint8_t out[64]) const;
   38 
   39       /**
   40       * Decrypt 4 blocks in parallel using SSE2 or AltiVec
   41       */
   42       void simd_decrypt_4(const uint8_t in[64], uint8_t out[64]) const;
   43 #endif
   44 
   45       /**
   46       * For use by subclasses using SIMD, asm, etc
   47       * @return const reference to the key schedule
   48       */
   49       const secure_vector<uint32_t>& get_round_keys() const
   50          { return m_round_key; }
   51 
   52       /**
   53       * For use by subclasses that implement the key schedule
   54       * @param ks is the new key schedule value to set
   55       */
   56       void set_round_keys(const uint32_t ks[132])
   57          {
   58          m_round_key.assign(&ks[0], &ks[132]);
   59          }
   60 
   61    private:
   62       void key_schedule(const uint8_t key[], size_t length) override;
   63       secure_vector<uint32_t> m_round_key;
   64    };
   65 
   66 }
   67 
   68 #endif