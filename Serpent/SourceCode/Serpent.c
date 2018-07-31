/*
    2 * Serpent
    3 * (C) 1999-2007 Jack Lloyd
    4 *
    5 * Botan is released under the Simplified BSD License (see license.txt)
    6 */
    7 
    8 #include <botan/serpent.h>
    9 #include <botan/loadstor.h>
   10 #include <botan/internal/serpent_sbox.h>
   11 
   12 #if defined(BOTAN_HAS_SERPENT_SIMD)
   13   #include <botan/cpuid.h>
   14 #endif
   15 
   16 namespace Botan {
   17 
   18 namespace {
   19 
   20 /*
   21 * Serpent's Linear Transform
   22 */
   23 inline void transform(uint32_t& B0, uint32_t& B1, uint32_t& B2, uint32_t& B3)
   24    {
   25    B0  = rotate_left(B0, 13);   B2  = rotate_left(B2, 3);
   26    B1 ^= B0 ^ B2;               B3 ^= B2 ^ (B0 << 3);
   27    B1  = rotate_left(B1, 1);    B3  = rotate_left(B3, 7);
   28    B0 ^= B1 ^ B3;               B2 ^= B3 ^ (B1 << 7);
   29    B0  = rotate_left(B0, 5);    B2  = rotate_left(B2, 22);
   30    }
   31 
   32 /*
   33 * Serpent's Inverse Linear Transform
   34 */
   35 inline void i_transform(uint32_t& B0, uint32_t& B1, uint32_t& B2, uint32_t& B3)
   36    {
   37    B2  = rotate_right(B2, 22);  B0  = rotate_right(B0, 5);
   38    B2 ^= B3 ^ (B1 << 7);        B0 ^= B1 ^ B3;
   39    B3  = rotate_right(B3, 7);   B1  = rotate_right(B1, 1);
   40    B3 ^= B2 ^ (B0 << 3);        B1 ^= B0 ^ B2;
   41    B2  = rotate_right(B2, 3);   B0  = rotate_right(B0, 13);
   42    }
   43 
   44 }
   45 
   46 /*
   47 * XOR a key block with a data block
   48 */
   49 #define key_xor(round, B0, B1, B2, B3) \
   50    B0 ^= m_round_key[4*round  ]; \
   51    B1 ^= m_round_key[4*round+1]; \
   52    B2 ^= m_round_key[4*round+2]; \
   53    B3 ^= m_round_key[4*round+3];
   54 
   55 /*
   56 * Serpent Encryption
   57 */
   58 void Serpent::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   59    {
   60 #if defined(BOTAN_HAS_SERPENT_SIMD)
   61    if(CPUID::has_simd_32())
   62       {
   63       while(blocks >= 4)
   64          {
   65          simd_encrypt_4(in, out);
   66          in += 4 * BLOCK_SIZE;
   67          out += 4 * BLOCK_SIZE;
   68          blocks -= 4;
   69          }
   70       }
   71 #endif
   72 
   73    BOTAN_PARALLEL_SIMD_FOR(size_t i = 0; i < blocks; ++i)
   74       {
   75       uint32_t B0, B1, B2, B3;
   76       load_le(in + 16*i, B0, B1, B2, B3);
   77 
   78       key_xor( 0,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   79       key_xor( 1,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   80       key_xor( 2,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   81       key_xor( 3,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   82       key_xor( 4,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   83       key_xor( 5,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   84       key_xor( 6,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   85       key_xor( 7,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   86       key_xor( 8,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   87       key_xor( 9,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   88       key_xor(10,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   89       key_xor(11,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   90       key_xor(12,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   91       key_xor(13,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   92       key_xor(14,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   93       key_xor(15,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   94       key_xor(16,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   95       key_xor(17,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   96       key_xor(18,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   97       key_xor(19,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   98       key_xor(20,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   99       key_xor(21,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  100       key_xor(22,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  101       key_xor(23,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  102       key_xor(24,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  103       key_xor(25,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  104       key_xor(26,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  105       key_xor(27,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  106       key_xor(28,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  107       key_xor(29,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  108       key_xor(30,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
  109       key_xor(31,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);
  110 
  111       store_le(out + 16*i, B0, B1, B2, B3);
  112       }
  113    }
  114 
  115 /*
  116 * Serpent Decryption
  117 */
  118 void Serpent::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
  119    {
  120 #if defined(BOTAN_HAS_SERPENT_SIMD)
  121    if(CPUID::has_simd_32())
  122       {
  123       while(blocks >= 4)
  124          {
  125          simd_decrypt_4(in, out);
  126          in += 4 * BLOCK_SIZE;
  127          out += 4 * BLOCK_SIZE;
  128          blocks -= 4;
  129          }
  130       }
  131 #endif
  132 
  133    BOTAN_PARALLEL_SIMD_FOR(size_t i = 0; i < blocks; ++i)
  134       {
  135       uint32_t B0, B1, B2, B3;
  136       load_le(in + 16*i, B0, B1, B2, B3);
  137 
  138       key_xor(32,B0,B1,B2,B3);  SBoxD8(B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
  139       i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
  140       i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
  141       i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
  142       i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
  143       i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
  144       i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
  145       i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);
  146       i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
  147       i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
  148       i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
  149       i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
  150       i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
  151       i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
  152       i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
  153       i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);
  154       i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
  155       i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
  156       i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
  157       i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
  158       i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
  159       i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
  160       i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
  161       i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);
  162       i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
  163       i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
  164       i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
  165       i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
  166       i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
  167       i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
  168       i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
  169       i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);
  170 
  171       store_le(out + 16*i, B0, B1, B2, B3);
  172       }
  173    }
  174 
  175 #undef key_xor
  176 #undef transform
  177 #undef i_transform
  178 
  179 /*
  180 * Serpent Key Schedule
  181 */
  182 void Serpent::key_schedule(const uint8_t key[], size_t length)
  183    {
  184    const uint32_t PHI = 0x9E3779B9;
  185 
  186    secure_vector<uint32_t> W(140);
  187    for(size_t i = 0; i != length / 4; ++i)
  188       W[i] = load_le<uint32_t>(key, i);
  189 
  190    W[length / 4] |= uint32_t(1) << ((length%4)*8);
  191 
  192    for(size_t i = 8; i != 140; ++i)
  193       {
  194       uint32_t wi = W[i-8] ^ W[i-5] ^ W[i-3] ^ W[i-1] ^ PHI ^ uint32_t(i-8);
  195       W[i] = rotate_left(wi, 11);
  196       }
  197 
  198    SBoxE1(W[ 20],W[ 21],W[ 22],W[ 23]);
  199    SBoxE1(W[ 52],W[ 53],W[ 54],W[ 55]);
  200    SBoxE1(W[ 84],W[ 85],W[ 86],W[ 87]);
  201    SBoxE1(W[116],W[117],W[118],W[119]);
  202 
  203    SBoxE2(W[ 16],W[ 17],W[ 18],W[ 19]);
  204    SBoxE2(W[ 48],W[ 49],W[ 50],W[ 51]);
  205    SBoxE2(W[ 80],W[ 81],W[ 82],W[ 83]);
  206    SBoxE2(W[112],W[113],W[114],W[115]);
  207 
  208    SBoxE3(W[ 12],W[ 13],W[ 14],W[ 15]);
  209    SBoxE3(W[ 44],W[ 45],W[ 46],W[ 47]);
  210    SBoxE3(W[ 76],W[ 77],W[ 78],W[ 79]);
  211    SBoxE3(W[108],W[109],W[110],W[111]);
  212 
  213    SBoxE4(W[  8],W[  9],W[ 10],W[ 11]);
  214    SBoxE4(W[ 40],W[ 41],W[ 42],W[ 43]);
  215    SBoxE4(W[ 72],W[ 73],W[ 74],W[ 75]);
  216    SBoxE4(W[104],W[105],W[106],W[107]);
  217    SBoxE4(W[136],W[137],W[138],W[139]);
  218 
  219    SBoxE5(W[ 36],W[ 37],W[ 38],W[ 39]);
  220    SBoxE5(W[ 68],W[ 69],W[ 70],W[ 71]);
  221    SBoxE5(W[100],W[101],W[102],W[103]);
  222    SBoxE5(W[132],W[133],W[134],W[135]);
  223 
  224    SBoxE6(W[ 32],W[ 33],W[ 34],W[ 35]);
  225    SBoxE6(W[ 64],W[ 65],W[ 66],W[ 67]);
  226    SBoxE6(W[ 96],W[ 97],W[ 98],W[ 99]);
  227    SBoxE6(W[128],W[129],W[130],W[131]);
  228 
  229    SBoxE7(W[ 28],W[ 29],W[ 30],W[ 31]);
  230    SBoxE7(W[ 60],W[ 61],W[ 62],W[ 63]);
  231    SBoxE7(W[ 92],W[ 93],W[ 94],W[ 95]);
  232    SBoxE7(W[124],W[125],W[126],W[127]);
  233 
  234    SBoxE8(W[ 24],W[ 25],W[ 26],W[ 27]);
  235    SBoxE8(W[ 56],W[ 57],W[ 58],W[ 59]);
  236    SBoxE8(W[ 88],W[ 89],W[ 90],W[ 91]);
  237    SBoxE8(W[120],W[121],W[122],W[123]);
  238 
  239    m_round_key.assign(W.begin() + 8, W.end());
  240    }
  241 
  242 void Serpent::clear()
  243    {
  244    zap(m_round_key);
  245    }
  246 
  247 std::string Serpent::provider() const
  248    {
  249 #if defined(BOTAN_HAS_SERPENT_SIMD)
  250    if(CPUID::has_simd_32())
  251       {
  252       return "simd";
  253       }
  254 #endif
  255 
  256    return "base";
  257    }
  258 
  259 }
