#include <gtest/gtest.h>

#include "core.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

class MyCryptoNetsTest : public ::testing::Test
{

protected:
    MyCryptoNetsTest()
    {
        envPtr = make_shared<SealBFVEnvironment>(8192, 549764251649);
    }

    virtual ~MyCryptoNetsTest() {}

    shared_ptr<SealBFVEnvironment> envPtr;
};

TEST_F(MyCryptoNetsTest, Square)
{
    vector<vector<uint64_t>> matrix_p{
        {3ULL, 1ULL, 2ULL},
        {2ULL, 1ULL, 2ULL},
        {1ULL, 1ULL, 2ULL},
    };
    auto encoded = encode(*envPtr, matrix_p);
    auto encrypted = encrypt(*envPtr, encoded);

    square(*envPtr, encrypted);

    auto decrypted = decrypt(*envPtr, encrypted);
    auto decoded = decode(*envPtr, decrypted);
    print_matrix(decoded);
}

TEST_F(MyCryptoNetsTest, WeightEncoding)
{
    vector<vector<uint64_t>> matrix_p{
        {3ULL, 1ULL, 2ULL},
    };
    auto encoded = encode(*envPtr, matrix_p);
    auto encrypted = encrypt(*envPtr, encoded);

    Plaintext p1 {"3"};
    envPtr->evaluatorPtr->multiply_plain_inplace(encrypted[0], p1);
    
    auto decrypted = decrypt(*envPtr, encrypted);
    auto decoded = decode(*envPtr, decrypted);
    print_matrix(decoded);
}

TEST_F(MyCryptoNetsTest, FC)
{
    vector<vector<uint64_t>> matrix_p{
        {3ULL, 1ULL, 2ULL},
        {2ULL, 1ULL, 2ULL},
        {1ULL, 1ULL, 2ULL},
    };
    auto encoded = encode(*envPtr, matrix_p);
    auto encrypted = encrypt(*envPtr, encoded);

    Plaintext weight00 {"1"};
    Plaintext weight01 {"2"};
    Plaintext weight02 {"3"};
    Plaintext weight10 {"2"};
    Plaintext weight11 {"1"};
    Plaintext weight12 {"1"};
    vector<Plaintext> weights {weight00, weight01, weight02, weight10, weight11, weight12};

    Plaintext bias0 {"5"};
    Plaintext bias1 {"2"};
    vector<Plaintext> biases {bias0, bias1};

    auto result = fc(*envPtr, encrypted, weights, biases, 3);

    auto decrypted = decrypt(*envPtr, result);
    auto decoded = decode(*envPtr, decrypted);
    print_matrix(decoded);
    /*
    [ 15, 11, 17, 5, ..., 5, 5, 5, 5 ]
    [ 11, 6, 10, 2, ..., 2, 2, 2, 2 ]
    */
}

TEST_F(MyCryptoNetsTest, CRT)
{
    // Precompute
    size_t poly_modulus_degree = 8192;
    uint64_t plain_modulus1 = 549764251649;
    uint64_t plain_modulus2 = 549764284417;
    SealBFVEnvironment env1 {poly_modulus_degree, plain_modulus1};
    SealBFVEnvironment env2 {poly_modulus_degree, plain_modulus2};

    BigUInt factor1 {to_hex(plain_modulus1)};
    BigUInt factor2 {to_hex(plain_modulus2)};

    BigUInt uIntBigFactor = factor1 * factor2;

    auto minor1 = factor2;
    auto minor2 = factor1;
    
    BigUInt rem1;
    minor1.divrem(factor1, rem1);
    BigUInt ys1 = rem1.modinv(factor1);
    BigUInt rem2;
    minor2.divrem(factor2, rem2);
    BigUInt ys2 = rem2.modinv(factor2);

    BigUInt preComputedCoefficient1 = ys1 * minor1;
    BigUInt preComputedCoefficient2 = ys2 * minor2;

    // SplitBigNumbers
    int a = -5;
    int b = -6;

    BigUInt uInta1, uInta2;   
    BigUInt uinta = a > 0 ? BigUInt(to_hex(a)) : uIntBigFactor - (uint64_t)abs(a);
    uinta.divrem(factor1, uInta1);
    uinta.divrem(factor2, uInta2);
    uint64_t a1 = stoul(uInta1.to_dec_string());
    uint64_t a2 = stoul(uInta2.to_dec_string());

    BigUInt uIntb1, uIntb2;   
    BigUInt uintb = b > 0 ? BigUInt(to_hex(b)) : uIntBigFactor - (uint64_t)abs(b);
    uintb.divrem(factor1, uIntb1);
    uintb.divrem(factor2, uIntb2);
    uint64_t b1 = stoul(uIntb1.to_dec_string());
    uint64_t b2 = stoul(uIntb2.to_dec_string());


    // Doing secure computation
    Plaintext temp_p;

    env1.batchEncoderPtr->encode(vector<uint64_t>{a1}, temp_p);
    Ciphertext a1_c;
    env1.encryptorPtr->encrypt(temp_p, a1_c);

    env2.batchEncoderPtr->encode(vector<uint64_t>{a2}, temp_p);
    Ciphertext a2_c;
    env2.encryptorPtr->encrypt(temp_p, a2_c);

    env1.batchEncoderPtr->encode(vector<uint64_t>{b1}, temp_p);
    Ciphertext b1_c;
    env1.encryptorPtr->encrypt(temp_p, b1_c);

    env2.batchEncoderPtr->encode(vector<uint64_t>{b2}, temp_p);
    Ciphertext b2_c;
    env2.encryptorPtr->encrypt(temp_p, b2_c);

    Ciphertext p1_c;
    env1.evaluatorPtr->multiply(a1_c, b1_c, p1_c);
    Ciphertext p2_c;
    env2.evaluatorPtr->multiply(a2_c, b2_c, p2_c);

    Plaintext p1_p;
    env1.decryptorPtr->decrypt(p1_c, p1_p);
    Plaintext p2_p;
    env2.decryptorPtr->decrypt(p2_c, p2_p);

    vector<uint64_t> temp;
    env1.batchEncoderPtr->decode(p1_p, temp);
    uint64_t r1 = temp[0];
    env2.batchEncoderPtr->decode(p2_p, temp);
    uint64_t r2 = temp[0];

    // JoinBigNumbers
    auto uIntTemp = preComputedCoefficient1 * r1 + preComputedCoefficient2 * r2;
    BigUInt rem;
    uIntTemp.divrem(uIntBigFactor, rem);

    double result;
    if (rem * 2 > uIntBigFactor) {
        result = (uIntBigFactor - rem).to_double() * -1;
    } else
    {
        result = rem.to_double();
    }
    

    cout << result << endl;
}


int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
