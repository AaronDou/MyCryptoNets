#include <gtest/gtest.h>

#include "SealBfvCrtWrapper.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;
using namespace testing;

class SealBfvCrtWrapper : public ::testing::Test
{

protected:
    SealBfvCrtWrapper()
    {
        env = SealBfvEnvironment(8192, {549764251649, 549764284417});
    }

    virtual ~SealBfvCrtWrapper() {}

    SealBfvEnvironment env;
};

TEST_F(SealBfvCrtWrapper, NoiseBudget)
{
    size_t poly_modulus_degree = 8192;
    uint64_t plain_modulus = 549764251649;

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_modulus_degree)); 
    
    // parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); // 146
    parms.set_plain_modulus(plain_modulus); // 127

    auto context = SEALContext::Create(parms);
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(10);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batchEncoder(context);
    Evaluator evaluator(context);
    IntegerEncoder encoder(context);

    vector<size_t> data {5};
    Plaintext temp;
    batchEncoder.encode(data, temp);
    Ciphertext dataE;
    encryptor.encrypt(temp, dataE);

    // int value1 = 5;
    // Plaintext plain1 = encoder.encode(value1);
    // Ciphertext dataE;
    // encryptor.encrypt(plain1, dataE);
}

TEST_F(SealBfvCrtWrapper, SplitBigNumbers)
{
    EXPECT_EQ(splitBigNumbers(0.5, 100, env), (vector<uint64_t>{50, 50}));
    EXPECT_EQ(splitBigNumbers(0.0, 100, env), (vector<uint64_t>{0, 0}));
    EXPECT_EQ(splitBigNumbers(-0.5, 100, env), (vector<uint64_t>{549764251599, 549764284367}));
}

TEST_F(SealBfvCrtWrapper, JoinSplitNumbers)
{
    EXPECT_EQ((joinSplitNumbers({50, 50}, env)), 50.0);
    EXPECT_EQ((joinSplitNumbers({0, 0}, env)), 0.0);
    EXPECT_EQ((joinSplitNumbers({549764251599, 549764284367}, env)), -50.0);
}

TEST_F(SealBfvCrtWrapper, EncryptionRoundTrip)
{
    vector<double> vec{1.0, 2.1, -5.3, 0};
    SealBfvCiphertext bfvCiphertext(vec, env, 100);
    EXPECT_EQ(bfvCiphertext.decrypt(env), vec);
}

TEST_F(SealBfvCrtWrapper, SquareInplace)
{
    vector<double> vec{1.0, 2.1, -5.3, 0};
    SealBfvCiphertext bfvCiphertext(vec, env, 100);
    square_inplace(bfvCiphertext, env);
    EXPECT_EQ(bfvCiphertext.decrypt(env), (vector<double>{1.0, 4.41, 28.09, 0}));
}

TEST_F(SealBfvCrtWrapper, MultiplyPlain)
{
    vector<double> vec{1.0, 2.1, -5.3, 0};
    SealBfvCiphertext ciphertext(vec, env, 100);

    SealBfvPlaintext plaintext(1.5, env, 2);
    SealBfvCiphertext res;
    multiply_plain(ciphertext, plaintext, res, env);
    EXPECT_EQ(res.decrypt(env), (vector<double>{1.5, 3.15, -7.95, 0}));
}

TEST_F(SealBfvCrtWrapper, AddMany)
{
    vector<double> vec1{1.0, 2.1, -5.3, 0};
    SealBfvCiphertext ciphertext1(vec1, env, 100);
    vector<double> vec2{-3, 2, 5, -4.2};
    SealBfvCiphertext ciphertext2(vec2, env, 100);

    SealBfvCiphertext res;
    add_many({ciphertext1, ciphertext2, ciphertext2}, res, env);
    EXPECT_EQ(res.decrypt(env), (vector<double>{-5, 6.1, 4.7, -8.4}));
}

TEST_F(SealBfvCrtWrapper, AddPlainInplace)
{
    vector<double> vec{1.0, 2.1, -5.3, 0};
    SealBfvCiphertext bfvCiphertext(vec, env, 100);

    SealBfvPlaintext plaintext(1.5, env, 100);
    add_plain_inplace(bfvCiphertext, plaintext, env);
    EXPECT_EQ(bfvCiphertext.decrypt(env), (vector<double>{2.5, 3.6, -3.8, 1.5}));
}

TEST_F(SealBfvCrtWrapper, IsZero)
{
    SealBfvPlaintext plaintext1(1.5, env, 2);
    EXPECT_EQ(plaintext1.is_zero(), false);

    SealBfvPlaintext plaintext2(0.0, env, 2);
    EXPECT_EQ(plaintext2.is_zero(), true);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
