#include <gtest/gtest.h>

#include "SealBfvVector.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;
using namespace testing;

class SealBfvVectorTest : public ::testing::Test
{

protected:
    SealBfvVectorTest()
    {
        env = SealBfvEnvironment(8192, vector<uint64_t>{549764251649, 549764284417});
    }

    virtual ~SealBfvVectorTest() {}

    SealBfvEnvironment env;
};

TEST_F(SealBfvVectorTest, EncryptionRoundTrip)
{
    vector<vector<double>> data{
        {4.2, -5, 0},
        {10000, -55555, 0.005},
    };
    vector<SealBfvCiphertext> ciphertexts;
    encrypt(data, ciphertexts, env, 10000);
    vector<vector<double>> decrypted;
    decrypt(ciphertexts, decrypted, env);
    EXPECT_EQ(data, decrypted);
}

TEST_F(SealBfvVectorTest, SquareInplace)
{
    vector<vector<double>> data{
        {4.2, -5, 0},
        {10000, -55555, 0.005},
    };
    vector<SealBfvCiphertext> ciphertexts;
    encrypt(data, ciphertexts, env, 10000);
    square_inplace_vec(ciphertexts, env);
    vector<vector<double>> decrypted;
    decrypt(ciphertexts, decrypted, env);

    vector<vector<double>> expected{
        {4.2 * 4.2, 25, 0},
        {10000 * 10000, 55555.0 * 55555, 0.005 * 0.005},
    };
    EXPECT_EQ(decrypted, expected);
}

TEST_F(SealBfvVectorTest, DotProduct)
{
    vector<vector<double>> data{
        {4.2, -5, 0},
        {5, -10, 5.3},
    };
    vector<SealBfvCiphertext> ciphertexts;
    encrypt(data, ciphertexts, env, 10000);

    vector<vector<double>> multipliers{
        {2, -2, 1},
        {-1, 0, -1},
    };
    vector<SealBfvPlaintext> plaintext;
    batch_encode(multipliers, plaintext, env, 10000);

    SealBfvCiphertext res;
    dot_product(ciphertexts, plaintext, res, env);
    vector<double> decrypted = res.decrypt(env);

    vector<double> expected{
        4.2 * 2 + 5 * -1,
        -5 * -2 + -10 * 0,
        0 * 1 + 5.3 * -1};

    for (size_t i = 0; i < expected.size(); i++)
    {
        EXPECT_DOUBLE_EQ(decrypted[i], expected[i]);
    }
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
