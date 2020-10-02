#include <gtest/gtest.h>

#include "NeuralNetworks.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;
using namespace testing;

class NeuralNetworksTest : public ::testing::Test
{

protected:
    NeuralNetworksTest()
    {
        env = SealBfvEnvironment(8192, {549764251649, 549764284417});
    }

    virtual ~NeuralNetworksTest() {}

    SealBfvEnvironment env;
};

TEST_F(NeuralNetworksTest, FC)
{
    vector<vector<double>> data{
        {8.5, -4.4, 0},
        {700, -0.05, 5.888},
        {41, -0.0001, 55558}};
    vector<SealBfvCiphertext> ciphertexts;
    encrypt(data, ciphertexts, env, 10000);

    SealBfvPlaintext weight00{-6, env, 100};
    SealBfvPlaintext weight01{0, env, 100};
    SealBfvPlaintext weight02{10.54, env, 100};
    SealBfvPlaintext weight10{8.4, env, 100};
    SealBfvPlaintext weight11{-99.99, env, 100};
    SealBfvPlaintext weight12{1001, env, 100};

    vector<SealBfvPlaintext> weights{weight00, weight01, weight02,
                                     weight10, weight11, weight12};

    SealBfvPlaintext bias0{-6.66666, env, 1000000};
    SealBfvPlaintext bias1{18888, env, 1000000};
    vector<SealBfvPlaintext> biases{bias0, bias1};

    vector<SealBfvCiphertext> destination;

    fc(getPointers(ciphertexts),
       getPointers(weights),
       getPointers(biases),
       3,
       destination,
       env);
    
    vector<vector<double>> res;
    decrypt(destination, res, env);

    vector<vector<double>> expected {
        {374.47334, 19.732286, 585574.65334}, 
        {-9992.6, 18855.9394,  55631857.258879997},
    };

    EXPECT_DOUBLE_EQ(res[0][0], expected[0][0]);
    EXPECT_DOUBLE_EQ(res[0][1], expected[0][1]);
    EXPECT_DOUBLE_EQ(res[0][2], expected[0][2]);
    EXPECT_DOUBLE_EQ(res[1][0], expected[1][0]);
    EXPECT_DOUBLE_EQ(res[1][1], expected[1][1]);
    EXPECT_DOUBLE_EQ(res[1][2], expected[1][2]);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
