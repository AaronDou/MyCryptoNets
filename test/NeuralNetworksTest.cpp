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
       weights,
       biases,
       3,
       destination,
       env);

    vector<vector<double>> res;
    decrypt(destination, res, env);

    vector<vector<double>> expected{
        {374.47334, 19.732286, 585574.65334},
        {-9992.6, 18855.9394, 55631857.258879997},
    };

    EXPECT_DOUBLE_EQ(res[0][0], expected[0][0]);
    EXPECT_DOUBLE_EQ(res[0][1], expected[0][1]);
    EXPECT_DOUBLE_EQ(res[0][2], expected[0][2]);
    EXPECT_DOUBLE_EQ(res[1][0], expected[1][0]);
    EXPECT_DOUBLE_EQ(res[1][1], expected[1][1]);
    EXPECT_DOUBLE_EQ(res[1][2], expected[1][2]);
}

TEST_F(NeuralNetworksTest, ConvolutionOrganizer)
{
    vector<int> data = {6, 1, 3, 4, 1, /**/ 8, 0, 1, 3, 8, /**/ 9, 2, 4, 4, 2, /**/ 8, 4, 2, 2, 4, /**/ 7, 3, 1, 0, 0};
    vector<int *> dataPtr;
    convolutionOrganizer(data, 3, 2, 2, dataPtr);
    vector<int> convData;
    transform(dataPtr.begin(), dataPtr.end(), back_inserter(convData), [](int *c) { return c == nullptr ? -1 : *c; });
    vector<int> expected{6, 1, 3, 8, 0, 1, 9, 2, 4, 3, 4, 1, 1, 3, 8, 4, 4, 2, 1, -1, -1, 8, -1, -1, 2, -1, -1, 9, 2, 4, 8, 4, 2, 7, 3, 1, 4, 4, 2, 2, 2, 4, 1, 0, 0, 2, -1, -1, 4, -1, -1, 0, -1, -1, 7, 3, 1, -1, -1, -1, -1, -1, -1, 1, 0, 0, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1};
    EXPECT_EQ(convData, expected);
}

TEST_F(NeuralNetworksTest, Convolution)
{
    vector<vector<double>> data = {{6}, {1}, {3}, {4}, {1}, /**/ {8}, {0}, {1}, {3}, {8}, /**/ {9}, {2}, {4}, {4}, {2}, /**/ {8}, {4}, {2}, {2}, {4}, /**/ {7}, {3}, {1}, {0}, {0}};
    vector<SealBfvCiphertext> dataE;
    encrypt(data, dataE, env, 10);
    vector<SealBfvCiphertext *> dataEPtr;
    convolutionOrganizer(dataE, 3, 2, 2, dataEPtr);

    SealBfvPlaintext weight000{-6, env, 100};
    SealBfvPlaintext weight001{0, env, 100};
    SealBfvPlaintext weight002{1, env, 100};
    SealBfvPlaintext weight010{5, env, 100};
    SealBfvPlaintext weight011{-7, env, 100};
    SealBfvPlaintext weight012{6, env, 100};
    SealBfvPlaintext weight020{-7, env, 100};
    SealBfvPlaintext weight021{10, env, 100};
    SealBfvPlaintext weight022{8, env, 100};

    SealBfvPlaintext weight100{5, env, 100}; // only this entry different
    SealBfvPlaintext weight101{0, env, 100};
    SealBfvPlaintext weight102{1, env, 100};
    SealBfvPlaintext weight110{5, env, 100};
    SealBfvPlaintext weight111{-7, env, 100};
    SealBfvPlaintext weight112{6, env, 100};
    SealBfvPlaintext weight120{-7, env, 100};
    SealBfvPlaintext weight121{10, env, 100};
    SealBfvPlaintext weight122{8, env, 100};

    vector<SealBfvPlaintext> weights{weight000, weight001, weight002,
                                     weight010, weight011, weight012,
                                     weight020, weight021, weight022,
                                     weight100, weight101, weight102,
                                     weight110, weight111, weight112,
                                     weight120, weight121, weight122};

    SealBfvPlaintext bias0{5, env, 1000};
    SealBfvPlaintext bias1{-3, env, 1000};
    vector<SealBfvPlaintext> biases{bias0, bias1};

    vector<SealBfvCiphertext> destination;

    fc(dataEPtr,
       weights,
       biases,
       9,
       destination,
       env);

    vector<vector<double>> res;
    decrypt(destination, res, env);

    vector<vector<double>> expected{
        {7}, {48}, {25}, {-32}, {-4}, {13}, {-36}, {-1}, {5}, {65}, {73}, {28}, {59}, {32}, {27}, {33}, {2}, {-3}};
    EXPECT_EQ(res, expected);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
