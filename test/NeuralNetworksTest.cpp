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
        env = SealBfvEnvironment(8192, vector<uint64_t>{549764251649, 549764284417});
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
    encrypt_vec(data, ciphertexts, env, 10000);

    vector<double> weights{-6, 0, 10.54, 8.4, -99.99, 1001};
    vector<SealBfvPlaintext> weightsP;
    encode(weights, weightsP, env, 100);

    SealBfvPlaintext bias0{-6.66666, env, 1000000};
    SealBfvPlaintext bias1{18888, env, 1000000};
    vector<SealBfvPlaintext> biases{bias0, bias1};

    vector<SealBfvCiphertext> destination;

    fc(getPointers(ciphertexts),
       weightsP,
       biases,
       data.size(),
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
    vector<int const *> dataPtr;
    convolutionOrganizer(data, 3, 2, 2, dataPtr);
    vector<int> convData;
    transform(dataPtr.begin(), dataPtr.end(), back_inserter(convData), [](int const *c) { return c == nullptr ? -1 : *c; });
    vector<int> expected{6, 1, 3, 8, 0, 1, 9, 2, 4, 3, 4, 1, 1, 3, 8, 4, 4, 2, 1, -1, -1, 8, -1, -1, 2, -1, -1, 9, 2, 4, 8, 4, 2, 7, 3, 1, 4, 4, 2, 2, 2, 4, 1, 0, 0, 2, -1, -1, 4, -1, -1, 0, -1, -1, 7, 3, 1, -1, -1, -1, -1, -1, -1, 1, 0, 0, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1};
    EXPECT_EQ(convData, expected);
}

TEST_F(NeuralNetworksTest, Convolution)
{
    vector<vector<double>> data = {{6}, {1}, {3}, {4}, {1}, /**/ {8}, {0}, {1}, {3}, {8}, /**/ {9}, {2}, {4}, {4}, {2}, /**/ {8}, {4}, {2}, {2}, {4}, /**/ {7}, {3}, {1}, {0}, {0}};
    vector<SealBfvCiphertext> dataE;
    encrypt_vec(data, dataE, env, 10);
    vector<SealBfvCiphertext const *> dataEPtr;
    convolutionOrganizer(dataE, 3, 2, 2, dataEPtr);

    vector<double> weights{
        -6, 0, 1,
        5, -7, 6,
        -7, 10, 8,
        /* kernel separator*/
        5, 0, 1,
        5, -7, 6,
        -7, 10, 8};
    vector<SealBfvPlaintext> weightsP;
    encode(weights, weightsP, env, 100);

    SealBfvPlaintext bias0{5, env, 1000};
    SealBfvPlaintext bias1{-3, env, 1000};
    vector<SealBfvPlaintext> biases{bias0, bias1};

    vector<SealBfvCiphertext> destination;

    fc(dataEPtr,
       weightsP,
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

TEST_F(NeuralNetworksTest, HardMax)
{
    vector<vector<int>> data = {
        {1, 9, -10, 4, -2},
        {9, -1, -5, 6, 5},
        {-1, -4, -9, 1, 9},
        {-6, -8, 0, 3, -7},
        {7, -8, 3, -2, 2}
    };
    vector<size_t> expected {1, 0, 4, 1, 2};
    EXPECT_EQ(hardmax(data), expected);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
