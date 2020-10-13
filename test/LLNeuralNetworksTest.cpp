#include <gtest/gtest.h>

#include "LLNeuralNetworks.h"

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

// TEST_F(NeuralNetworksTest, FC)
// {
//     vector<vector<double>> data{
//         {8.5, -4.4, 0},
//         {700, -0.05, 5.888},
//         {41, -0.0001, 55558}};
//     vector<SealBfvCiphertext> ciphertexts;
//     encrypt_vec(data, ciphertexts, env, 10000);

//     vector<double> weights{-6, 0, 10.54, 8.4, -99.99, 1001};
//     vector<SealBfvPlaintext> weightsP;
//     encode(weights, weightsP, env, 100);

//     SealBfvPlaintext bias0{-6.66666, env, 1000000};
//     SealBfvPlaintext bias1{18888, env, 1000000};
//     vector<SealBfvPlaintext> biases{bias0, bias1};

//     vector<SealBfvCiphertext> destination;

//     fc(getPointers(ciphertexts),
//        weightsP,
//        biases,
//        data.size(),
//        destination,
//        env);

//     vector<vector<double>> res;
//     decrypt(destination, res, env);

//     vector<vector<double>> expected{
//         {374.47334, 19.732286, 585574.65334},
//         {-9992.6, 18855.9394, 55631857.258879997},
//     };

//     EXPECT_DOUBLE_EQ(res[0][0], expected[0][0]);
//     EXPECT_DOUBLE_EQ(res[0][1], expected[0][1]);
//     EXPECT_DOUBLE_EQ(res[0][2], expected[0][2]);
//     EXPECT_DOUBLE_EQ(res[1][0], expected[1][0]);
//     EXPECT_DOUBLE_EQ(res[1][1], expected[1][1]);
//     EXPECT_DOUBLE_EQ(res[1][2], expected[1][2]);
// }

TEST_F(NeuralNetworksTest, ConvolutionOrganizer)
{
    vector<int> data = {6, 1, 3, 4, 1, /**/ 8, 0, 1, 3, 8, /**/ 9, 2, 4, 4, 2, /**/ 8, 4, 2, 2, 4, /**/ 7, 3, 1, 0, 0};
    vector<vector<int>> patches;
    convolutionOrganizer(data, 3, 2, 2, patches, 0);
    vector<vector<int>> expected{
        {6, 3, 1, 9, 4, 2, 7, 1, 0},
        {1, 4, 0, 2, 4, 0, 3, 0, 0},
        {3, 1, 0, 4, 2, 0, 1, 0, 0},
        {8, 1, 8, 8, 2, 4, 0, 0, 0},
        {0, 3, 0, 4, 2, 0, 0, 0, 0},
        {1, 8, 0, 2, 4, 0, 0, 0, 0},
        {9, 4, 2, 7, 1, 0, 0, 0, 0},
        {2, 4, 0, 3, 0, 0, 0, 0, 0},
        {4, 2, 0, 1, 0, 0, 0, 0, 0}};
    EXPECT_EQ(patches, expected);
}

TEST_F(NeuralNetworksTest, Convolution)
{
    vector<double> data = {6, 1, 3, 4, 1, /**/ 8, 0, 1, 3, 8, /**/ 9, 2, 4, 4, 2, /**/ 8, 4, 2, 2, 4, /**/ 7, 3, 1, 0, 0};
    vector<vector<double>> patches;
    convolutionOrganizer(data, 3, 2, 2, patches, 0.0);

    vector<SealBfvCiphertext> dataE;
    encrypt(patches, dataE, env);

    vector<double> kernel1{
        -6, 0, 1,
        5, -7, 6,
        -7, 10, 8};
    vector<double> kernel2{
        5, 0, 1,
        5, -7, 6,
        -7, 10, 8};
    vector<SealBfvPlaintext> kernel1P;
    encode(kernel1, kernel1P, env);
    vector<SealBfvPlaintext> kernel2P;
    encode(kernel2, kernel2P, env);
    vector<vector<SealBfvPlaintext>> weightsP{kernel1P, kernel2P};

    SealBfvPlaintext bias0{vector<double>(dataE[0].batchSize, 5), env};
    SealBfvPlaintext bias1{vector<double>(dataE[0].batchSize, -3), env};
    vector<SealBfvPlaintext> biases{bias0, bias1};

    vector<SealBfvCiphertext> destination;

    conv2d(dataE,
           weightsP,
           biases,
           destination,
           env);

    vector<vector<double>> res;
    decrypt(destination, res, env);

    vector<vector<double>> expected{
        {7, 48, 25, -32, -4, 13, -36, -1, 5},
        {65, 73, 28, 59, 32, 27, 33, 2, -3}};
    EXPECT_EQ(res, expected);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
