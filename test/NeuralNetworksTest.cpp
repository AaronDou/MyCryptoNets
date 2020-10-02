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

// TEST_F(MyCryptoNetsTest, Square)
// {
//     vector<vector<uint64_t>> matrix_p{
//         {3ULL, 1ULL, 2ULL},
//         {2ULL, 1ULL, 2ULL},
//         {1ULL, 1ULL, 2ULL},
//     };
//     auto encoded = encode(*envPtr, matrix_p);
//     auto encrypted = encrypt(*envPtr, encoded);

//     square(*envPtr, encrypted);

//     auto decrypted = decrypt(*envPtr, encrypted);
//     auto decoded = decode(*envPtr, decrypted);
//     print_matrix(decoded);
// }

// TEST_F(MyCryptoNetsTest, WeightEncoding)
// {
//     vector<vector<uint64_t>> matrix_p{
//         {3ULL, 1ULL, 2ULL},
//     };
//     auto encoded = encode(*envPtr, matrix_p);
//     auto encrypted = encrypt(*envPtr, encoded);

//     Plaintext p1 {"3"};
//     envPtr->evaluatorPtr->multiply_plain_inplace(encrypted[0], p1);
    
//     auto decrypted = decrypt(*envPtr, encrypted);
//     auto decoded = decode(*envPtr, decrypted);
//     print_matrix(decoded);
// }

// TEST_F(NeuralNetworksTest, FC)
// {
//     vector<vector<uint64_t>> matrix_p{
//         {3ULL, 1ULL, 2ULL},
//         {2ULL, 1ULL, 2ULL},
//         {1ULL, 1ULL, 2ULL},
//     };
//     auto encoded = encode(*envPtr, matrix_p);
//     auto encrypted = encrypt(*envPtr, encoded);

//     Plaintext weight00{"1"};
//     Plaintext weight01{"2"};
//     Plaintext weight02{"3"};
//     Plaintext weight10{"2"};
//     Plaintext weight11{"1"};
//     Plaintext weight12{"1"};
//     vector<Plaintext> weights{weight00, weight01, weight02, weight10, weight11, weight12};

//     Plaintext bias0{"5"};
//     Plaintext bias1{"2"};
//     vector<Plaintext> biases{bias0, bias1};

//     auto result = fc(*envPtr, encrypted, weights, biases, 3);

//     auto decrypted = decrypt(*envPtr, result);
//     auto decoded = decode(*envPtr, decrypted);
//     print_matrix(decoded);
//     /*
//     [ 15, 11, 17, 5, ..., 5, 5, 5, 5 ]
//     [ 11, 6, 10, 2, ..., 2, 2, 2, 2 ]
//     */
// }

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
