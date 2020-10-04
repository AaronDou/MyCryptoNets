#include "NeuralNetworks.h"
#include "DataPreprocess.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

vector<double> cryptonets(const Weights &weight, const vector<vector<double>> &input, const SealBfvEnvironment &env)
{
    vector<SealBfvCiphertext> dataE;
    auto encryptDecor = make_decorator(encrypt, "Encryption");
    encryptDecor(input, dataE, env, 16.0);

    

    vector<double> res;
    return res;
}

int main()
{
    size_t poly_modulus_degree = 8192;
    vector<uint64_t> plain_modulus{549764251649, 549764284417};

    SealBfvEnvironment env = SealBfvEnvironment(poly_modulus_degree, plain_modulus);

    auto weights = readWeights();
    
    vector<vector<vector<double>>> data;
    vector<vector<double>> labels;
    readInput(poly_modulus_degree, 1.0 / 256.0, data, labels);

    // Batch processing
    for (size_t batchIndex = 0; batchIndex < data.size(); batchIndex++)
    {   
        auto res = cryptonets(weights, data[batchIndex], env);
        break;
    }

    return 0;
}