#include "NeuralNetworks.h"
#include "DataPreprocess.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

vector<vector<double>> cryptonets(const Params &params, const vector<vector<double>> &input, const SealBfvEnvironment &env)
{
    vector<SealBfvCiphertext> dataE;

    {
        auto decor = make_decorator(encrypt_vec, "Encryption");
        decor(input, dataE, env, 16.0);
    }

    // Conv Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0;
        auto decor = make_decorator(fc, "Conv");

        vector<SealBfvCiphertext *> dataEPtr;
        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        convolutionOrganizer(dataE, 5, 2, 1, dataEPtr);
        singleCoefficientEncode_vec(params.convWeights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.convBiases, BiasesP, env, dataE[0].scale * scale);
        decor(dataEPtr,
              WeightsP,
              BiasesP,
              5 * 5,
              resultE,
              env);

        dataE.clear();
        dataE = move(resultE);
    }

    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(dataE, env);
    }

    // FC Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0 * 32.0; // Needs to be slightly larger because the weights are smaller.
        auto decor = make_decorator(fc, "FC1");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        singleCoefficientEncode_vec(params.FC1Weights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.FC1Biases, BiasesP, env, dataE[0].scale * scale);
        decor(getPointers(dataE),
              WeightsP,
              BiasesP,
              dataE.size(),
              resultE,
              env);

        dataE.clear();
        dataE = move(resultE);
    }

    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(dataE, env);
    }

    // FC Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0;
        auto decor = make_decorator(fc, "FC2");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        singleCoefficientEncode_vec(params.FC2Weights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.FC2Biases, BiasesP, env, dataE[0].scale * scale);
        decor(getPointers(dataE),
              WeightsP,
              BiasesP,
              dataE.size(),
              resultE,
              env);

        dataE.clear();
        dataE = move(resultE);
    }

    vector<vector<double>> res;
    decrypt_vec(dataE, res, env);

    return res;
}

int main()
{
    size_t poly_modulus_degree = 8192;
    vector<uint64_t> plain_modulus{549764251649, 549764284417};

    SealBfvEnvironment env = SealBfvEnvironment(poly_modulus_degree, plain_modulus);

    auto params = readParams();

    vector<vector<vector<double>>> data;
    vector<vector<double>> labels;
    readInput(poly_modulus_degree, 1.0 / 256.0, data, labels);

    // Batch processing
    for (size_t batchIndex = 0; batchIndex < data.size(); batchIndex++)
    {
        auto res = cryptonets(params, data[batchIndex], env);
        break;
    }

    return 0;
}