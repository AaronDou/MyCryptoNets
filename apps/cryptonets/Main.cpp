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

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
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

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
    }

    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(dataE, env);

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
    }

    // FC1 Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0 * 32.0;
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

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
    }

    // Debugging
    vector<vector<double>> temp;
    decrypt_vec(dataE, temp, env);


    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(dataE, env);

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
    }

    // FC2 Layer
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

        cout << "Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(dataE[0].eVectors[0]) << endl;
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
    vector<vector<size_t>> labels;
    readInput(poly_modulus_degree, 1.0 / 256.0, data, labels);

    // Batch processing

    size_t correct = 0;
    for (size_t batchIndex = 0; batchIndex < data.size(); batchIndex++)
    {
        auto res = cryptonets(params, data[batchIndex], env);
        auto predictions = hardmax(res);

        for (size_t i = 0; i < predictions.size(); i++)
        {
            if (predictions[i] == labels[batchIndex][i])
            {
                correct++;
            }
        }

        cout << "Accuracy is " << correct << "/" << poly_modulus_degree << endl;

        break;
    }

    return 0;
}