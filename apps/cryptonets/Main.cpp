#include "NeuralNetworks.h"
#include "DataPreprocess.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

vector<vector<double>> cryptonets(const Params &params, const vector<SealBfvCiphertext> &inputE, const SealBfvEnvironment &env)
{
    vector<SealBfvCiphertext> intermediateResultsE;

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;
    // Conv Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0;
        auto decor = make_decorator(fc, "Conv");

        vector<SealBfvCiphertext const *> inputEPtr;
        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        convolutionOrganizer(inputE, 5, 2, 1, inputEPtr);
        singleCoefficientEncode_vec(params.convWeights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.convBiases, BiasesP, env, inputE[0].scale * scale);
        decor(inputEPtr,
              WeightsP,
              BiasesP,
              5 * 5,
              resultE,
              env);

        intermediateResultsE = move(resultE);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(intermediateResultsE, env);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // FC1 Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0 * 32.0;
        auto decor = make_decorator(fc, "FC1");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        singleCoefficientEncode_vec(params.FC1Weights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.FC1Biases, BiasesP, env, intermediateResultsE[0].scale * scale);
        decor(getPointers(intermediateResultsE),
              WeightsP,
              BiasesP,
              intermediateResultsE.size(),
              resultE,
              env);

        intermediateResultsE.clear();
        intermediateResultsE = move(resultE);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // Debugging
    vector<vector<double>> temp;
    decrypt_vec(intermediateResultsE, temp, env);


    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(intermediateResultsE, env);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // FC2 Layer
    {
        vector<SealBfvCiphertext> resultE;
        double scale = 32.0;
        auto decor = make_decorator(fc, "FC2");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        singleCoefficientEncode_vec(params.FC2Weights, WeightsP, env, scale);
        singleCoefficientEncode_vec(params.FC2Biases, BiasesP, env, intermediateResultsE[0].scale * scale);
        decor(getPointers(intermediateResultsE),
              WeightsP,
              BiasesP,
              intermediateResultsE.size(),
              resultE,
              env);

        intermediateResultsE.clear();
        intermediateResultsE = move(resultE);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    vector<vector<double>> res;
    decrypt_vec(intermediateResultsE, res, env);

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
        // Encrypt
        vector<SealBfvCiphertext> inputE;
        auto decor = make_decorator(encrypt_vec, "Encryption");
        decor(data[batchIndex], inputE, env, 16.0);
        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(inputE[0].eVectors[0]) << endl;

        // Forward pass on the cloud
        std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
        auto res = cryptonets(params, inputE, env);
        std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        cout << setw(20) << "Total time: ";
        cout<< elapsed_seconds.count() << " seconds" << std::endl;

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