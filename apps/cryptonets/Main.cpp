#include "NeuralNetworks.h"
#include "DataPreprocess.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

namespace {
    size_t POLY_MODULUS_DEGREE = 8192; 
    vector<Modulus> PLAINTEXT_MODULUS = PlainModulus::Batching(
        POLY_MODULUS_DEGREE, {18, 18});
    
    double INPUT_SCALE = 2.0;
    double CONV_SCALE = 2.0;
    double FC1_SCALE = 32.0;
    double FC2_SCALE = 16.0;
}


vector<vector<double>> cryptonets(const Params &params, const vector<SealBfvCiphertext> &inputE, const SealBfvEnvironment &env)
{
    vector<SealBfvCiphertext> intermediateResultsE;

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;
    // Conv Layer
    {
        vector<SealBfvCiphertext> resultE;
        auto decor = make_decorator(fc, "Conv");

        vector<SealBfvCiphertext const *> inputEPtr;
        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        convolutionOrganizer(inputE, 5, 2, 1, inputEPtr);
        encode(params.convWeights, WeightsP, env, CONV_SCALE);
        encode(params.convBiases, BiasesP, env, inputE[0].scale * CONV_SCALE);
        decor(inputEPtr,
              WeightsP,
              BiasesP,
              5 * 5,
              resultE,
              env);

        intermediateResultsE = move(resultE);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // Modulus switch
    {
        #pragma omp parallel for
        for (size_t i = 0; i < intermediateResultsE.size(); i++) {
            mod_switch_to_next_inplace(intermediateResultsE[i], env);
        }
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
        auto decor = make_decorator(fc, "FC1");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        encode(params.FC1Weights, WeightsP, env, FC1_SCALE);
        encode(params.FC1Biases, BiasesP, env, intermediateResultsE[0].scale * FC1_SCALE);
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
    decrypt(intermediateResultsE, temp, env);

    // Square activation layer
    {
        auto decor = make_decorator(square_inplace_vec, "Square");

        decor(intermediateResultsE, env);

        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(intermediateResultsE[0].eVectors[0]) << endl;
    }

    // FC2 Layer
    {
        vector<SealBfvCiphertext> resultE;
        auto decor = make_decorator(fc, "FC2");

        vector<SealBfvPlaintext> WeightsP;
        vector<SealBfvPlaintext> BiasesP;

        encode(params.FC2Weights, WeightsP, env, FC2_SCALE);
        encode(params.FC2Biases, BiasesP, env, intermediateResultsE[0].scale * FC2_SCALE);
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
    decrypt(intermediateResultsE, res, env);

    return res;
}

int main()
{
    SealBfvEnvironment env = SealBfvEnvironment(
        POLY_MODULUS_DEGREE,
        PLAINTEXT_MODULUS);

    auto params = readParams();

    vector<vector<vector<double>>> data;
    vector<vector<size_t>> labels;
    readInput(POLY_MODULUS_DEGREE, 1.0 / 256.0, data, labels);

    // Batch processing

    size_t correct = 0;
    for (size_t batchIndex = 0; batchIndex < data.size(); batchIndex++)
    {
        // Encrypt
        vector<SealBfvCiphertext> inputE;
        auto decor = make_decorator(encrypt, "Encryption");
        decor(data[batchIndex], inputE, env, INPUT_SCALE);
        cout << "- Noise budget: " << env.environments[0].decryptorPtr->invariant_noise_budget(inputE[0].eVectors[0]) << endl;

        // Forward pass on the cloud
        std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
        auto res = cryptonets(params, inputE, env);
        std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        cout << setw(20) << "Total time: ";
        cout << elapsed_seconds.count() << " seconds" << std::endl;

        auto predictions = hardmax(res);

        for (size_t i = 0; i < predictions.size(); i++)
        {
            if (predictions[i] == labels[batchIndex][i])
            {
                correct++;
            }
        }

        cout << "Accuracy is " << correct << "/" << POLY_MODULUS_DEGREE;
        cout << "=" << (1.0 * correct)/POLY_MODULUS_DEGREE << endl;

        break;
    }

    return 0;
}