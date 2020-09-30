#include "HEWrapper.h"

namespace mycryptonets
{
    struct Weights
    {
        vector<double> convWeights;
        vector<double> FC1Weights;
        vector<double> FC1Biases;
        vector<double> FC2Weights;
        vector<double> FC2Biases;
    };
    
    // Return 785 * 10000 matrix
    // The top 784 rows are for input pixel values.
    // The bottom 1 row is for labels.
    vector<vector<uint64_t>> readInput(double normalizationFactor, double scale)
    {
        size_t numRows = 28 * 28 + 1;
        size_t numCols = 10000;
        vector<uint64_t> pixelBatch(numCols, 0);
        vector<vector<uint64_t>> input(numRows, pixelBatch);
        ifstream infile("/home/aaron/Dropbox/Projects/MyCryptoNets/MNIST-28x28-test.txt");
        if (!infile.is_open())
        {
            exit(1);
        }

        string line;
        size_t index = 0;
        while (getline(infile, line))
        {
            auto pairs = extractIntegers(line);
            input[numRows - 1][index] = pairs[0];

            for (size_t i = 2; i < pairs.size(); i += 2)
            {
                input[pairs[i]][index] = round(pairs[i + 1] * normalizationFactor * scale);
            }
            index++;
        }

        infile.close();

        return input;
    }

    Weights readWeights()
    {
        ifstream infile("/home/aaron/Dropbox/Projects/MyCryptoNets/LinerWeights.txt");
        if (!infile.is_open())
        {
            exit(1);
        }

        Weights weights;
        string line;

        getline(infile, line);
        weights.convWeights = split(line, ' ');

        getline(infile, line);
        weights.FC1Weights = split(line, ' ');
        getline(infile, line);
        weights.FC1Biases = split(line, ' ');

        getline(infile, line);
        weights.FC2Weights = split(line, ' ');
        getline(infile, line);
        weights.FC2Biases = split(line, ' ');

        infile.close();

        return weights;
    }

//     void square(SealBFVEnvironment &env, vector<Ciphertext> &input)
//     {
// #pragma omp parallel for
//         for (size_t i = 0; i < input.size(); i++)
//         {
//             env.evaluatorPtr->square_inplace(input[i]);
//             env.evaluatorPtr->relinearize_inplace(input[i], env.relin_keys);
//         }
//     }

//     vector<Ciphertext> fc(SealBFVEnvironment &env,
//                           const vector<Ciphertext> &input,
//                           const vector<Plaintext> &weights,
//                           const vector<Plaintext> &biases,
//                           size_t dotLen)
//     {
//         vector<Ciphertext> result;
//         for (size_t i = 0; i < weights.size(); i += dotLen)
//         {
//             for (size_t j = 0; j < input.size(); j += dotLen)
//             {
//                 vector<Ciphertext> dots;
//                 for (size_t x = 0; x < dotLen; x++)
//                 {
//                     Ciphertext temp;
//                     env.evaluatorPtr->multiply_plain(input[j + x], weights[i + x], temp);
//                     dots.emplace_back(temp);
//                 }
//                 Ciphertext dotsum;
//                 env.evaluatorPtr->add_many(dots, dotsum);
//                 env.evaluatorPtr->add_plain_inplace(dotsum, biases[i / dotLen]);
//                 result.emplace_back(move(dotsum));
//             }
//         }
//         return result;
//     }

//     vector<Plaintext> encode(SealBFVEnvironment &env, const vector<vector<uint64_t>> &input)
//     {
//         vector<Plaintext> result;
//         result.reserve(input.size());

//         for (size_t i = 0; i < input.size(); i++)
//         {
//             Plaintext temp_p;
//             env.batchEncoderPtr->encode(input[i], temp_p);
//             result.emplace_back(move(temp_p));
//         }
//         return result;
//     }

//     vector<vector<uint64_t>> decode(SealBFVEnvironment &env, const vector<Plaintext> &input)
//     {
//         vector<vector<uint64_t>> result;
//         result.reserve(input.size());

//         for (size_t i = 0; i < input.size(); i++)
//         {
//             vector<uint64_t> temp;
//             env.batchEncoderPtr->decode(input[i], temp);
//             result.emplace_back(move(temp));
//         }
//         return result;
//     }

//     vector<Ciphertext> encrypt(SealBFVEnvironment &env, const vector<Plaintext> &input)
//     {
//         vector<Ciphertext> result;
//         result.reserve(input.size());

//         for (size_t i = 0; i < input.size(); i++)
//         {
//             Ciphertext temp_c;
//             env.encryptorPtr->encrypt(input[i], temp_c);
//             result.emplace_back(move(temp_c));
//         }
//         return result;
//     }

//     vector<Plaintext> decrypt(SealBFVEnvironment &env, const vector<Ciphertext> &input)
//     {
//         vector<Plaintext> result;
//         result.reserve(input.size());

//         for (size_t i = 0; i < input.size(); i++)
//         {
//             Plaintext temp_p;
//             env.decryptorPtr->decrypt(input[i], temp_p);
//             result.emplace_back(move(temp_p));
//         }
//         return result;
//     }

} // namespace mycryptonets