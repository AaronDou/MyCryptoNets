#include <math.h>

#include "SealBfvVector.h"

namespace mycryptonets
{
    void fc(vector<SealBfvCiphertext *> inputPtr,
            vector<SealBfvPlaintext> weights,
            vector<SealBfvPlaintext> biases,
            size_t dotLen,
            vector<SealBfvCiphertext> &destination,
            const SealBfvEnvironment &env)
    {
        assert((inputPtr.size() * weights.size()) % (dotLen * dotLen) == 0);
        destination = vector<SealBfvCiphertext>{
            (inputPtr.size() * weights.size()) / (dotLen * dotLen),
            SealBfvCiphertext()};

        for (size_t i = 0; i < weights.size(); i += dotLen)
        {
            for (size_t j = 0; j < inputPtr.size(); j += dotLen)
            {
                vector<SealBfvCiphertext> dots;
                for (size_t x = 0; x < dotLen; x++)
                {
                    SealBfvCiphertext temp;
                    if (weights[i + x].is_zero() || inputPtr[j + x] == nullptr)
                    {
                        continue;
                    }
                    multiply_plain(*inputPtr[j + x], weights[i + x], temp, env);
                    dots.emplace_back(move(temp));
                }
                size_t idx = (i / dotLen) * inputPtr.size() / dotLen + (j / dotLen);
                add_many(dots, destination[idx], env);
                add_plain_inplace(destination[idx], biases[i / dotLen], env);
            }
        }
    }

    template <typename T>
    void convolutionOrganizer(
        vector<T> &data,
        size_t kernelDim,
        size_t stride,
        size_t padding, // to the right bottom direction
        vector<T *> &dataPTr)
    {
        size_t dim = (size_t)sqrt(data.size());
        size_t outputDim = (dim + padding - kernelDim) / stride + 1;
        size_t kernelSize = kernelDim * kernelDim;
        dataPTr = vector<T *>(outputDim * outputDim * kernelSize, nullptr);

        for (size_t i = 0; i < outputDim; i++)
        {
            for (size_t j = 0; j < outputDim; j++)
            {
                size_t start = ((i * outputDim) + j) * kernelSize;
                for (size_t x = 0; x < kernelDim; x++)
                {
                    for (size_t y = 0; y < kernelDim; y++)
                    {
                        size_t row = i * stride + x;
                        size_t col = j * stride + y;
                        dataPTr[start + x * kernelDim + y] =
                            row < dim && col < dim ? &data[row * dim + col] : nullptr;
                    }
                }
            }
        }
    }

    template <typename T>
    vector<size_t> hardmax(vector<vector<T>> input)
    {
        assert(input.size() > 0);
        vector<size_t> res (input[0].size(), 0);

        for (size_t i = 0; i < input[0].size(); i++)
        {
            T max = input[0][i];
            for (size_t j = 1; j < input.size(); j++)
            {
                if (input[j][i] > max) {
                    max = input[j][i];
                    res[i] = j;
                }
                
            }
        }
        return res;
    }
} // namespace mycryptonets