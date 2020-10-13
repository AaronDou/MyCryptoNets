#pragma once

#include <math.h>

#include "SealBfvVector.h"

namespace mycryptonets
{
    void conv2d(vector<SealBfvCiphertext> patches,
                vector<vector<SealBfvPlaintext>> weights,
                vector<SealBfvPlaintext> biases,
                vector<SealBfvCiphertext> &destination,
                const SealBfvEnvironment &env)
    {
        size_t channels = weights.size();
        destination = vector<SealBfvCiphertext>(channels, SealBfvCiphertext());

#pragma omp parallel for
        for (size_t i = 0; i < channels; i++)
        {
            dot_product(patches, weights[i], destination[i], env);
            add_plain_inplace(destination[i], biases[i], env);
        }
    }

    // Organize a 28*28 image into patches that are ready for convolving.
    template <typename T>
    void convolutionOrganizer(
        const vector<T> &data,
        size_t kernelDim,
        size_t stride,
        size_t padding, // to the right bottom direction
        vector<vector<T>> &patches,
        T filler)
    {
        size_t dim = (size_t)sqrt(data.size());
        size_t outputDim = (dim + padding - kernelDim) / stride + 1;
        size_t kernelSize = kernelDim * kernelDim;
        patches = vector<vector<T>>(
            kernelSize,
            vector<T>(outputDim * outputDim, filler));

#pragma omp parallel for
        for (size_t i = 0; i < outputDim; i++)
        {
            for (size_t j = 0; j < outputDim; j++)
            {
                for (size_t x = 0; x < kernelDim; x++)
                {
                    for (size_t y = 0; y < kernelDim; y++)
                    {
                        size_t row = i * stride + x;
                        size_t col = j * stride + y;
                        if (row < dim && col < dim)
                        {
                            patches[x * kernelDim + y][(i * outputDim) + j] =
                                data[row * dim + col];
                        }
                    }
                }
            }
        }
    }

} // namespace mycryptonets