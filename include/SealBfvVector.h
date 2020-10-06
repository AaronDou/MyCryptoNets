#pragma once

#include "SealBfvCrtWrapper.h"

namespace mycryptonets
{
    void square_inplace_vec(vector<SealBfvCiphertext> &ciphertexts,
                        const SealBfvEnvironment &env)
    {
        for (size_t i = 0; i < ciphertexts.size(); i++)
        {
            square_inplace(ciphertexts[i], env);
        }
    }

    void encrypt_vec(const vector<vector<double>> &data,
                 vector<SealBfvCiphertext> &ciphertexts,
                 const SealBfvEnvironment &env,
                 double scale = 1.0)
    {
        size_t size = data.size();
        ciphertexts = vector<SealBfvCiphertext>(size, SealBfvCiphertext());

        for (size_t i = 0; i < size; i++)
        {
            ciphertexts[i] = SealBfvCiphertext(data[i], env, scale);
        }
    }

    void decrypt_vec(const vector<SealBfvCiphertext> &ciphertexts,
                 vector<vector<double>> &data,
                 const SealBfvEnvironment &env)
    {
        size_t size = ciphertexts.size();
        assert(size > 0);
        data = vector<vector<double>>(size, {0});

        for (size_t i = 0; i < size; i++)
        {
            data[i] = ciphertexts[i].decrypt(env);
        }
    }

    // Not for batch processing
    void singleCoefficientEncode_vec(
        const vector<double> &data,
        vector<SealBfvPlaintext> &plaintexts,
        const SealBfvEnvironment &env,
        double scale = 1.0)
    {
        size_t size = data.size();
        plaintexts = vector<SealBfvPlaintext>(size, SealBfvPlaintext());

        for (size_t i = 0; i < size; i++)
        {
            plaintexts[i] = SealBfvPlaintext(data[i], env, scale);
        }
    }

} // namespace mycryptonets