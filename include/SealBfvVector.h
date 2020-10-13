#pragma once

#include "SealBfvCrtWrapper.h"

namespace mycryptonets
{
    void square_inplace(vector<SealBfvCiphertext> &ciphertexts,
                        const SealBfvEnvironment &env)
    {
#pragma omp parallel for
        for (size_t i = 0; i < ciphertexts.size(); i++)
        {
            square_inplace(ciphertexts[i], env);
        }
    }

    void encrypt(const vector<vector<double>> &data,
                 vector<SealBfvCiphertext> &ciphertexts,
                 const SealBfvEnvironment &env,
                 double scale = 1.0)
    {
        size_t size = data.size();
        ciphertexts = vector<SealBfvCiphertext>(size, SealBfvCiphertext());

#pragma omp parallel for
        for (size_t i = 0; i < size; i++)
        {
            ciphertexts[i] = SealBfvCiphertext(data[i], env, scale);
        }
    }

    void decrypt(const vector<SealBfvCiphertext> &ciphertexts,
                 vector<vector<double>> &data,
                 const SealBfvEnvironment &env)
    {
        size_t size = ciphertexts.size();
        assert(size > 0);
        data = vector<vector<double>>(size, {0});

#pragma omp parallel for
        for (size_t i = 0; i < size; i++)
        {
            data[i] = ciphertexts[i].decrypt(env);
        }
    }

    void encode(
        const vector<double> &data,
        vector<SealBfvPlaintext> &plaintexts,
        const SealBfvEnvironment &env,
        double scale = 1.0)
    {
        size_t size = data.size();
        plaintexts = vector<SealBfvPlaintext>(size, SealBfvPlaintext());

#pragma omp parallel for
        for (size_t i = 0; i < size; i++)
        {
            plaintexts[i] = SealBfvPlaintext(data[i], env, scale);
        }
    }

    void batch_encode(
        const vector<vector<double>> &data,
        vector<SealBfvPlaintext> &plaintexts,
        const SealBfvEnvironment &env,
        double scale = 1.0)
    {
        size_t size = data.size();
        plaintexts = vector<SealBfvPlaintext>(size, SealBfvPlaintext());

#pragma omp parallel for
        for (size_t i = 0; i < size; i++)
        {
            plaintexts[i] = SealBfvPlaintext(data[i], env, scale);
        }
    }

    void dot_product(
        const vector<SealBfvCiphertext> &ciphertexts,
        const vector<SealBfvPlaintext> &plaintexts,
        SealBfvCiphertext &destination,
        const SealBfvEnvironment &env)
    {
        vector<SealBfvCiphertext> products;

        for (size_t i = 0; i < ciphertexts.size(); i++)
        {
            // Prevent transparent ciphertexts
            if (plaintexts[i].is_zero())
                continue;
            SealBfvCiphertext temp;
            multiply_plain(ciphertexts[i], plaintexts[i], temp, env);
            products.emplace_back(move(temp));
        }

        if (products.size() > 0)
        {
            add_many(products, destination, env);
        }
        else
        {
            destination = move(SealBfvCiphertext(vector<double>(ciphertexts[0].batchSize, 0.0),
                                                 env,
                                                 ciphertexts[0].scale * plaintexts[0].scale));
        }
    }

    // Stack multiple ciphertexts of the same batchSize into one new ciphertext by rotation.
    void stack(const vector<SealBfvCiphertext> &ciphertexts,
               SealBfvCiphertext &destination,
               const SealBfvEnvironment &env)
    {
        assert (ciphertexts.size() > 0);
        size_t stackedBatchSize = ciphertexts[0].batchSize * ciphertexts.size();
        assert (stackedBatchSize < env.poly_modulus_degree);

        
    }

    // Replicate
    void replicate(const SealBfvCiphertext &destination,
                   size_t count,
                   const SealBfvEnvironment &env) {}

} // namespace mycryptonets