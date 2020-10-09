#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <regex>
#include <omp.h>
#include <cmath>
#include <cassert>

#include "seal/seal.h"
#include "Util.h"

using namespace std;
using namespace seal;

namespace mycryptonets
{
    struct AtomicSealBfvEnvironment
    {
        /*
        * Parameter selections
        * First pick a good plaintext modulus so that computation won't overflow
        * Depth is roughly determined by log2(Q/t) - 1. For more depth, increase Q (coeff_modulus). 
        *    - Fine tune Q by adopting trial-and-error
        *    - Specifically, start from a modestly small Q, evaluate the circuit. If it fails, then increase Q and so on.
        * Choose n based on Q according to the expected security level.
        *    - There's a map from homomorphicencryption.org
        */
        AtomicSealBfvEnvironment() = default;

        AtomicSealBfvEnvironment(size_t poly_modulus_degree, uint64_t plain_modulus)
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(poly_modulus_degree);
            // version 3.2.1
            // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_modulus_degree));
            // version 3.5+
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            parms.set_plain_modulus(plain_modulus);

            context = SEALContext::Create(parms);
            KeyGenerator keygen(context);
            public_key = keygen.public_key();
            secret_key = keygen.secret_key();
            // version 3.2.1
            // relin_keys = keygen.relin_keys(10);
            // version 3.5+
            relin_keys = keygen.relin_keys_local();

            encryptorPtr = make_shared<Encryptor>(context, public_key);
            decryptorPtr = make_shared<Decryptor>(context, secret_key);
            batchEncoderPtr = make_shared<BatchEncoder>(context);
            evaluatorPtr = make_shared<Evaluator>(context);
        }
        ~AtomicSealBfvEnvironment() {}

        shared_ptr<SEALContext> context;
        PublicKey public_key;
        SecretKey secret_key;
        RelinKeys relin_keys;

        shared_ptr<Encryptor> encryptorPtr;
        shared_ptr<Decryptor> decryptorPtr;
        shared_ptr<Evaluator> evaluatorPtr;
        shared_ptr<BatchEncoder> batchEncoderPtr;
    };

    struct SealBfvEnvironment
    {
        SealBfvEnvironment() = default;
        SealBfvEnvironment(size_t poly_modulus_degree, vector<Modulus> plain_modulus)
            : poly_modulus_degree(poly_modulus_degree)
        {
            vector<uint64_t> plain_modulus_uint64;
            transform(plain_modulus.begin(),
                      plain_modulus.end(),
                      back_inserter(plain_modulus_uint64),
                      [](const Modulus &modulus) { return modulus.value(); });
            set(poly_modulus_degree, plain_modulus_uint64);
        }
        SealBfvEnvironment(size_t poly_modulus_degree, vector<uint64_t> plain_modulus)
            : poly_modulus_degree(poly_modulus_degree)
        {
            set(poly_modulus_degree, plain_modulus);
        }
        ~SealBfvEnvironment() {}

        void set(size_t poly_modulus_degree, vector<uint64_t> plain_modulus)
        {
            uIntBigFactor = BigUInt("1");

            for (auto plain_modulo : plain_modulus)
            {
                environments.emplace_back(poly_modulus_degree, plain_modulo);
                auto factor = to_hex(plain_modulo);
                uIntBigFactor *= factor;
                factors.emplace_back(move(factor));
            }
            for (auto &factor : factors)
            {
                auto minor = uIntBigFactor / factor;
                BigUInt rem;
                minor.divrem(factor, rem);
                auto ys = rem.modinv(factor);
                preComputedCoefficients.emplace_back(ys * minor);
            }
        }

        size_t poly_modulus_degree;
        vector<BigUInt> factors;
        vector<AtomicSealBfvEnvironment> environments;
        BigUInt uIntBigFactor;
        vector<BigUInt> preComputedCoefficients;
    };

    vector<uint64_t> splitBigNumbers(
        double num, double scale, const SealBfvEnvironment &env)
    {
        size_t envCount = env.environments.size();
        vector<uint64_t> res(envCount, 0);

        auto w = (long long)round(num * scale);
        BigUInt z = w < 0 ? env.uIntBigFactor - (uint64_t)abs(w) : BigUInt(to_hex(w));

        for (size_t i = 0; i < envCount; i++)
        {
            BigUInt temp;
            z.divrem(env.factors[i], temp);
            res[i] = (uint64_t)temp.to_double();
        }

        return res;
    }

    double joinSplitNumbers(const vector<uint64_t> &split, const SealBfvEnvironment &env)
    {
        BigUInt res("0");
        for (size_t i = 0; i < env.environments.size(); i++)
        {
            res += env.preComputedCoefficients[i] * split[i];
        }
        res.divrem(env.uIntBigFactor, res);
        if (res * 2 > env.uIntBigFactor)
        {
            return -1 * (env.uIntBigFactor - res).to_double();
        }
        return res.to_double();
    }

    // A wrapper class for Ciphertext with CRT
    struct SealBfvCiphertext
    {
        SealBfvCiphertext() = default;
        SealBfvCiphertext(const vector<double> &m,
                          const SealBfvEnvironment &env,
                          double scale = 1.0) : batchSize(m.size()), scale(scale)
        {
            size_t envCount = env.environments.size();
            assert(envCount > 0);
            vector<vector<uint64_t>> split(envCount, vector<uint64_t>(batchSize, 0));
            for (size_t i = 0; i < batchSize; i++)
            {
                auto temp = splitBigNumbers(m[i], scale, env);
                for (size_t j = 0; j < envCount; j++)
                {
                    split[j][i] = temp[j];
                }
            }
            for (size_t j = 0; j < envCount; j++)
            {
                Plaintext temp_p;
                env.environments[j].batchEncoderPtr->encode(split[j], temp_p);
                Ciphertext temp_c;
                env.environments[j].encryptorPtr->encrypt(move(temp_p), temp_c);
                eVectors.emplace_back(move(temp_c));
            }
        }

        ~SealBfvCiphertext() {}

        vector<double> decrypt(const SealBfvEnvironment &env) const
        {

            size_t envCount = eVectors.size();
            vector<vector<uint64_t>> split(batchSize, vector<uint64_t>(envCount, 0));

            for (size_t j = 0; j < envCount; j++)
            {
                Plaintext temp_p;
                env.environments[j].decryptorPtr->decrypt(eVectors[j], temp_p);
                vector<uint64_t> temp_vec;
                env.environments[j].batchEncoderPtr->decode(move(temp_p), temp_vec);
                for (size_t i = 0; i < batchSize; i++)
                {
                    split[i][j] = temp_vec[i];
                }
            }

            vector<double> res(batchSize, 0.0);
            for (size_t i = 0; i < batchSize; i++)
            {
                res[i] = joinSplitNumbers(split[i], env) / scale;
            }
            return res;
        }

        vector<Ciphertext> eVectors;
        double scale;
        size_t batchSize;
    };

    // A wrapper class for Plaintext with CRT
    struct SealBfvPlaintext
    {
        SealBfvPlaintext() = default;

        SealBfvPlaintext(double m,
                         const SealBfvEnvironment &env,
                         double scale = 1.0) : scale(scale)
        {
            vector<uint64_t> split = splitBigNumbers(m, scale, env);
            for (auto num : split)
            {
                pVectors.emplace_back(to_hex(num));
            }
        }

        ~SealBfvPlaintext() {}

        bool is_zero()
        {
            return all_of(pVectors.begin(),
                          pVectors.end(),
                          [](Plaintext &p) { return p.is_zero(); });
        }

        vector<Plaintext> pVectors;
        double scale;
    };

    void square_inplace(
        SealBfvCiphertext &ciphertext,
        const SealBfvEnvironment &env)
    {

        for (size_t i = 0; i < env.environments.size(); i++)
        {
            env.environments[i].evaluatorPtr->square_inplace(ciphertext.eVectors[i]);
            env.environments[i].evaluatorPtr->relinearize_inplace(ciphertext.eVectors[i], env.environments[i].relin_keys);
        }
        ciphertext.scale *= ciphertext.scale;
    }

    void mod_switch_to_next_inplace(
        SealBfvCiphertext &ciphertext,
        const SealBfvEnvironment &env)
    {
        for (size_t i = 0; i < env.environments.size(); i++)
        {
            env.environments[i].evaluatorPtr->mod_switch_to_next_inplace(
                ciphertext.eVectors[i]);
        }
    }

    void multiply_plain(
        const SealBfvCiphertext &ciphertext,
        const SealBfvPlaintext &plaintext,
        SealBfvCiphertext &destination,
        const SealBfvEnvironment &env)
    {
        size_t envCount = env.environments.size();
        vector<Ciphertext> eVectors(envCount, Ciphertext());

        for (size_t i = 0; i < envCount; i++)
        {
            env.environments[i].evaluatorPtr->multiply_plain(ciphertext.eVectors[i],
                                                             plaintext.pVectors[i],
                                                             eVectors[i]);
        }
        destination.eVectors = move(eVectors);
        destination.scale = ciphertext.scale * plaintext.scale;
        destination.batchSize = ciphertext.batchSize;
    }

    void add_many(
        const vector<SealBfvCiphertext> &ciphertexts,
        SealBfvCiphertext &destination,
        const SealBfvEnvironment &env)
    {
        assert(ciphertexts.size() > 0);
        //TODO assert all the scales are equal

        size_t envCount = env.environments.size();
        vector<Ciphertext> eVectors(envCount, Ciphertext());

        for (size_t i = 0; i < envCount; i++)
        {
            eVectors[i] = ciphertexts[0].eVectors[i];
            for (size_t j = 1; j < ciphertexts.size(); j++)
            {
                env.environments[i].evaluatorPtr->add_inplace(eVectors[i], ciphertexts[j].eVectors[i]);
            }
        }
        destination.eVectors = move(eVectors);
        destination.scale = ciphertexts[0].scale;
        destination.batchSize = ciphertexts[0].batchSize;
    }

    void add_plain_inplace(
        SealBfvCiphertext &ciphertext,
        const SealBfvPlaintext &plaintext,
        const SealBfvEnvironment &env)
    {
        assert(ciphertext.scale == plaintext.scale);

        for (size_t i = 0; i < env.environments.size(); i++)
        {
            env.environments[i].evaluatorPtr->add_plain_inplace(ciphertext.eVectors[i], plaintext.pVectors[i]);
        }
    }

} // namespace mycryptonets