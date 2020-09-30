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
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            parms.set_plain_modulus(plain_modulus);

            context = SEALContext::Create(parms);
            KeyGenerator keygen(context);
            public_key = keygen.public_key();
            secret_key = keygen.secret_key();
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
        SealBfvEnvironment(size_t poly_modulus_degree, vector<uint64_t> plain_modulus)
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
        ~SealBfvEnvironment() {}

        vector<BigUInt> factors;
        vector<AtomicSealBfvEnvironment> environments;
        BigUInt uIntBigFactor;
        vector<BigUInt> preComputedCoefficients;
    };

  

    // A wrapper class for Ciphertext with CRT
    struct SealBfvCiphertext
    {
        SealBfvCiphertext() = default;
        SealBfvCiphertext(const vector<double> &m,
                          const SealBfvEnvironment &env,
                          double scaleFactor = 1.0) : scale(scaleFactor)
        {
        }

        ~SealBfvCiphertext() {}

        // vector<double> decrypt(const SealBfvEnvironment &env) {}

        vector<Ciphertext> eVectors;
        double scale;
    };

    // A wrapper class for Plaintext with CRT
    struct SealBfvPlaintext
    {
        SealBfvPlaintext() = default;

        SealBfvPlaintext(double m,
                         const SealBfvEnvironment &env,
                         double scaleFactor = 1.0) : scale(scaleFactor) {}

        vector<Plaintext> pVectors;
        double scale;
    };

    // Maximum number support:
    vector<uint64_t> splitBigNumbers(double num, double scale, const SealBfvEnvironment &env)
    {
        size_t envCount = env.environments.size();
        vector<uint64_t> res{envCount, 0};

        auto w = (long long)round(num * scale);
        BigUInt z = w < 0 ? env.uIntBigFactor - (uint64_t)abs(w) : BigUInt(to_hex(w));

        for (size_t i = 0; i < envCount; i++)
        {
            BigUInt temp;
            z.divrem(env.factors[i], temp);
            res.emplace_back(stoul(temp.to_dec_string()));
        }

        return res;
    }

    // double joinSplitNumbers() {}

} // namespace mycryptonets