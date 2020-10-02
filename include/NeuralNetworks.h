#include "SealBfvVector.h"

namespace mycryptonets
{
    void fc(vector<SealBfvCiphertext *> inputPtr,
            vector<SealBfvPlaintext *> weightsPtr,
            vector<SealBfvPlaintext *> biasesPtr,
            size_t dotLen,
            vector<SealBfvCiphertext> &destination,
            const SealBfvEnvironment &env)
    {
        assert((inputPtr.size() * weightsPtr.size()) % (dotLen * dotLen) == 0);
        destination = vector<SealBfvCiphertext>{
            (inputPtr.size() * weightsPtr.size()) / (dotLen * dotLen),
            SealBfvCiphertext()};

        for (size_t i = 0; i < weightsPtr.size(); i += dotLen)
        {
            for (size_t j = 0; j < inputPtr.size(); j += dotLen)
            {
                vector<SealBfvCiphertext> dots;
                for (size_t x = 0; x < dotLen; x++)
                {
                    SealBfvCiphertext temp;
                    if (weightsPtr[i + x]->is_zero()){
                        continue;
                    }
                    multiply_plain(*inputPtr[j + x], *weightsPtr[i + x], temp, env);
                    dots.emplace_back(move(temp));
                }
                size_t idx = (i / dotLen) + (j / dotLen);
                add_many(dots, destination[idx], env);
                add_plain_inplace(destination[idx], *biasesPtr[i / dotLen], env);
            }
        }
    }
} // namespace mycryptonets