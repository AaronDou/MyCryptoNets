#include <gtest/gtest.h>

#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace testing;

class SealBenchmark : public ::testing::Test
{

protected:
    SealBenchmark()
    {
        poly_modulus_degree = 8192;

        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_modulus_degree));
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 18));

        auto context = SEALContext::Create(parms);
        KeyGenerator keygen(context);
        auto public_key = keygen.public_key();
        auto secret_key = keygen.secret_key();
        // relin_keys = keygen.relin_keys(60);
        relin_keys = keygen.relin_keys_local();

        encryptorPtr = make_shared<Encryptor>(context, public_key);
        decryptorPtr = make_shared<Decryptor>(context, secret_key);
        batchEncoderPtr = make_shared<BatchEncoder>(context);
        evaluatorPtr = make_shared<Evaluator>(context);
    }

    virtual ~SealBenchmark() {}

    RelinKeys relin_keys;

    shared_ptr<Encryptor> encryptorPtr;
    shared_ptr<Decryptor> decryptorPtr;
    shared_ptr<Evaluator> evaluatorPtr;
    shared_ptr<BatchEncoder> batchEncoderPtr;
    size_t poly_modulus_degree;
};

TEST_F(SealBenchmark, CiphetextMultNoiseBudget)
{
    vector<uint64_t> data(poly_modulus_degree, 2);
    Plaintext temp;
    batchEncoderPtr->encode(data, temp);
    Ciphertext dataE;
    encryptorPtr->encrypt(temp, dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->square_inplace(dataE);
    evaluatorPtr->relinearize_inplace(dataE, relin_keys);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->square_inplace(dataE);
    evaluatorPtr->relinearize_inplace(dataE, relin_keys);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->square_inplace(dataE);
    evaluatorPtr->relinearize_inplace(dataE, relin_keys);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->square_inplace(dataE);
    evaluatorPtr->relinearize_inplace(dataE, relin_keys);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;
}

TEST_F(SealBenchmark, PlaintextMultNoiseBudget)
{
    vector<uint64_t> data(poly_modulus_degree, 2);
    Plaintext temp;
    batchEncoderPtr->encode(data, temp);
    Ciphertext dataE;
    encryptorPtr->encrypt(temp, dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->multiply_plain_inplace(dataE, temp);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->multiply_plain_inplace(dataE, temp);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->multiply_plain_inplace(dataE, temp);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->multiply_plain_inplace(dataE, temp);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;
}

TEST_F(SealBenchmark, CiphertextAddNoiseBudget)
{
    vector<uint64_t> data(poly_modulus_degree, 2);
    Plaintext temp;
    batchEncoderPtr->encode(data, temp);
    Ciphertext dataE;
    encryptorPtr->encrypt(temp, dataE);

    vector<uint64_t> data1(poly_modulus_degree, 3);
    Plaintext temp1;
    batchEncoderPtr->encode(data1, temp1);
    Ciphertext dataE1;
    encryptorPtr->encrypt(temp1, dataE1);

    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->add_inplace(dataE, dataE1);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->add_inplace(dataE, dataE1);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->add_inplace(dataE, dataE1);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->add_inplace(dataE, dataE1);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;
}

TEST_F(SealBenchmark, ModulusSwitching)
{
    vector<uint64_t> data(poly_modulus_degree, 2);
    Plaintext temp;
    batchEncoderPtr->encode(data, temp);
    Ciphertext dataE;
    encryptorPtr->encrypt(temp, dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->mod_switch_to_next_inplace(dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->mod_switch_to_next_inplace(dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;

    evaluatorPtr->mod_switch_to_next_inplace(dataE);
    cout << decryptorPtr->invariant_noise_budget(dataE) << endl;
}


int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
