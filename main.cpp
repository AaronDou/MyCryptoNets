
#include "core.h"

using namespace std;
using namespace seal;
using namespace mycryptonets;

int main()
{
    // auto weights = readWeights();
    // auto input = readInput(1.0 / 256.0, 16.0);
    // uint64_t plain_modulus = 549764251649; // 549764284417
    // size_t poly_modulus_degree = 8192;
    // cryptonets(weights, input, plain_modulus, poly_modulus_degree);
    // SealBFVEnvironment env;

    return 0;
}

void cryptonets(const Weights &weight, const vector<vector<uint64_t>> &input, uint64_t plain_modulus, size_t poly_modulus_degree)
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
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plain_modulus);

    auto context = SEALContext::Create(parms);
    KeyGenerator keygen(context);
    IntegerEncoder encoder(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    auto time_norelin_start = chrono::high_resolution_clock::now();

    cout << "Generating weights plaintext for Conv 1 ..." << endl;
    size_t p_len = 5 * 25;
    vector<Plaintext> p_conv_vec;
    for (int idx = 0; idx < p_len; idx++)
    {
        Plaintext enc_rval = encoder.encode((rand() % 10) + 1);
        p_conv_vec.emplace_back(enc_rval);
    }

    int c_len = 169 * 25;
    vector<Ciphertext> c_conv_vec;
    for (int idx = 0; idx < c_len; idx++)
    {
        Plaintext enc_rval = encoder.encode((rand() % 5) + 1);
        Ciphertext prval;
        encryptor.encrypt(enc_rval, prval);
        c_conv_vec.emplace_back(prval);
    }

    cout << "...pseudo-weights for Conv 1 complete" << endl;

    //conv 1: 5X169 <- 5X25 * 25X169, convert conv to matrix multiplication
    cout << "Calculating Conv 1 ..." << endl;
    int dot_len = 25;
    vector<Ciphertext> conv_out;
    for (int i = 0; i < p_len; i += dot_len)
    {
        for (int j = 0; j < c_len; j += dot_len)
        {
            vector<Ciphertext> dots;
            for (int x = 0; x < dot_len; x++)
            {
                Ciphertext c_tpm;
                evaluator.multiply_plain(c_conv_vec[j + x], p_conv_vec[i + x], c_tpm);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum;
            evaluator.add_many(dots, dotsum);
            conv_out.emplace_back(dotsum);
        }
    }

    p_conv_vec.clear();
    c_conv_vec.clear();

    //act: square
    cout << "...Conv 1 is done" << endl;

    cout << "Calculating activation layer 1 (square)..." << endl;
    vector<Ciphertext> act_out;
    for (vector<Ciphertext>::iterator it = conv_out.begin(); it != conv_out.end(); ++it)
    {
        Ciphertext c_tpm;
        evaluator.square(*it, c_tpm);
        act_out.emplace_back(c_tpm);
    }

    conv_out.clear();
    cout << "...Activation layer 1 is done" << endl;

    //mean_pool: 100X1 <- 100X845 * 845X1, convert pool to matrix multiplication
    //!!!I remove pool layer here, as the mean pool is in fact a CONV operation.
    //!!!To evalute the accuracy performance, you should add this mean pooling layer

    cout << "Calculating pool + linear..." << endl;

    //Generating pseudo-weights
    p_len = 100 * 845;
    vector<Plaintext> p_pool_vec;
    for (int idx = 0; idx < p_len; idx++)
    {
        Plaintext enc_rval = encoder.encode((rand() % 7) + 1);
        p_pool_vec.emplace_back(enc_rval);
    }
    // pseudo-weights complete

    dot_len = 845;
    c_len = 845 * 1; // act_out.size()
    vector<Ciphertext> pool_out;
    for (int i = 0; i < p_len; i += dot_len)
    {
        for (int j = 0; j < c_len; j += dot_len)
        {
            vector<Ciphertext> dots;
            for (int x = 0; x < dot_len; x++)
            {
                //cout << j+x<<"  "<<i+x << endl;
                Ciphertext c_tpm;
                evaluator.multiply_plain(act_out[j + x], p_pool_vec[i + x], c_tpm);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum;
            evaluator.add_many(dots, dotsum);
            pool_out.emplace_back(dotsum);
        }
    }
    act_out.clear();
    p_pool_vec.clear();

    cout << "...Pool+Linear layer  is done" << endl;

    //act 2

    cout << "Calculating activation layer 2 (square)..." << endl;
    vector<Ciphertext> act_out_2;
    for (vector<Ciphertext>::iterator it = pool_out.begin(); it != pool_out.end(); ++it)
    {
        Ciphertext c_tpm;
        evaluator.square(*it, c_tpm);
        act_out_2.emplace_back(c_tpm);
    }

    pool_out.clear();
    cout << "...Activation layer 2 is done" << endl;

    //FC: 10X1<- 10X100 * 100X1
    cout << "Calculating FC layer..." << endl;

    //Generating pseudo-weights
    p_len = 10 * 100;
    vector<Plaintext> p_fc_vec;
    for (int idx = 0; idx < p_len; idx++)
    {
        Plaintext enc_rval = encoder.encode((rand() % 9) + 1);
        p_fc_vec.emplace_back(enc_rval);
    }
    // pseudo-weights complete

    dot_len = 100;
    c_len = 100 * 1; // act_out_2.size()
    vector<Ciphertext> fc_out;
    for (int i = 0; i < p_len; i += dot_len)
    {
        for (int j = 0; j < c_len; j += dot_len)
        {
            vector<Ciphertext> dots;
            for (int x = 0; x < dot_len; x++)
            {
                Ciphertext c_tpm;
                evaluator.multiply_plain(act_out_2[j + x], p_fc_vec[i + x], c_tpm);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum;
            evaluator.add_many(dots, dotsum);
            fc_out.emplace_back(dotsum);
        }
    }

    cout << "...FC layer  is done" << endl;

    //add decrypts here... if you want

    auto time_norelin_end = chrono::high_resolution_clock::now();
    cout << "Time of CryptoNets: " << chrono::duration_cast<chrono::microseconds>(time_norelin_end - time_norelin_start).count() / (1000 * 1000.0)
         << " seconds" << endl;
    return;
}