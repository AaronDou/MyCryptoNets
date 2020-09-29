#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <regex>

#include "seal/seal.h"

using namespace std;
using namespace seal;

struct Weights
{
    vector<double> convWeights;
    vector<double> FC1Weights;
    vector<double> FC1Biases;
    vector<double> FC2Weights;
    vector<double> FC2Biases;
};

void cryptonets(const Weights &, const vector<vector<uint64_t>> &, uint64_t, size_t);
Weights readWeights();
vector<vector<uint64_t>> readInput(double, double);
void test();

int main()
{
    // auto weights = readWeights();
    // auto input = readInput(1.0 / 256.0, 16.0);
    // uint64_t plain_modulus = 549764251649; // 549764284417
    // size_t poly_modulus_degree = 8192;
    // cryptonets(weights, input, plain_modulus, poly_modulus_degree);

    test();

    return 0;
}

vector<double> split(const string &s, char delim)
{
    vector<double> elems;
    istringstream iss(s);
    string item;
    while (getline(iss, item, delim))
    {
        elems.push_back(stod(item));
    }
    return elems;
}

vector<int> extractIntegers(const string &s)
{
    std::regex r("([0-9]+)");
    std::vector<int> results;
    for (std::sregex_iterator i = std::sregex_iterator(s.begin(), s.end(), r);
         i != std::sregex_iterator();
         ++i)
    {
        std::smatch m = *i;
        results.push_back(std::stod(m[1].str().c_str()));
    }
    return results;
}

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
    // 7	784	202:84	203:185	204:159	205:151	206:60	207:36	230:222	231:254	232:254	233:254	234:254	235:241	236:198	237:198	238:198	239:198	240:198	241:198	242:198	243:198	244:170	245:52	258:67	259:114	260:72	261:114	262:163	263:227	264:254	265:225	266:254	267:254	268:254	269:250	270:229	271:254	272:254	273:140	291:17	292:66	293:14	294:67	295:67	296:67	297:59	298:21	299:236	300:254	301:106	326:83	327:253	328:209	329:18	353:22	354:233	355:255	356:83	381:129	382:254	383:238	384:44	408:59	409:249	410:254	411:62	436:133	437:254	438:187	439:5	463:9	464:205	465:248	466:58	491:126	492:254	493:182	518:75	519:251	520:240	521:57	545:19	546:221	547:254	548:166	572:3	573:203	574:254	575:219	576:35	600:38	601:254	602:254	603:77	627:31	628:224	629:254	630:115	631:1	655:133	656:254	657:254	658:52	682:61	683:242	684:254	685:254	686:52	710:121	711:254	712:254	713:219	714:40	738:121	739:254	740:207	741:18
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


void square(Evaluator& evaluator, const RelinKeys& relin_keys, vector<Ciphertext> input) {
    for (vector<Ciphertext>::iterator it = input.begin(); it != input.end(); ++it)
    {
        evaluator.square_inplace(*it);
        evaluator.relinearize_inplace(*it, relin_keys);
    }
}

void test() {
     EncryptionParameters parms(scheme_type::BFV);
     size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plain_modulus);

    auto context = SEALContext::Create(parms);
    IntegerEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
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
    IntegerEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    auto time_norelin_start = chrono::high_resolution_clock::now();

    cout << "Generating weights plaintext for Conv 1 ..." << endl;
    int p_len = 5 * 25;
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