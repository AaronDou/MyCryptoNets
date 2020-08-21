#include "seal/seal.h"
#include "util.h"

using namespace std;
using namespace seal;

int main() {
    // Client side
    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(1024);
    // Params selection procedure for BFV
    // 1. Determine plain modulus and coeff modulus
    // 2. Determine poly_modulus_degree

    auto context = SEALContext::Create(params);
    print_parameters(context);

    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);

    int x = 1;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;
    
    Plaintext x_decrypted;
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

    // Server side
    Evaluator evaluator(context);
    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one);
    Plaintext one_plain("1");
    evaluator.add_plain_inplace(x_sq_plus_one, one_plain);
    cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
         << endl;
    
    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, one_plain, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
         << endl;
    
    Ciphertext encrypted_result;
    Plaintext plain_four("4");
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    evaluator.multiply_plain_inplace(encrypted_result, plain_four);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
         << endl;
    
    // Server side
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    cout << "0x" << plain_result.to_string() << " ...... Correct." << endl;

    RelinKeys relinkeys = keygen.relin_keys_local();

    // Client side
    evaluator.square(x_encrypted, x_sq_plus_one);
    evaluator.relinearize_inplace(x_sq_plus_one, relinkeys);
    evaluator.add_plain_inplace(x_sq_plus_one, one_plain);
    cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
         << endl;
    
    evaluator.add_plain(x_encrypted, one_plain, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);
    evaluator.relinearize_inplace(x_plus_one_sq, relinkeys);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
         << endl;
    
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    evaluator.multiply_plain_inplace(encrypted_result, plain_four);
    evaluator.relinearize_inplace(encrypted_result, relinkeys);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
         << endl;

    decryptor.decrypt(encrypted_result, plain_result);
    cout << "0x" << plain_result.to_string() << " ...... Correct." << endl;


    IntegerEncoder encoder(context);
    auto encoded = encoder.encode(65);
    cout << encoded.to_string();


    return 0;
}