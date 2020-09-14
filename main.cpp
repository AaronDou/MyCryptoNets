#include <iostream>
#include <chrono>
#include <thread>
#include <torch/script.h>
#include <torch/torch.h>

#include "seal/seal.h"
#include "util.h"
#include "xtensor/xarray.hpp"
#include "xtensor/xio.hpp"
#include "xtensor/xview.hpp"
#include "xtensor/xadapt.hpp"
#include "xtensor/xfixed.hpp"

using namespace std;
using namespace seal;

const std::string MODULE_PATH = "/home/aaron/Dropbox/Projects/Tenseal/model/mnist_script_model.pt";

struct ModelParameters
{
     xt::xtensor_fixed<Plaintext, xt::xshape<3>> conv_weight; // 5 * 5 * 5
     xt::xtensor_fixed<Plaintext, xt::xshape<1>> conv_bias;   // 5

     xt::xtensor_fixed<Plaintext, xt::xshape<2>> fc1_weight; // 845 * 100
     xt::xtensor_fixed<Plaintext, xt::xshape<1>> fc1_bias;   // 100

     xt::xtensor_fixed<Plaintext, xt::xshape<2>> fc2_weight; // 100 * 10
     xt::xtensor_fixed<Plaintext, xt::xshape<1>> fc2_bias;   // 10
};

torch::jit::script::Module loadModule()
{
     torch::jit::script::Module module;
     try
     {
          // Deserialize the ScriptModule from a file using torch::jit::load().
          module = torch::jit::load(MODULE_PATH);
     }
     catch (const c10::Error &e)
     {
          std::cerr << "error loading the model: " << e.what();
          throw;
     }
     return module;
}

template <typename T>
void encodeFromTensor(IntegerEncoder &encoder, const at::Tensor &tensor, const int64_t scale, xt::xtensor_fixed<Plaintext, T> &encodedTensor)
{
     auto scaledTensor = torch::round(torch::squeeze(pair.value) * scale);
     for ()
     encoder.encode(int(*(params.index({2, 0, 0}).data_ptr<float>())), value);
     mp.conv_weight(2, 0, 0) = value;
     std::cout << pair.name << ": " << params.sizes() << std::endl;
     cout << mp.conv_weight(2, 0, 0).to_string() << endl;
     cout << encoder.decode_int32(mp.conv_weight(2, 0, 0));
}

void encodeModelParameters(IntegerEncoder &encoder, const torch::jit::script::Module &module, const int64_t scale, ModelParameters &mp)
{
     for (const auto &pair : module.named_parameters())
     {
          encodeFromTensor<xt::xshape<3>>(encoder, pair.value, scale, mp.conv_weight);

          break;
     }
}

int main()
{
     EncryptionParameters parms(scheme_type::BFV);
     size_t poly_modulus_degree = 4096;
     parms.set_poly_modulus_degree(poly_modulus_degree);
     parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
     parms.set_plain_modulus(1024);

     auto context = SEALContext::Create(parms);
     KeyGenerator keygen(context);
     PublicKey public_key = keygen.public_key();
     SecretKey secret_key = keygen.secret_key();
     RelinKeys relin_keys = keygen.relin_keys_local();
     Encryptor encryptor(context, public_key);
     Evaluator evaluator(context);
     Decryptor decryptor(context, secret_key);
     IntegerEncoder encoder(context);

     auto module = loadModule();
     ModelParameters mp;
     encodeModelParameters(encoder, module, 1e3, mp);

     // const size_t load = 200;

     // // Prepare weight
     // xt::xtensor_fixed<Plaintext, xt::xshape<load, load>> weight{};
     // for (size_t i = 0; i < weight.size(); i++)
     // {
     //      // CAVEAT: multiply plaintext 0 doesn't make sense and is not allowed
     //      weight(i / load, i % load) = encoder.encode(i + 1);
     // }

     // // Prepare bias
     // xt::xtensor_fixed<Plaintext, xt::xshape<load>> bias{};
     // for (auto &it : bias)
     // {
     //      it = encoder.encode(5);
     // }

     // // Prepare x
     // xt::xtensor_fixed<Plaintext, xt::xshape<load>> x{};
     // for (size_t i = 0; i < x.size(); i++)
     // {
     //      x(i) = encoder.encode(i);
     // }

     // // Encrypt
     // xt::xtensor_fixed<Ciphertext, xt::xshape<load>> x_encrypted{};
     // for (size_t i = 0; i < x_encrypted.size(); i++)
     // {
     //      encryptor.encrypt(x(i), x_encrypted(i));
     // }

     // xt::xtensor_fixed<Ciphertext, xt::xshape<load>> result_encrypted{};
     // for (size_t i = 0; i < result_encrypted.size(); i++)
     // {
     //      encryptor.encrypt(encoder.encode(0), result_encrypted(i));
     // }

     // chrono::steady_clock::time_point time_start, time_end;
     // time_start = chrono::steady_clock::now();
     // for (size_t r = 0; r < result_encrypted.shape()[0]; r++)
     // {
     //      for (size_t c = 0; c < result_encrypted.shape()[1]; c++)
     //      {
     //           Ciphertext product;
     //           evaluator.multiply_plain(x_encrypted(c), weight(r, c), product);
     //           evaluator.add_inplace(result_encrypted(r), product);
     //      }
     //      evaluator.add_plain_inplace(result_encrypted(r), bias(r));
     // }
     // time_end = chrono::steady_clock::now();
     // std::chrono::duration<double> time_diff = time_end - time_start;
     // cout << "Done [" << time_diff.count() << " seconds]" << endl;

     // // for (size_t i = 0; i < result_encrypted.size(); i++)
     // // {
     // //      Plaintext result;
     // //      decryptor.decrypt(result_encrypted(i), result);
     // //      cout << encoder.decode_int32(result) << endl;
     // // }

     // // Parallilize it with multithreading
     // xt::xtensor_fixed<Ciphertext, xt::xshape<load>> result_encrypted_threading{};
     // for (size_t i = 0; i < result_encrypted_threading.size(); i++)
     // {
     //      encryptor.encrypt(encoder.encode(0), result_encrypted_threading(i));
     // }

     // time_start = chrono::steady_clock::now();
     // const size_t num_threads = 5;
     // std::vector<std::thread> threads;
     // threads.reserve(num_threads);
     // size_t worker_load = load/5; // assume const size_t

     // for (size_t thread_idx = 0; thread_idx < num_threads; thread_idx++)
     // {
     //      std::vector<size_t> partition(worker_load);
     //      std::iota(std::begin(partition), std::end(partition), thread_idx*worker_load);

     //      threads.emplace_back(std::thread([&](std::vector<size_t> rows) {
     //           for (auto &r : rows)
     //           {
     //                for (size_t c = 0; c < result_encrypted_threading.shape()[1]; c++)
     //                {
     //                     Ciphertext product;
     //                     evaluator.multiply_plain(x_encrypted(c), weight(r, c), product);
     //                     evaluator.add_inplace(result_encrypted_threading(r), product);
     //                }
     //                evaluator.add_plain_inplace(result_encrypted_threading(r), bias(r));
     //           }
     //      },
     //      partition));
     // }
     // for (auto &thread : threads)
     // {
     //      thread.join();
     // }

     // time_end = chrono::steady_clock::now();
     // time_diff = time_end - time_start;
     // cout << "Done [" << time_diff.count() << " seconds]" << endl;

     // return 0;
}