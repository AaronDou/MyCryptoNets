#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <functional>
#include <chrono>
#include <iostream>

using namespace std;

namespace mycryptonets
{
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
        regex r("([0-9]+)");
        vector<int> results;
        for (sregex_iterator i = sregex_iterator(s.begin(), s.end(), r);
             i != sregex_iterator();
             ++i)
        {
            smatch m = *i;
            results.push_back(stod(m[1].str().c_str()));
        }
        return results;
    }

    /*
    Helper function: Prints a vector of floating-point values.
    */
    template <typename T>
    inline void print_vector(vector<T> vec, size_t print_size = 4, int prec = 3)
    {
        /*
        Save the formatting information for cout.
        */
        ios old_fmt(nullptr);
        old_fmt.copyfmt(cout);

        size_t slot_count = vec.size();

        cout << fixed << setprecision(prec);
        cout << endl;
        if (slot_count <= 2 * print_size)
        {
            cout << "    [";
            for (size_t i = 0; i < slot_count; i++)
            {
                cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
            }
        }
        else
        {
            vec.resize(max(vec.size(), 2 * print_size));
            cout << "    [";
            for (size_t i = 0; i < print_size; i++)
            {
                cout << " " << vec[i] << ",";
            }
            if (vec.size() > 2 * print_size)
            {
                cout << " ...,";
            }
            for (size_t i = slot_count - print_size; i < slot_count; i++)
            {
                cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
            }
        }
        cout << endl;

        /*
        Restore the old cout formatting.
        */
        cout.copyfmt(old_fmt);
    }

    /*
    Helper function: Prints a matrix of values.
    */
    template <typename T>
    inline void print_matrix(vector<vector<T>> matrix)
    {
        for (const auto &row : matrix)
        {
            print_vector(row);
        }
    }

    template <typename T>
    string to_hex(T i)
    {
        stringstream stream;
        stream << hex << i;
        return stream.str();
    }

    template <typename T>
    vector<T const *> getPointers(const vector<T>& x)
    {
        vector<T const *> y;
        transform(x.begin(), x.end(), back_inserter(y), [](const T &c) { return &c; });
        return y;
    }

    template <typename T>
    vector<size_t> hardmax(vector<vector<T>> input)
    {
        assert(input.size() > 0);
        vector<size_t> res(input[0].size(), 0);

        for (size_t i = 0; i < input[0].size(); i++)
        {
            T max = input[0][i];
            for (size_t j = 1; j < input.size(); j++)
            {
                if (input[j][i] > max)
                {
                    max = input[j][i];
                    res[i] = j;
                }
            }
        }
        return res;
    }

    template <class>
    struct ExeTime;

    // Execution time decorator
    template <class... Args>
    struct ExeTime<void(Args...)>
    {
    public:
        ExeTime(std::function<void(Args...)> func, string desc) : f_(func), desc(desc) {}

        void operator()(Args... args)
        {
            std::chrono::time_point<std::chrono::steady_clock> start, end;
            std::chrono::duration<double> elapsed_seconds;

            start = std::chrono::steady_clock::now();
            f_(args...);
            end = std::chrono::steady_clock::now();
            elapsed_seconds = end - start;
            std::cout << desc << " took ";
            std::cout << elapsed_seconds.count() << " seconds" << std::endl;
        }

    private:
        std::function<void(Args...)> f_;
        std::string desc;
    };

    template <class... Args>
    ExeTime<void(Args...)> make_decorator(void (*f)(Args...), string desc)
    {
        return ExeTime<void(Args...)>(std::function<void(Args...)>(f), desc);
    }
} // namespace mycryptonets
