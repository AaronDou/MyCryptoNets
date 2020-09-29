#include <vector>
#include <string>
#include <sstream>

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

} // namespace mycryptonets
