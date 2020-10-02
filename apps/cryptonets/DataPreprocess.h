#include <vector>

namespace mycryptonets
{
    struct Weights
    {
        vector<double> convWeights;
        vector<double> FC1Weights;
        vector<double> FC1Biases;
        vector<double> FC2Weights;
        vector<double> FC2Biases;
    };

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
}; // namespace mycryptonets