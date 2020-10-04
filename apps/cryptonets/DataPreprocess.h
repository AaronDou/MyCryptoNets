#include <vector>

namespace mycryptonets
{
    struct Params
    {
        vector<double> convWeights;
        vector<double> convBiases;
        vector<double> FC1Weights;
        vector<double> FC1Biases;
        vector<double> FC2Weights;
        vector<double> FC2Biases;
    };

    void readInput(size_t batchSize,
                   double normalizationFactor,
                   vector<vector<vector<double>>>& data,
                   vector<vector<size_t>>& labels)
    {
        size_t numRows = 28 * 28;
        size_t batch = 2;

        vector<double> pixelBatch(batchSize, 0.0);
        vector<vector<double>> imageBatch(numRows, pixelBatch);
        data = vector<vector<vector<double>>>(batch, imageBatch);
        labels = vector<vector<size_t>>(batch, vector<size_t>(batchSize, 0));

        ifstream infile("../apps/cryptonets/resources/MNIST-28x28-test.txt");
        assert(infile.is_open());

        string line;
        size_t index = 0;
        while (getline(infile, line))
        {
            vector<int> pixelValuesPerImage = extractIntegers(line);
            labels[index / batchSize][index % batchSize] = pixelValuesPerImage[0];

            for (size_t i = 2; i < pixelValuesPerImage.size(); i += 2)
            {
                data[index / batchSize][pixelValuesPerImage[i]][index % batchSize] = pixelValuesPerImage[i + 1] * normalizationFactor;
            }
            index++;
        }

        infile.close();
    }

    Params readParams()
    {
        ifstream infile("../apps/cryptonets/resources/MyWeights.txt");
        assert(infile.is_open());

        Params params;
        string line;

        getline(infile, line);
        params.convWeights = split(line, ' ');

        getline(infile, line);
        params.convBiases = split(line, ' ');

        getline(infile, line);
        params.FC1Weights = split(line, ' ');
        getline(infile, line);
        params.FC1Biases = split(line, ' ');

        getline(infile, line);
        params.FC2Weights = split(line, ' ');
        getline(infile, line);
        params.FC2Biases = split(line, ' ');

        infile.close();

        return params;
    }
}; // namespace mycryptonets