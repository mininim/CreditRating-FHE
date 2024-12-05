#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

#include <map>
#include <vector>
#include <string>
#include <iostream>

int daysSinceBaseDate(const std::string& date);
int encodeRepaymentStatus(const std::string& status);

void processLine(
    const std::string& line,
    std::map<std::string, int>& reasonCodes,
    std::map<std::string, int>& institutionCodes,
    std::vector<std::string>& categoryVector,
    std::vector<int>& reasonVector,
    std::vector<int>& institutionVector,
    std::vector<int>& dateVector,
    std::vector<int>& amountVector,
    std::vector<int>& repaymentStatusVector
);

void processCSV(
    const std::string& filePath,
    std::map<std::string, int>& reasonCodes,
    std::map<std::string, int>& institutionCodes,
    std::vector<std::string>& categoryVector,
    std::vector<int>& reasonVector,
    std::vector<int>& institutionVector,
    std::vector<int>& dateVector,
    std::vector<int>& amountVector,
    std::vector<int>& repaymentStatusVector
);

template <typename T>
void debugVector(const std::string& vectorName, const std::vector<T>& vec) {
    std::cout << "Vector: " << vectorName << std::endl;
    std::cout << "Size: " << vec.size() << std::endl;
    std::cout << "First 5 elements: ";
    for (size_t i = 0; i < vec.size() && i < 5; ++i) {
        std::cout << vec[i] << " ";
    }
    std::cout << std::endl << std::endl;
}

#endif 