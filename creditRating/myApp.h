#ifndef MYAPP_H
#define MYAPP_H

#include "openfhe.h"
#include <vector>
#include <tuple>

using namespace lbcrypto;

struct Weights {
    std::vector<double> reasonWeights;       // 대출 사유 가중치
    std::vector<double> institutionWeights;  // 대출 기관 가중치
    std::vector<double> repaymentWeights;    // 상환 상태 가중치

    // 기본 생성자
    Weights()
        : reasonWeights{1.0, 1.2, 1.5, 1.8, 2.0, 2.2, 2.5, 2.8, 3.0, 3.5},
          institutionWeights{1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.0},
          repaymentWeights{0.5, 1.0} {}

    // 사용자 정의 값으로 초기화하는 생성자
    Weights(const std::vector<double>& customReasonWeights,
            const std::vector<double>& customInstitutionWeights,
            const std::vector<double>& customRepaymentWeights)
        : reasonWeights(customReasonWeights),
          institutionWeights(customInstitutionWeights),
          repaymentWeights(customRepaymentWeights) {}
};
class MyApp {
private:
    std::vector<std::pair<std::string, std::string>> customerData; // {ID, Name}
    std::vector<std::tuple<std::string, std::string, std::string>> companyData; // {ID, Report Type, Description}
    std::map<std::string, LoanData> loanDataMap;                  // LoanData by Customer ID
    std::map<std::string, std::vector<Ciphertext<DCRTPoly>>> encryptedLoanDataMap; // Encrypted LoanData by Customer ID
    std::map<std::string, Weights> companyWeightsMap;             // Weights by Company ID
    std::map<std::string, std::vector<Ciphertext<DCRTPoly>>> encryptedWeightsMap; // Encrypted Weights by Company ID
    std::map<std::string, KeyPair<DCRTPoly>> customerKeyPairs;    // 사용자별 키 쌍
    std::map<std::string, KeyPair<DCRTPoly>> companyKeyPairs;     // 회사별 키 쌍
    CryptoContext<DCRTPoly> cc;                                   // OpenFHE CryptoContext

public:
    // Constructor
    MyApp(const std::vector<std::pair<std::string, std::string>>& customers,
          const std::vector<std::tuple<std::string, std::string, std::string>>& companies);

    // Initialize all users' loan data, generate keys, and encrypt
    void initializeAllUsers(const std::string& baseFilePath);

    // Initialize all companies' weights, generate keys, and encrypt
    void initializeAllCompanies();

    // Initialize OpenFHE context
    void initializeEncryptionContext();
};

#endif 