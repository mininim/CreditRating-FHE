#include "openfhe.h"
#include "DataProcessor.h"
#include "myApp.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <ctime>

using namespace lbcrypto;
// Constructor
MyApp::MyApp(const std::vector<std::pair<std::string, std::string>>& customers,
             const std::vector<std::tuple<std::string, std::string, std::string>>& companies)
    : customerData(customers), companyData(companies) {}

// Initialize OpenFHE encryption context
void MyApp::initializeEncryptionContext() {
    uint32_t multDepth = 10;                   // 연산 깊이
    uint32_t scaleModSize = 50;                // 스케일링 모듈 크기
    uint32_t batchSize = 128;                  // 배치 크기
    SecurityLevel securityLevel = HEStd_128_classic; // 보안 수준 설정

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);

    // 암호화 컨텍스트 생성 및 활성화
    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);        // 공개 키 암호화 활성화
    cc->Enable(LEVELEDSHE); // 준동형 연산 활성화
    cc->Enable(KEYSWITCH);  // 키 전환 활성화
    cc->Enable(ADVANCEDSHE); // 고급 동형 연산 활성화
}

// Initialize all users' loan data, generate keys, and encrypt
void MyApp::initializeAllUsers(const std::string& baseFilePath) {
    for (const auto& [customerId, name] : customerData) {
        // Step 1: Initialize LoanData
        std::string filePath = "../creditRating/"+ customerId + ".csv";
        loanDataMap[customerId] = processCSV(filePath);

        // Step 2: Generate Keys
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        customerKeyPairs[customerId] = keyPair;

        // Step 3: Encrypt LoanData
        const LoanData& loanData = loanDataMap.at(customerId);
        std::vector<Ciphertext<DCRTPoly>> encryptedData;

        std::vector<std::vector<double>> dataToEncrypt = {
            std::vector<double>(loanData.reasonVector.begin(), loanData.reasonVector.end()),
            std::vector<double>(loanData.institutionVector.begin(), loanData.institutionVector.end()),
            std::vector<double>(loanData.dateVector.begin(), loanData.dateVector.end()),
            std::vector<double>(loanData.amountVector.begin(), loanData.amountVector.end()),
            std::vector<double>(loanData.repaymentStatusVector.begin(), loanData.repaymentStatusVector.end())
        };

        for (const auto& data : dataToEncrypt) {
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
            encryptedData.push_back(ciphertext);
        }

        // Store encrypted data
        encryptedLoanDataMap[customerId] = encryptedData;

        std::cout << "Processed customer ID: " << customerId << std::endl;
    }
}

// Initialize all companies' weights, generate keys, and encrypt
void MyApp::initializeAllCompanies() {
    for (const auto& [companyId, reportType, description] : companyData) {
        // Step 1: Initialize Weights
        companyWeightsMap[companyId] = Weights(
            {1.0, 1.2, 1.5, 1.8, 2.0, 2.2, 2.5, 2.8, 3.0, 3.5}, // reasonWeights
            {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.0}, // institutionWeights
            {0.5, 1.0}                                          // repaymentWeights
        );

        // Step 2: Generate Keys
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        companyKeyPairs[companyId] = keyPair;

        // Step 3: Encrypt Weights
        const Weights& weights = companyWeightsMap.at(companyId);
        std::vector<Ciphertext<DCRTPoly>> encryptedWeights;

        std::vector<std::vector<double>> dataToEncrypt = {
            weights.reasonWeights,
            weights.institutionWeights,
            weights.repaymentWeights
        };

        for (const auto& data : dataToEncrypt) {
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
            encryptedWeights.push_back(ciphertext);
        }

        // Store encrypted weights
        encryptedWeightsMap[companyId] = encryptedWeights;

        std::cout << "Processed company ID: " << companyId << std::endl;
    }
}

void MyApp::evaluateAndPrintCreditScore(const std::string& customerId, const std::string& companyId) {
    // Check if the user and company data exist
    if (encryptedLoanDataMap.find(customerId) == encryptedLoanDataMap.end()) {
        throw std::runtime_error("No encrypted loan data found for customer ID: " + customerId);
    }
    if (companyWeightsMap.find(companyId) == companyWeightsMap.end()) {
        throw std::runtime_error("No weights found for company ID: " + companyId);
    }

    // Retrieve the encrypted loan data and weights
    const std::vector<Ciphertext<DCRTPoly>>& encryptedLoanData = encryptedLoanDataMap.at(customerId);
    const LoanData& loanData = loanDataMap.at(customerId); // Retrieve original loan data
    const Weights& weights = companyWeightsMap.at(companyId);

    // Ensure the amount vector is available in encryptedLoanData
    if (encryptedLoanData.size() < 4 || loanData.amountVector.empty()) {
        throw std::runtime_error("Amount vector is missing for customer ID: " + customerId);
    }

    Ciphertext<DCRTPoly> encAmountVector = encryptedLoanData[3]; // Assuming the 4th vector is the amount vector

    // Convert weights to OpenFHE plaintexts
    Plaintext weightReasonVectorPlaintext = cc->MakeCKKSPackedPlaintext(weights.reasonWeights);
    Plaintext weightInstitutionVectorPlaintext = cc->MakeCKKSPackedPlaintext(weights.institutionWeights);
    Plaintext weightRepaymentStatusVectorPlaintext = cc->MakeCKKSPackedPlaintext(weights.repaymentWeights);

    // Perform encrypted evaluation
    auto weight1calc = cc->EvalMult(encAmountVector, weightReasonVectorPlaintext);
    auto weight2calc = cc->EvalMult(weight1calc, weightInstitutionVectorPlaintext);
    auto weight3calc = cc->EvalMult(weight2calc, weightRepaymentStatusVectorPlaintext);
    auto ctxCalcResult = weight3calc;

    // Decrypt the result
    Plaintext decrypted_ptx;
    auto secretKey = customerKeyPairs.at(customerId).secretKey; // Retrieve the user's secret key
    cc->Decrypt(secretKey, ctxCalcResult, &decrypted_ptx);
    decrypted_ptx->SetLength(loanData.amountVector.size());

    // Get decrypted value
    std::vector<double> decryptedMsg = decrypted_ptx->GetRealPackedValue();

    // Compute the same operation without encryption
    std::vector<double> originalAmountVector(loanData.amountVector.begin(), loanData.amountVector.end());
    std::vector<double> weightReasonVector(weights.reasonWeights.begin(), weights.reasonWeights.end());
    std::vector<double> weightInstitutionVector(weights.institutionWeights.begin(), weights.institutionWeights.end());
    std::vector<double> weightRepaymentVector(weights.repaymentWeights.begin(), weights.repaymentWeights.end());

    std::vector<double> originalResult;
    for (size_t i = 0; i < originalAmountVector.size(); ++i) {
        double result = originalAmountVector[i];
        result *= weightReasonVector[i % weightReasonVector.size()];
        result *= weightInstitutionVector[i % weightInstitutionVector.size()];
        result *= weightRepaymentVector[i % weightRepaymentVector.size()];
        originalResult.push_back(result);
    }

    // Print the decrypted result
    std::cout << "Decrypted Credit Score for Customer " << customerId << " and Company " << companyId << ":" << std::endl;
    for (double val : decryptedMsg) {
        std::cout << val << " ";
    }
    std::cout << std::endl;

    // Print the non-encrypted computed result
    std::cout << "Non-encrypted Credit Score for Customer " << customerId << " and Company " << companyId << ":" << std::endl;
    for (double val : originalResult) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
}



int main() {
    // 고객 데이터 정의
    std::vector<std::pair<std::string, std::string>> customerData = {
        {"1", "왕쌍치"},
        {"2", "유리리"},
        {"3", "왕우"},
    };

    // 회사 데이터 정의
    std::vector<std::tuple<std::string, std::string, std::string>> companyData = {
        {"A", "신용정보 조회서", "공과금"},
        {"B", "신용정보 조회서", "통신요금"},
        {"C", "신용정보 조회서", "통신요금, 이것저것"}
    };

    // MyApp 객체 초기화
    MyApp app(customerData, companyData);

    // OpenFHE 컨텍스트 초기화
    app.initializeEncryptionContext();

    // 모든 사용자의 데이터를 초기화, 키 생성, 암호화
    app.initializeAllUsers("../creditRating");

    // 모든 회사의 가중치를 초기화, 키 생성, 암호화
    app.initializeAllCompanies();

    // 특정 사용자와 회사의 신용평가 계산 및 출력
    try {
        app.evaluateAndPrintCreditScore("1", "A");
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
