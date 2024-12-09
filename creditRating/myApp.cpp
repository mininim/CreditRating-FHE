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

        //std::cout << "Processed customer ID: " << customerId << std::endl;
    }
}

// Initialize all companies' weights, generate keys, and encrypt
void MyApp::initializeAllCompanies() {

    for (const auto& [companyId, reportType, description] : companyData) {
        // Step 1: Initialize Weights
    if (companyId == "A") {
        companyWeightsMap[companyId] = Weights(
            {0.02, 0.021, 0.022, 0.023, 0.024, 0.025, 0.026, 0.027, 0.028, 0.029}, // reasonWeights
            {0.03, 0.031, 0.032, 0.03, 0.034, 0.035, 0.036, 0.037, 0.038, 0.039}, // institutionWeights
            {0.06, 0.11}                                                  // repaymentWeights
        );
    } else if (companyId == "B") {
        companyWeightsMap[companyId] = Weights(
            {0.015, 0.016, 0.017, 0.018, 0.019, 0.02, 0.021, 0.022, 0.023, 0.024}, // reasonWeights
            {0.025, 0.026, 0.027, 0.028, 0.029, 0.03, 0.031, 0.032, 0.033, 0.034}, // institutionWeights
            {0.055, 0.105}                                                // repaymentWeights
        );
    } else if (companyId == "C") {
        companyWeightsMap[companyId] = Weights(
            {0.01, 0.012, 0.014, 0.016, 0.018, 0.02, 0.022, 0.024, 0.026, 0.028}, // reasonWeights
            {0.02, 0.022, 0.024, 0.026, 0.028, 0.03, 0.032, 0.034, 0.036, 0.038}, // institutionWeights
            {0.05, 0.01}                                                 // repaymentWeights
        );
    } else {
        companyWeightsMap[companyId] = Weights(
            {0.1, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19}, // reasonWeights
            {0.1, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19}, // institutionWeights
            {0.5, 1.0}                                                 // repaymentWeights
        );
    }
        // Step 2: Generate Keys
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        // Rotate Key Set
        // std::vector<int> rotationIndexes(257); // 257 = 128 - (-128) + 1
        // std::iota(rotationIndexes.begin(), rotationIndexes.end(), -128);
        // cc->EvalRotateKeyGen(keyPair.secretKey, rotationIndexes);
        // companyKeyPairs[companyId] = keyPair;

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

        //std::cout << "Processed company ID: " << companyId << std::endl;
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
    auto ctxCalcResult = cc->EvalMult(weight2calc, weightRepaymentStatusVectorPlaintext);


    // 암호화 상태에서 연산     Rotate Sum
    // Ciphertext<DCRTPoly> ctxSum = ctxCalcResult; // Start with the original ciphertext
    // size_t vectorSize = loanData.amountVector.size(); // Number of elements in the vector

    // for (size_t i = 1; i < vectorSize; i++) {
    //     // Rotate the ciphertext to the right by i positions
    //     auto ctxRot = cc->EvalRotate(ctxCalcResult, i);
    
    //     // Add the rotated ciphertext to the current sum
    //     ctxSum = cc->EvalAdd(ctxSum, ctxRot);
    // }



    // Decrypt the result
    Plaintext m_decrypted_ptx;
    auto secretKey = customerKeyPairs.at(customerId).secretKey; // Retrieve the user's secret key
    cc->Decrypt(secretKey, ctxCalcResult, &m_decrypted_ptx);
    m_decrypted_ptx->SetLength(loanData.amountVector.size());
    // Get decrypted value
    std::vector<double> m_decryptedMsg = m_decrypted_ptx->GetRealPackedValue();
    double m_sum = std::accumulate(m_decryptedMsg.begin(), m_decryptedMsg.end(), 0.0);
    

    // For Debug Compute the same operation without encryption
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

    m_sum = (m_sum / 4000) * 300;


     //std::cout << "MS ---  " << customerId << " and Company " << companyId << "  :  m_sum " << m_sum  << std::endl;

    // 유찬 ------------------------------------------------------------

    double assetScore, phoneScore;
    // Key Generation
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    /* asset score 계산 부분 */     
    // CSV 파일 읽기
    std::string assetFilename;
    if (customerId == "1") {assetFilename = "../creditRating/asset_0.csv";}
    else if (customerId == "2") {assetFilename = "../creditRating/asset_1.csv";}
    else if (customerId == "3") {assetFilename = "../creditRating/asset_2.csv";}
    std::ifstream file(assetFilename);
    std::string line;
    Ciphertext<DCRTPoly> totalSumCiphertext;
    // Skip the header line
    std::getline(file, line);
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string instantCashStr, amountStr;
        // CSV 파일에서 instantCash와 amount 읽기
        std::getline(ss, instantCashStr, ',');
        std::getline(ss, amountStr, ',');
        double instantCash = std::stod(instantCashStr);
        double amount = std::stod(amountStr);
        // 동형암호화된 instantCash
        std::vector<double> msg1 = {instantCash};
        Plaintext ptx1 = cc->MakeCKKSPackedPlaintext(msg1);
        auto ctx1 = cc->Encrypt(keyPair.publicKey, ptx1);
        // 동형암호화된 amount
        std::vector<double> msg2 = {amount};
        Plaintext ptx2 = cc->MakeCKKSPackedPlaintext(msg2);
        auto ctx2 = cc->Encrypt(keyPair.publicKey, ptx2);
        // (amount - instantCash) 계산
        auto ctxSub = cc->EvalSub(ctx2, ctx1);
        // (amount - instantCash) * 0.5 계산
        std::vector<double> msg3;  // 0.5를 암호화
        if (companyId == "A") {msg3 = {0.5};}
        else if (companyId == "B") {msg3 = {0.4};}
        else if (companyId == "C") {msg3 = {0.3};}
        Plaintext ptx3 = cc->MakeCKKSPackedPlaintext(msg3);
        auto ctx3 = cc->Encrypt(keyPair.publicKey, ptx3);
        auto ctxWeightedAmount = cc->EvalMult(ctxSub, ctx3);
        // 동형암호화된 계산: instantCash + weightedAmount
        auto ctxSum = cc->EvalAdd(ctx1, ctxWeightedAmount);
        // 누적 합산
        if (totalSumCiphertext == nullptr) {
            totalSumCiphertext = ctxSum;  // 첫 번째 값으로 초기화
        } else {
            totalSumCiphertext = cc->EvalAdd(totalSumCiphertext, ctxSum);  // 이후 합산
        }
    }
    file.close();
    // 최종 합산된 결과 복호화
    Plaintext u_decrypted_ptx;
    cc->Decrypt(keyPair.secretKey, totalSumCiphertext, &u_decrypted_ptx);
    u_decrypted_ptx->SetLength(1);
    // 최종 결과 출력
    std::vector<double> u_decryptedMsg = u_decrypted_ptx->GetRealPackedValue();
    if (u_decryptedMsg[0] > 100000) {u_decryptedMsg[0] = 100000;}
    assetScore = u_decryptedMsg[0] / 100000 * 300;

    /* phone score 계산 */
    std::vector<double> zeroVec = {0.0}; // 0 값을 가진 벡터
    Plaintext zeroPlaintext = cc->MakeCKKSPackedPlaintext(zeroVec);
    auto u_encryptedResult = cc->Encrypt(keyPair.publicKey, zeroPlaintext); // 암호화된 0 값
    std::vector<double> zeroVec2 = {0.0}; // 0 값을 가진 벡터
    Plaintext zeroPlaintext2 = cc->MakeCKKSPackedPlaintext(zeroVec);
    auto encryptedMax = cc->Encrypt(keyPair.publicKey, zeroPlaintext); // 암호화된 0 값
    // CSV 파일을 읽기
    std::string phoneFilename;
    if (customerId == "1") {phoneFilename = "../creditRating/phone_0.csv";}
    else if (customerId == "2") {phoneFilename = "../creditRating/phone_1.csv";}
    else if (customerId == "3") {phoneFilename = "../creditRating/phone_2.csv";}
    std::ifstream file_(phoneFilename);
    std::getline(file_, line); // 헤더 건너뛰기
    while (std::getline(file_, line)) {
        std::stringstream ss(line);
        std::string phoneBillStr, paymentStr;
        std::getline(ss, phoneBillStr, ',');
        std::getline(ss, paymentStr, ',');
        double phoneBill = std::stod(phoneBillStr);
        double payment = std::stod(paymentStr);
        // phoneBill과 payment 값을 암호화
        std::vector<double> msg1 = {phoneBill};
        std::vector<double> msg2 = {payment};
        Plaintext ptx1 = cc->MakeCKKSPackedPlaintext(msg1);
        Plaintext ptx2 = cc->MakeCKKSPackedPlaintext(msg2);
        auto ctx1 = cc->Encrypt(keyPair.publicKey, ptx1);
        auto ctx2 = cc->Encrypt(keyPair.publicKey, ptx2);
        // 암호화된 상태에서 차이 계산 (ctx1 - ctx2)
        auto encryptedDiff = cc->EvalSub(ctx1, ctx2);
        // 누적
        u_encryptedResult = cc->EvalAdd(u_encryptedResult, encryptedDiff);
        encryptedMax = cc->EvalAdd(encryptedMax, ctx1);
    }
    // 최종 결과 복호화
    Plaintext u_decryptedResult;
    cc->Decrypt(keyPair.secretKey, u_encryptedResult, &u_decryptedResult);
    u_decryptedResult->SetLength(1); // 복호화된 결과 길이 설정
    std::vector<double> u_decryptedResult_ = u_decryptedResult->GetRealPackedValue();
    // 최종 결과 복호화
    Plaintext u_decryptedResult2;
    cc->Decrypt(keyPair.secretKey, encryptedMax, &u_decryptedResult2);
    u_decryptedResult2->SetLength(1); // 복호화된 결과 길이 설정
    std::vector<double> u_decryptedMsg2 = u_decryptedResult2->GetRealPackedValue();
    double w__ = 1;
    if (companyId == "A") {w__ = 0.9;}
    else if (companyId == "B") {w__ = 0.8;}
    else if (companyId == "C") {w__ = 1;}
    phoneScore = (1.0 - w__ * u_decryptedResult_[0] / u_decryptedMsg2[0]) * 300.0;
    
    //std::cout << "YC ---  " << customerId << " and Company " << companyId << "  :  assetScore " << assetScore << " phoneScore "  << phoneScore << std::endl;

    /****최종 결과 합치지***/
    std::cout << "Total score: " << m_sum + assetScore + phoneScore << " (" << m_sum << ", " << assetScore << ", " << phoneScore << ")" << std::endl;


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

    // 모든 사용자와 회사의 신용평가 조합 출력
    try {
        for (const auto& [customerId, customerName] : customerData) {
            for (const auto& [companyId, reportType, description] : companyData) {
                std::cout << "Evaluating credit score for Customer ID: " << customerId
                      << " (" << customerName << ") and Company ID: " << companyId << std::endl;
                try {
                    app.evaluateAndPrintCreditScore(customerId, companyId);
                } catch (const std::runtime_error& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
                std::cout << "---------------------------------------------" << std::endl;
            }
        }
} catch (const std::exception& e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
}
    return 0;
}
