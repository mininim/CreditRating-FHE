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


int main() {
    // 데이터 전처리--------------------------------------------------

    LoanData loanData = processCSV("../creditRating/loan_data_100.csv");
    
    // // loanData 출력
    // for (size_t i = 0; i < loanData.categoryVector.size(); ++i) {
    //     std::cout << "Category: " << loanData.categoryVector[i]
    //               << ", Reason Code: " << loanData.reasonVector[i]
    //               << ", Institution Code: " << loanData.institutionVector[i]
    //               << ", Days Since 2000: " << loanData.dateVector[i]
    //               << ", Amount: " << loanData.amountVector[i]
    //               << ", Repayment Status: " << loanData.repaymentStatusVector[i] << std::endl;
    // }
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

    // 결과 출력
    std::cout << "All users and companies have been initialized, keys generated, and data encrypted." << std::endl;

    return 0;

    // // Initialize 예시 - QString 일때 
    // std::vector<std::pair<QString, QString>> customerData = {
    //     {"1", "왕쌍치"},
    //     {"2", "유리리"},
    //     {"3", "왕우"},
    // };

    // std::vector<std::tuple<QString, QString, QString>> companyData = {
    //     {"A", "신용정보 조회서", "공과금"},
    //     {"B", "신용정보 조회서", "통신요금"},
    //     {"B", "신용정보 조회서", "통신요금, 이것저것"}
    // };
    //  // QString 데이터를 std::string으로 변환
    // std::vector<std::pair<std::string, std::string>> stdCustomerData;
    // for (const auto& [qId, qName] : customerData) {
    //     stdCustomerData.emplace_back(qId.toStdString(), qName.toStdString());
    // }

    // std::vector<std::tuple<std::string, std::string, std::string>> stdCompanyData;
    // for (const auto& [qId, qType, qDescription] : companyData) {
    //     stdCompanyData.emplace_back(qId.toStdString(), qType.toStdString(), qDescription.toStdString());
    // }

    // // Initialize MyApp with std::string data
    // MyApp app(stdCustomerData, stdCompanyData);


    return 0;

/*
    // 암호화--------------------------------------------------
    // Step 1: OpenFHE 암호화 컨텍스트 초기화
    uint32_t multDepth = 10;                   // 연산 깊이
    uint32_t scaleModSize = 50;                // 스케일링 모듈 크기
    uint32_t batchSize = 128;                  // 배치 크기
    SecurityLevel securityLevel = HEStd_128_classic; // 보안 수준 설정

    CCParams<CryptoContextCKKSRNS> parameters; // 암호화 파라미터 설정
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize); 
    parameters.SetSecurityLevel(securityLevel);

    // 암호화 컨텍스트 생성 및 활성화
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);            // 공개 키 암호화 활성화
    cc->Enable(LEVELEDSHE);     // 준동형 연산 활성화
    cc->Enable(KEYSWITCH);      // 키 전환 활성화
    cc->Enable(ADVANCEDSHE);    // 고급 동형 연산 활성화

    // Step 2: 키 생성
    auto keyPair = cc->KeyGen();               // 키 생성
    cc->EvalMultKeyGen(keyPair.secretKey);     // 곱셈 키 생성

    // 정수 데이터를 부동소수점(double) 데이터로 변환 (CKKS 암호화 요구사항)
    std::vector<double> reasonVectorDouble(reasonVector.begin(), reasonVector.end());
    std::vector<double> institutionVectorDouble(institutionVector.begin(), institutionVector.end());
    std::vector<double> dateVectorDouble(dateVector.begin(), dateVector.end());                                             
    std::vector<double> amountVectorDouble(amountVector.begin(), amountVector.end());                                      
    std::vector<double> repaymentStatusVectorDouble(repaymentStatusVector.begin(), repaymentStatusVector.end());        

    // 벡터 디버깅 출력
    debugVector("대출 사유 벡터 (Double)", reasonVectorDouble);
    debugVector("대출 기관 벡터 (Double)", institutionVectorDouble);
    debugVector("날짜 벡터 (Double)", dateVectorDouble);
    debugVector("대출 금액 벡터 (Double)", amountVectorDouble);
    debugVector("상환 상태 벡터 (Double)", repaymentStatusVectorDouble);

    // 가중치 정의
    std::vector<double> reasonWeights = {1.0, 1.2, 1.5, 1.8, 2.0, 2.2, 2.5, 2.8, 3.0, 3.5}; // 대출 사유 가중치
    std::vector<double> institutionWeights = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.0}; // 대출 기관 가중치
    std::vector<double> repaymentWeights = {0.5, 1.0};  // 상환 상태 가중치 (미상환: 0.5, 상환: 1.0)
    
    // 가중치 벡터 생성
    std::vector<double> weightReasonVectorDouble(reasonVectorDouble.size());
    std::vector<double> weightInstitutionVectorDouble(institutionVectorDouble.size());
    std::vector<double> weightRepaymentStatusVectorDouble(repaymentStatusVectorDouble.size());

    for (size_t i = 0; i < reasonVectorDouble.size(); ++i) {
        weightReasonVectorDouble[i] = reasonWeights[static_cast<int>(reasonVectorDouble[i] - 1)];
        weightInstitutionVectorDouble[i] =
            institutionWeights[static_cast<int>(institutionVectorDouble[i] - 1)];
        weightRepaymentStatusVectorDouble[i] =
            repaymentWeights[static_cast<int>(repaymentStatusVectorDouble[i])];
    }

    // Step 4: 벡터 암호화
    auto encReasonVector = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(reasonVectorDouble));
    auto encInstitutionVector = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(institutionVectorDouble));
    auto encDateVector = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(dateVectorDouble));
    auto encAmountVector = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(amountVectorDouble));
    auto encRepaymentStatusVector = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(repaymentStatusVectorDouble));

    // 암호화된 벡터 곱셈
    auto weight1calc = cc->EvalMult(
        encReasonVector, cc->MakeCKKSPackedPlaintext(weightReasonVectorDouble));
    auto weight2calc = cc->EvalMult(
        weight1calc, cc->MakeCKKSPackedPlaintext(weightInstitutionVectorDouble));    
    auto weight3calc = cc->EvalMult(
        weight2calc, cc->MakeCKKSPackedPlaintext(weightRepaymentStatusVectorDouble));
    auto ctxCalcResult = cc->EvalMult(
        encAmountVector, cc->MakeCKKSPackedPlaintext(weightReasonVectorDouble));

    Plaintext decrypted_ptx;
    cc->Decrypt(keyPair.secretKey, ctxCalcResult, &decrypted_ptx);
    decrypted_ptx->SetLength(1);
    
    // 결과 출력
    std::vector<double> decryptedMsg = decrypted_ptx->GetRealPackedValue();

    std::cout << "Final Total Sum: " << decryptedMsg[0] << std::endl;

    // 결과를 저장할 벡터
    std::vector<double> result;

    // 각 요소를 곱하여 결과 벡터에 추가
    for (size_t i = 0; i < amountVectorDouble.size(); ++i) {
        result.push_back(
            amountVectorDouble[i] *
            weightReasonVectorDouble[i] *
            weightInstitutionVectorDouble[i] *
            weightRepaymentStatusVectorDouble[i]
        );
    }
    // 결과 출력
    std::cout << "평문 계산: ";
    for (double val : result) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
*/

    return 0;
}
