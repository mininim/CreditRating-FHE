#include "openfhe.h"
#include "DataProcessor.h"

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

int main() {
    // 데이터 전처리--------------------------------------------------
    // 파일 경로 (필요시 적절한 경로로 변경)
    std::string filePath = "../creditRating/loan_data_100.csv";

    // 대출 사유와 대출 기관의 고유 코드를 매핑할 맵
    std::map<std::string, int> reasonCodes;
    std::map<std::string, int> institutionCodes;

    // 데이터를 저장할 벡터들
    std::vector<std::string> categoryVector;    // 구분
    std::vector<int> reasonVector;             // 내역 사유 코드
    std::vector<int> institutionVector;        // 대출 기관 코드
    std::vector<int> dateVector;               // 날짜 (2000-01-01 기준 날짜로부터의 일수)
    std::vector<int> amountVector;             // 대출 금액
    std::vector<int> repaymentStatusVector;    // 상환 상태 코드

    // CSV 파일 처리
    processCSV(filePath, reasonCodes, institutionCodes, categoryVector, reasonVector, institutionVector, dateVector, amountVector, repaymentStatusVector);
    
    // 대출 사유 코드 출력
    std::cout << "대출 사유 코드:" << std::endl;
    for (const auto& pair : reasonCodes) {
        std::cout << "사유: " << pair.first << ", 코드: " << pair.second << std::endl;
    }

    // 대출 기관 코드 출력
    std::cout << "\n대출 기관 코드:" << std::endl;
    for (const auto& pair : institutionCodes) {
        std::cout << "기관: " << pair.first << ", 코드: " << pair.second << std::endl;
    }

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

    // 가중치 벡터 암호화
    auto encReasonWeights = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(weightReasonVectorDouble));
    auto encInstitutionWeights = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(weightInstitutionVectorDouble));
    auto encRepaymentWeights = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(weightRepaymentStatusVectorDouble));

    // 암호화된 벡터 곱셈
    auto weight1calc = cc->EvalMultAndRelinearize(encAmountVector, encReasonWeights);
    auto weight2calc = cc->EvalMultAndRelinearize(weight1calc, encInstitutionWeights);
    auto weight3calc = cc->EvalMultAndRelinearize(weight2calc, encRepaymentWeights);

    return 0;
}
