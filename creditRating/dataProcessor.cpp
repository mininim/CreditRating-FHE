#include "DataProcessor.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>

// Definitions of declared functions
int daysSinceBaseDate(const std::string& date) {
    // 기준 날짜
    constexpr int BASE_YEAR = 1900; // 1900년
    constexpr int BASE_MONTH = 0; // 1월
    constexpr int BASE_DAY = 1;   // 1일

    // 기준 날짜 설정
    std::tm baseDate = {};
    baseDate.tm_year = BASE_YEAR - 1900; // 1900년 기준
    baseDate.tm_mon = BASE_MONTH;
    baseDate.tm_mday = BASE_DAY;

    // 입력된 날짜 파싱
    std::tm givenDate = {};
    std::istringstream dateStream(date);
    dateStream >> std::get_time(&givenDate, "%Y.%m.%d");

    // 날짜 형식 확인
    if (dateStream.fail()) {
        std::cerr << "Invalid date format: " << date << ". Expected format: YYYY.MM.DD" << std::endl;
        return -1;
    }

    // 기준 날짜와 입력 날짜를 time_t로 변환
    std::time_t baseTime = std::mktime(&baseDate);
    std::time_t givenTime = std::mktime(&givenDate);

    // mktime 에러 처리 (비정상 값 검출)
    if (baseTime == -1 || givenTime == -1) {
        std::cerr << "Error converting dates to time_t." << std::endl;
        return -1;
    }

    // 일 단위 차이를 반환
    return static_cast<int>(std::difftime(givenTime, baseTime) / (60 * 60 * 24));
}
int encodeRepaymentStatus(const std::string& status) {
    if (status == "상환중") return 0;
    if (status == "미상환") return 0;
    if (status == "상환완료") return 1;
    return -1;
}

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
) {
    std::stringstream lineStream(line);
    std::string category, reason, institution, date, repaymentStatus;
    int amount;

    std::getline(lineStream, category, ',');
    std::getline(lineStream, reason, ',');
    std::getline(lineStream, institution, ',');
    std::getline(lineStream, date, ',');
    lineStream >> amount;
    lineStream.ignore();
    std::getline(lineStream, repaymentStatus, ',');

    categoryVector.push_back(category);

    if (reasonCodes.find(reason) == reasonCodes.end()) {
        reasonCodes[reason] = reasonCodes.size() + 1;
    }
    reasonVector.push_back(reasonCodes[reason]);

    if (institutionCodes.find(institution) == institutionCodes.end()) {
        institutionCodes[institution] = institutionCodes.size() + 1;
    }
    institutionVector.push_back(institutionCodes[institution]);

    dateVector.push_back(daysSinceBaseDate(date));
    amountVector.push_back(amount);
    repaymentStatusVector.push_back(encodeRepaymentStatus(repaymentStatus));
}

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
) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filePath << std::endl;
        return;
    }

    std::string header;
    std::getline(file, header);

    std::string line;
    while (std::getline(file, line)) {
        processLine(line, reasonCodes, institutionCodes, categoryVector, reasonVector, institutionVector, dateVector, amountVector, repaymentStatusVector);
    }
    file.close();
}
