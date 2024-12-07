#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>


#include "openfhe.h"
using namespace lbcrypto;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    this->setWindowTitle("신용 평가 시스템");
    this->resize(600, 400);

    QWidget *centralWidget = new QWidget(this);
    this->setCentralWidget(centralWidget);

    customerTable = new QTableWidget(2, 2, this);
    customerTable->setHorizontalHeaderLabels({"ID", "이름"});
    customerTable->setItem(0, 0, new QTableWidgetItem("asw222"));
    customerTable->setItem(0, 1, new QTableWidgetItem("왕쌍치"));
    customerTable->setItem(1, 0, new QTableWidgetItem("12asdc"));
    customerTable->setItem(1, 1, new QTableWidgetItem("유리리"));

    customerTable->setSelectionBehavior(QAbstractItemView::SelectRows);    // 设置整行选择模式
    customerTable->setSelectionMode(QAbstractItemView::SingleSelection);    // 限制只能选中一行

    customerTable->setStyleSheet(
        "QTableWidget::item:selected {"
        "   background-color: #f7dc6f;" // 设置背景颜色为黄色
        "   color: black;"             // 设置字体颜色为黑色
        "}"
        );
    customerTable->setFocusPolicy(Qt::NoFocus);  // 禁用表格的焦点策略（移除黑线框）



    companyTable = new QTableWidget(2, 3, this);
    companyTable->setHorizontalHeaderLabels({"평가사 이름", "금융 데이터", "비금융 데이터"});
    companyTable->setItem(0, 0, new QTableWidgetItem("A"));
    companyTable->setItem(0, 1, new QTableWidgetItem("신용정보 조회서"));
    companyTable->setItem(0, 2, new QTableWidgetItem("공과금"));
    companyTable->setItem(1, 0, new QTableWidgetItem("B"));
    companyTable->setItem(1, 1, new QTableWidgetItem("신용정보 조회서"));
    companyTable->setItem(1, 2, new QTableWidgetItem("통신요금"));

    companyTable->setSelectionBehavior(QAbstractItemView::SelectRows);    // 设置整行选择模式
    companyTable->setSelectionMode(QAbstractItemView::SingleSelection);    // 限制只能选中一行

    companyTable->setStyleSheet(
        "QTableWidget::item:selected {"
        "   background-color: #f7dc6f;" // 设置背景颜色为黄色
        "   color: black;"             // 设置字体颜色为黑色
        "}"
        "QTableWidget::item {"
        "    outline: none;" // 移除黑线框
        "}"
        );
    companyTable->setFocusPolicy(Qt::NoFocus);  // 禁用表格的焦点策略


    generateKeyButton = new QPushButton("키 생성하기", this);
    generateKeyButton -> setFixedSize(120,35);
    generateKeyButton->setStyleSheet("font-size: 15px; font-weight: bold;");


    selectedInfoLabel = new QLabel("<span style='font-size: 14px;'>"
                                   "선택된 고객: 없음"
                                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                                   "신용평가 회사: 없음", this);
    scoreLabel = new QLabel("<span style='font-size: 16px;'>점수: --", this);
    checkScoreButton = new QPushButton("신용평가 점수 확인하기", this);
    checkScoreButton -> setFixedSize(160,35);
    generateKeyButton->setStyleSheet("font-size: 15px; font-weight: bold;");

    QVBoxLayout *leftLayout = new QVBoxLayout;
    leftLayout->addWidget(new QLabel("<span style='font-size: 14.5px; color: #1f618d;'>고객 목록", this));
    leftLayout->addWidget(customerTable);

    QVBoxLayout *rightLayout = new QVBoxLayout;
    rightLayout->addWidget(new QLabel("<span style='font-size: 14.5px;color: #1f618d;'>신용평가회사 목록", this));
    rightLayout->addWidget(companyTable);

    QHBoxLayout *tablesLayout = new QHBoxLayout;
    tablesLayout->addLayout(leftLayout);
    tablesLayout->addLayout(rightLayout);

    QHBoxLayout *infoLayout = new QHBoxLayout;
    infoLayout->addWidget(selectedInfoLabel);
    infoLayout->addWidget(checkScoreButton);

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addStretch(); // 左侧弹性空白
    buttonLayout->addWidget(scoreLabel);
    buttonLayout->addStretch(); // 右侧弹性空白

    QVBoxLayout *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(generateKeyButton);
    mainLayout->addSpacing(20);
    mainLayout->addLayout(tablesLayout);
    mainLayout->addSpacing(15);
    mainLayout->addLayout(infoLayout);
    mainLayout->addSpacing(15);
    mainLayout->addLayout(buttonLayout);
    mainLayout->addSpacing(30);

    centralWidget->setLayout(mainLayout);

    connect(checkScoreButton, &QPushButton::clicked, this, &MainWindow::checkScore);
}

MainWindow::~MainWindow() {}

void MainWindow::checkScore() {
    int customerRow = customerTable->currentRow();
    int companyRow = companyTable->currentRow();

    if (customerRow == -1 || companyRow == -1) {
        selectedInfoLabel->setText("<span style='font-size: 14px;'>고객과 신용평가 회사를 선택해주세요");
        scoreLabel->setText("<span style='font-size: 14px;'>점수: --");
        return;
    }

    QString qcustomerId = customerTable->item(customerRow, 0)->text();
    QString qcompanyName = companyTable->item(companyRow, 0)->text();


    /* 변수 설정 */
    std::string customerId = qcustomerId.toStdString();
    std::string companyName = qcompanyName.toStdString();
    double creditScore = 0.0;
    double debtScore, assetScore, phoneScore;

    /* openFHE 변수 설정 */
    // OpenFHE 설정
    uint32_t multDepth = 2;
    uint32_t scaleModSize = 50;
    SecurityLevel securityLevel = HEStd_128_classic;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(4);
    parameters.SetSecurityLevel(securityLevel);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    /* asset score 계산 부분 */
    // CSV 파일 읽기
    std::string assetFilename;
    if (id == "0") {assetFilename = "asset_0.csv";}
    else if (id == "1") {assetFilename = "asset_1.csv";}
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
        std::vector<double> msg3 = {0.5};  // 0.5를 암호화
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
    Plaintext decrypted_ptx;
    cc->Decrypt(keyPair.secretKey, totalSumCiphertext, &decrypted_ptx);
    decrypted_ptx->SetLength(1);
    // 최종 결과 출력
    std::vector<double> decryptedMsg = decrypted_ptx->GetRealPackedValue();
    if (decryptedMsg[0] > 100000) {decryptedMsg[0] = 100000;}
    assetScore = decryptedMsg[0] / 100000 * 300;

    /* phone score 계산 */
    std::vector<double> zeroVec = {0.0}; // 0 값을 가진 벡터
    Plaintext zeroPlaintext = cc->MakeCKKSPackedPlaintext(zeroVec);
    auto encryptedResult = cc->Encrypt(keyPair.publicKey, zeroPlaintext); // 암호화된 0 값
    std::vector<double> zeroVec2 = {0.0}; // 0 값을 가진 벡터
    Plaintext zeroPlaintext2 = cc->MakeCKKSPackedPlaintext(zeroVec);
    auto encryptedMax = cc->Encrypt(keyPair.publicKey, zeroPlaintext); // 암호화된 0 값
    // CSV 파일을 읽기
    std::string phoneFilename;
    if (id == "0") {phoneFilename = "phone_0.csv";}
    else if (id == "1") {phoneFilename = "phone_1.csv";}
    std::ifstream file(phoneFilename);
    std::string line;
    std::getline(file, line); // 헤더 건너뛰기
    while (std::getline(file, line)) {
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
        encryptedResult = cc->EvalAdd(encryptedResult, encryptedDiff);
        encryptedMax = cc->EvalAdd(encryptedMax, ctx1);
    }
    // 최종 결과 복호화
    Plaintext decryptedResult;
    cc->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    decryptedResult->SetLength(1); // 복호화된 결과 길이 설정
    std::vector<double> decryptedMsg = decryptedResult->GetRealPackedValue();
    // 최종 결과 복호화
    Plaintext decryptedResult2;
    cc->Decrypt(keyPair.secretKey, encryptedMax, &decryptedResult2);
    decryptedResult2->SetLength(1); // 복호화된 결과 길이 설정
    std::vector<double> decryptedMsg2 = decryptedResult2->GetRealPackedValue();
    phoneScore = (1 - decryptedMsg[0] / decryptedMsg2[0]) * 300.0;
    

    /*************/


    creditScore = debtScore + assetScore + phoneScore;

    selectedInfoLabel->setText(
        QString("<span style='font-size: 14px;'>"
                "선택된 고객: <span style='color: red;'>%1</span>"
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"  //空格
                "신용평가 회사: <span style='color: red;'>%2</span> ").arg(customerId, companyName));


    scoreLabel->setText(QString("<span style='font-size: 16px;'>점수: %1").arg(creditScore));
}
