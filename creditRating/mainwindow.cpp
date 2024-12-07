#include "mainwindow.h"
#include <QVBoxLayout>
#include <vector>
#include <string>

// 각자 헤더 추가

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    this->setWindowTitle("신용 평가 시스템");
    this->resize(600, 400);

    QWidget *centralWidget = new QWidget(this);
    this->setCentralWidget(centralWidget);

    // 데이터 초기화
    std::vector<std::pair<QString, QString>> customerData = {
        {"1", "왕쌍치"},
        {"2", "유리리"},
        {"3", "왕우"},
    };

    std::vector<std::tuple<QString, QString, QString>> companyData = {
        {"A", "신용정보 조회서", "공과금"},
        {"B", "신용정보 조회서", "통신요금"},
        {"B", "신용정보 조회서", "통신요금, 이것저것"}
    };

    // 고객 테이블
    customerTable = new QTableWidget(static_cast<int>(customerData.size()), 2, this);
    customerTable->setHorizontalHeaderLabels({"ID", "이름"});
    for (size_t i = 0; i < customerData.size(); ++i) {
        customerTable->setItem(static_cast<int>(i), 0, new QTableWidgetItem(customerData[i].first));
        customerTable->setItem(static_cast<int>(i), 1, new QTableWidgetItem(customerData[i].second));
    }

    customerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    customerTable->setSelectionMode(QAbstractItemView::SingleSelection);
    customerTable->setStyleSheet(
        "QTableWidget::item:selected {"
        "   background-color: #f7dc6f;"
        "   color: black;"
        "}"
    );
    customerTable->setFocusPolicy(Qt::NoFocus);

    // 신용평가회사 테이블
    companyTable = new QTableWidget(static_cast<int>(companyData.size()), 3, this);
    companyTable->setHorizontalHeaderLabels({"평가사 이름", "금융 데이터", "비금융 데이터"});
    for (size_t i = 0; i < companyData.size(); ++i) {
        companyTable->setItem(static_cast<int>(i), 0, new QTableWidgetItem(std::get<0>(companyData[i])));
        companyTable->setItem(static_cast<int>(i), 1, new QTableWidgetItem(std::get<1>(companyData[i])));
        companyTable->setItem(static_cast<int>(i), 2, new QTableWidgetItem(std::get<2>(companyData[i])));
    }

    companyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    companyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    companyTable->setStyleSheet(
        "QTableWidget::item:selected {"
        "   background-color: #f7dc6f;"
        "   color: black;"
        "}"
        "QTableWidget::item {"
        "    outline: none;"
        "}"
    );
    companyTable->setFocusPolicy(Qt::NoFocus);

    // 버튼 및 레이블 설정
    generateKeyButton = new QPushButton("키 생성하기", this);
    generateKeyButton->setFixedSize(120, 35);
    generateKeyButton->setStyleSheet("font-size: 15px; font-weight: bold;");

    selectedInfoLabel = new QLabel("<span style='font-size: 14px;'>"
                                   "선택된 고객: 없음"
                                   "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                                   "신용평가 회사: 없음", this);
    scoreLabel = new QLabel("<span style='font-size: 16px;'>점수: --", this);
    checkScoreButton = new QPushButton("신용평가 점수 확인하기", this);
    checkScoreButton->setFixedSize(160, 35);
    checkScoreButton->setStyleSheet("font-size: 15px; font-weight: bold;");

    // 레이아웃 구성
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
    buttonLayout->addStretch();
    buttonLayout->addWidget(scoreLabel);
    buttonLayout->addStretch();

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

    QString customerId = customerTable->item(customerRow, 0)->text();
    QString companyName = companyTable->item(companyRow, 0)->text();

    selectedInfoLabel->setText(
        QString("<span style='font-size: 14px;'>"
                "선택된 고객: <span style='color: red;'>%1</span>"
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                "신용평가 회사: <span style='color: red;'>%2</span>").arg(customerId, companyName));

    scoreLabel->setText("<span style='font-size: 16px;'>점수: 100");
}

