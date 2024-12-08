#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

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

    QString customerId = customerTable->item(customerRow, 0)->text();
    QString companyName = companyTable->item(companyRow, 0)->text();

    selectedInfoLabel->setText(
        QString("<span style='font-size: 14px;'>"
                "선택된 고객: <span style='color: red;'>%1</span>"
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"  //空格
                "신용평가 회사: <span style='color: red;'>%2</span> ").arg(customerId, companyName));


    scoreLabel->setText("<span style='font-size: 16px;'>점수: 100");
}
