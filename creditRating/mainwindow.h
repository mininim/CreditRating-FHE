#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void checkScore();

private:
    QTableWidget *customerTable;
    QTableWidget *companyTable;
    QLabel *selectedInfoLabel;
    QLabel *scoreLabel;
    QPushButton *generateKeyButton;
    QPushButton *checkScoreButton;
};

#endif // MAINWINDOW_H
