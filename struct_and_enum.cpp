#include <string>
#include <iostream>

using namespace std;

enum processState{
    RUNNING = 1,
    SUSPENDED = 2,
    TERMINATED = 3
};

struct processInfo{
    int pid;
    string nameProc;
    processState state;
};

int main(){

    processInfo p1 = {1001,"notepad.exe",RUNNING};

    processInfo p2;
    p2.pid = 1002;
    p2.nameProc = "chrome.exe";
    p2.state = SUSPENDED;

    cout << "process " << p1.nameProc << " is " << (p1.state == RUNNING ? "RUNNING" : "NOT RUNNING") << "\n";
    cout << "process " << p2.nameProc << " is " << (p2.state == TERMINATED ? "TERMINATED" : "OTHER") << "\n";
}