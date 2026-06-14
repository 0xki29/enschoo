#include <iostream>
#include <string>

using namespace std;

int main(){

    string fileName = "C:\\Users\\0xki29\\enschoo\\love.exe";
    string& pathName = fileName;
    string* ptr = &fileName;
    cout << fileName <<"\n";
    cout << &fileName << "\n";
    cout << pathName << "\n";
    cout << *ptr << "\n"; 
}