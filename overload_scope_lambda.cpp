#include <iostream>
#include <string>
using namespace std;


void overload(int x){
    cout << x << " is interger" << "\n";
}

void overload(string s){
    cout << s << " is string" << "\n";
}

int x = 100;

void change(){
    x = 99;
    cout << "x changed to " << x << "\n";
}


int main(){

    overload(10);
    overload("0xki29");

    change();
    cout << x << "\n";
    int nguong = 100;

    auto loc1 = [nguong](int value){return value > nguong;};
    auto loc2 = [&nguong](int value){return value > nguong;};
    nguong = 200;
    cout << loc1(150) << "\n";
    cout << loc2(150) << "\n"; 



}