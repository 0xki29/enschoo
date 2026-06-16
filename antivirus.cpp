#include <iostream>
#include <string>


using namespace std;

class Process{
    protected:
        string ten;
        int pid;
    public:

        Process(string ten,int pid){
            this->ten = ten;
            this->pid = pid;
        }

        virtual void run(){
            cout << this->ten << " (PID " << this->pid << ")" << " dang chay binh thuong" << "\n";
        }

        string getTen(){
            return this->ten;
        }

        int getPid(){
            return this->pid;
        }
};

class MalwareProcess : public Process{
    private:
        int mucDoNguyHiem;
    public:
        MalwareProcess(string ten,int pid,int mucDoNguyHiem) : Process(ten,pid){
            this->mucDoNguyHiem = mucDoNguyHiem;
        }

        void run() override{
            cout << this->ten << " (PID " << this->pid << ") CANH BAO! Muc do nguy hiem: " << this->mucDoNguyHiem << "\n";
        }

    
};

class SystemProcess : public Process{
    private:
        bool laRoot;
    public:

        SystemProcess(string ten,int pid,bool laRoot) : Process(ten,pid) {
            this->laRoot = laRoot;
        }

        void run() override{
            if(laRoot == true){
                cout << this->ten << " (PID " << this->pid << ")" << " la tien trinh he thong (ROOT)" << "\n";
            }
            else{
                cout << this->ten << " (PID " << this->pid << ")" << " la tien trinh he thong (USER)" << "\n";
            }
        }


};
template <typename T>

void quetProcess (T &Proc){
    Proc.run();
}
template <typename T>
class KetQuaQuet{
    private:
        T giaTri;
    public:
        KetQuaQuet(T giaTri){
            this->giaTri = giaTri;
        }
        
        T layGiaTri(){
            return this->giaTri;
        }
};

int main(){

    Process p("chrome.exe",1001);
    MalwareProcess m("trojan.exe",1002,8);
    SystemProcess s("cmd.exe",1003,true);

    Process* p1 = &p;
    Process* p2 = &m;
    Process* p3 = &s;


    quetProcess(*p1);
    quetProcess(*p2);
    quetProcess(*p3);

    KetQuaQuet<int> diemRuiRo(75);
    KetQuaQuet<string> ghiChu("Can theo doi them");

    cout << "Diem rui ro: " << diemRuiRo.layGiaTri() << "\n";
    cout << "Ghi chu: " << ghiChu.layGiaTri() << "\n";
}