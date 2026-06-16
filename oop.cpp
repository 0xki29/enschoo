#include <iostream>
#include <string>

using namespace std;


class nhanvien{

    private:
        int luong;
        int maNV;
    
    protected:
        string ten;
        int tuoi;



    public:
        nhanvien(int luong, int maNV,string ten, int tuoi){
            this->luong = luong;
            this->maNV = maNV;
            this->ten = ten;
            this->tuoi = tuoi;
        }

        int getLuong(){
            return luong;
        }

        int getMaNV(){
            return maNV;
        }

        void setLuong(int l){
            if(l > 0){
                this->luong = l;
            }
        }

        void gioithieu(){
            cout << "Ten toi la: " << this->ten << " nam nay " << this->tuoi << " tuoi" << "\n";
        }

        friend void kiemToan(nhanvien nv);



};

class LapTrinhVien : public nhanvien {
    private:
        string ngonNgu;

    public:
        LapTrinhVien(int luong, int maNV,string ten,int tuoi,string ngonNgu) : nhanvien(luong,maNV,ten,tuoi){
            this->ngonNgu = ngonNgu;
        }

        void code(){
            cout << this->ten << " dang code bang " << this->ngonNgu << "\n";
        }


};

class Quanly : public nhanvien{
    private:
        string phongBan;

    public:
        Quanly(int luong,int maNV,string ten,int tuoi,string phongBan): nhanvien (luong,maNV,ten,tuoi){
            this->phongBan = phongBan;
        }

        void hopHanh(){
            cout << this->ten << " dang hop phong " << this->phongBan << "\n";
        }
};

void kiemToan(nhanvien nv){
    cout << "Kiem toan NV #" << nv.maNV << ": luong " << nv.luong << "\n";
}

int main(){

    LapTrinhVien ltv(100,001,"Nguyen Viet Hoang",30,"Java");
    Quanly ql(150,007,"Nguyen Quang Cuong",32,"Quan ly hanh chinh");

    ltv.gioithieu();
    ql.gioithieu();

    ltv.code();
    ql.hopHanh();

    ltv.setLuong(-500);
    ql.setLuong(8000);

    kiemToan(ltv);
    kiemToan(ql);

}