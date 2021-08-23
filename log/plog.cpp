//
// Created by GYWork on 2020/11/15.
//

#include "plog.h"
#include<iostream>
#include <iomanip>

using namespace std;


static void Draw_line(const vector<short> &max) {
    for (int i = 0; i < max.size(); i++) {
        cout << "+-";
        for (int j = 0; j <= max[i]; j++) {
            cout << '-';
        }
    }
    cout << '+' << endl;
}


void draw_table(const std::string &title, const std::vector<std::string> &labels, const std::vector<VOIDDATA> &data) {
    ///output title
    cout << title << endl;
    ///statistic
    int len = labels.size();
    vector<short> label_len;
    for (int i = 0; i < len; ++i) {
        label_len.push_back(labels[i].size());
    }
    ///draw labels
    Draw_line(label_len);
    for (int i = 0; i < len; i++) {
        cout << "| " << labels[i] << ' ';
    }
    cout << '|' << endl;
    Draw_line(label_len);
    for (int i = 0; i < int(data.size() / len); i++) {
        for (int j = 0; j < len; j++) {
            cout << "| " << setw(label_len[j]) << setiosflags(ios::left) << setfill(' ');
            switch (data[i * len + j].type) {
                case INT:
                    cout << data[i * len + j].d_int << ' ';
                    break;
                case DOUBLE:
                    cout << data[i * len + j].d_double << ' ';
                    break;
                case STRING:
                    cout << data[i * len + j].d_string << ' ';
                    break;
                default:
                    break;
            }
        }
        cout << '|' << endl;
        Draw_line(label_len);
    }

}
