//
// Created by GYWork on 2020/11/15.
//

#ifndef AUTH_ALL_PLOG_H
#define AUTH_ALL_PLOG_H

#include <string>
#include <vector>

enum DATATYPE{
    INT,
    DOUBLE,
    STRING
};

struct VOIDDATA{
    DATATYPE type;
    int d_int;
    double d_double;
    std::string d_string;
};

///function for draw picture
void draw_table(const std::string &title, const std::vector<std::string> &labels, const std::vector<VOIDDATA>& data);

#endif //AUTH_ALL_PLOG_H
