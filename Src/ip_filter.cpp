#include "ip_filter.h"
#include <algorithm>

using namespace std;
// ("",  '.') -> [""]
// ("11", '.') -> ["11"]
// ("..", '.') -> ["", "", ""]
// ("11.", '.') -> ["11", ""]
// (".11", '.') -> ["", "11"]
// ("11.22", '.') -> ["11", "22"]

bool VectorComparer::operator () (const vector<uint8_t>& lhs, const vector<uint8_t>& rhs){    
    size_t min_size = min(lhs.size(), rhs.size());
    for(size_t i = 0;i < min_size;i++){
        if(rhs[i] < lhs[i]){
            return true;
        }else if(rhs[i] > lhs[i]){
            return false;
        }
    }
    return false;
}

ostream& operator<<(ostream& out, const IpAddress& ip_addr){
    for(auto ip_part = ip_addr.begin(); ip_part != ip_addr.end(); ++ip_part)
    {
        if (ip_part != ip_addr.begin())
        {
            out << ".";

        }
        out << (*ip_part) + 0;
    }

    return out;
}


vector<string> split(const string &str, char d)
{
    vector<string> r;

    string::size_type start = 0;
    string::size_type stop = str.find_first_of(d);
    while(stop != string::npos)
    {
        r.push_back(str.substr(start, stop - start));

        start = stop + 1;
        stop = str.find_first_of(d, start);
    }

    r.push_back(str.substr(start));

    return r;
}

IpAddress ipValidator(const vector<string>& str_ip){
    IpAddress res;
    if(str_ip.size() != SIZE_IP){
        return {};
    }

    for(size_t i = 0;i < SIZE_IP;i++){        
        for(char symb : str_ip[i]){
            if(symb < '0' || symb > '9'){
                return {};
            }
        }

        int tmp = stoi(str_ip[i]);
        if(tmp > 255){
            return {};
        }

        res.push_back((uint8_t)tmp);

    }

    return res;
}

vector<IpAddress> getPoolIpAddresses(istream& in){
    vector<IpAddress> ip_pool;

    for(string line; getline(in, line);)
    {
        if(line == ""){
            break;
        }
        std::vector<std::string> v = split(line, '\t');
        IpAddress tmp_ip = ipValidator(split(v.at(0), '.'));
        if(tmp_ip.empty()){
            continue;
        } 

        ip_pool.push_back(move(tmp_ip));                   
    }

    
    sort(ip_pool.begin(), ip_pool.end(), VectorComparer());        

    return ip_pool;
}

vector<IpAddress> filter(const vector<IpAddress>& in_pool, uint8_t first_b){    
    auto range = equal_range(in_pool.begin(), in_pool.end(), vector<uint8_t>{first_b}, VectorComparer());
    return {range.first, range.second};
}

vector<IpAddress> filter(const vector<IpAddress>& in_pool, uint8_t first_b, uint8_t second_b){    
    auto range = equal_range(in_pool.begin(), in_pool.end(), vector<uint8_t>{first_b, second_b}, VectorComparer());
    return {range.first, range.second};
}

vector<IpAddress> filter_any(const vector<IpAddress>& in_pool, uint8_t any_b){
    vector<IpAddress> res;
    for(const auto& ip : in_pool){
        for(uint8_t byte : ip){
            if(byte == any_b){
                res.push_back(ip);
                break;
            }
        }
    }

    return res;
}