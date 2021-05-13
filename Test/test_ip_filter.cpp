#include "ip_filter.h"
#include <gtest/gtest.h>
#include <sstream>
using namespace std;

TEST(TestIpFilter, OperatorLess){
    {
        vector<uint8_t> lhs = {};
        vector<uint8_t> rhs = {};
        VectorComparer comp;
        ASSERT_FALSE(comp(lhs, rhs));
        ASSERT_FALSE(comp(rhs, lhs));        
    }

    {
        vector<uint8_t> lhs = {};
        vector<uint8_t> rhs = {1, 2, 3, 4};
        VectorComparer comp;
        ASSERT_FALSE(comp(lhs, rhs));
        ASSERT_FALSE(comp(rhs, lhs));
    }

    {
        vector<uint8_t> lhs = {1, 2, 3, 4};
        vector<uint8_t> rhs = {};
        VectorComparer comp;
        ASSERT_FALSE(comp(lhs, rhs));
        ASSERT_FALSE(comp(rhs, lhs));                
    }

    {
        vector<uint8_t> lhs = {1, 2, 3, 4};
        vector<uint8_t> rhs = {1, 2};
        VectorComparer comp;
        ASSERT_FALSE(comp(lhs, rhs));
        ASSERT_FALSE(comp(rhs, lhs));        
    }

    {
        vector<uint8_t> lhs = {1, 2, 3, 4};
        vector<uint8_t> rhs = {1, 2, 3, 4};
        VectorComparer comp;
        ASSERT_FALSE(comp(lhs, rhs));
        ASSERT_FALSE(comp(rhs, lhs));                
    }

    {
        vector<uint8_t> lhs = {255, 0, 0, 0};
        vector<uint8_t> rhs = {254, 255, 255, 255};
        VectorComparer comp;
        ASSERT_TRUE(comp(lhs, rhs));        
    }

    {
        vector<uint8_t> lhs = {0, 0, 0, 1};
        vector<uint8_t> rhs = {0, 0, 0, 0};
        VectorComparer comp;
        ASSERT_TRUE(comp(lhs, rhs));        
    }
}

TEST(TestIpFilter, OutOperator){
    IpAddress ip = {192, 168, 23, 23};
    ostringstream out_str;
    out_str << ip;
    ASSERT_EQ(out_str.str(), string("192.168.23.23"));
}

TEST(TestIpFilter, IpValidator){
    {
        vector<string> str_ip = {};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {" 192", "168", "23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"192", "a68", "23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"192", "168", "-23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"192", "168", "23", "?23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"192", "168", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"192", "168", "23", "23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"256", "168", "23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.empty());
    }

    {
        vector<string> str_ip = {"255", "168", "23", "23"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.size() == SIZE_IP);
    }

    {
        vector<string> str_ip = {"0", "0", "0", "255"};
        vector<uint8_t> ip = ipValidator(str_ip);
        ASSERT_TRUE(ip.size() == SIZE_IP);
    }
}

TEST(TestIpFilter, PoolGenerating){
    istringstream s_str(string("192.168.23.5\t\n234.123.48.3\t\n200.150.34.4"));
    vector<IpAddress> ip_pool = getPoolIpAddresses(s_str);
    ASSERT_EQ(ip_pool.size(), 3);
    IpAddress test_ip = {234, 123, 48, 3};    
    ASSERT_EQ(ip_pool[0], test_ip);
    test_ip = {200,150,34,4};
    ASSERT_EQ(ip_pool[1], test_ip);
    test_ip = {192,168,23,5};
    ASSERT_EQ(ip_pool[2], test_ip);
}

TEST(TestIpFilter, FilterOneByte){
    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {254, 122, 48, 3},
                                     {253, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 254);
        ASSERT_EQ(ip_filt.size(), 2);

        IpAddress test_ip = {254, 123, 48, 3};
        ASSERT_EQ(ip_filt[0], test_ip);
        test_ip = {254, 122, 48, 3};
        ASSERT_EQ(ip_filt[1], test_ip);
    }

    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {253, 122, 48, 3},
                                     {252, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 253);
        ASSERT_EQ(ip_filt.size(), 1);
        IpAddress test_ip = {253, 122, 48, 3};
        ASSERT_EQ(ip_filt[0], test_ip);        
    }

    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {253, 122, 48, 3},
                                     {253, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 253);
        ASSERT_EQ(ip_filt.size(), 2);
        IpAddress test_ip = {253, 122, 48, 3};
        ASSERT_EQ(ip_filt[0], test_ip);
        test_ip = {253, 123, 48, 5};
        ASSERT_EQ(ip_filt[1], test_ip);                
    }    

    {
        vector<IpAddress> ip_pool = {{254, 123, 123, 123},
                                     {253, 123, 123, 123},
                                     {253, 123, 123, 123}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 123);
        ASSERT_TRUE(ip_filt.empty());                        
    }
}

TEST(TestIpFilter, FilterTwoBytes){
    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {254, 123, 43, 254},
                                     {252, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 254, 123);
        ASSERT_EQ(ip_filt.size(), 2);
        IpAddress test_ip = {254, 123, 48, 3};
        ASSERT_EQ(ip_filt[0], test_ip);
        test_ip = {254, 123, 43, 254};
        ASSERT_EQ(ip_filt[1], test_ip);
    }

    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {254, 122, 43, 254},
                                     {252, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 254, 122);
        ASSERT_EQ(ip_filt.size(), 1);
        IpAddress test_ip = {254, 122, 43, 254};
        ASSERT_EQ(ip_filt[0], test_ip);        
    }

    {
        vector<IpAddress> ip_pool = {{254, 123, 48, 3},
                                     {254, 122, 43, 254},
                                     {252, 123, 48, 5}
                                    };
        vector<IpAddress> ip_filt = filter(ip_pool, 254, 124);
        ASSERT_TRUE(ip_filt.empty());        
    }   
}

TEST(TestIpFilter, FilterAny){
    {
        vector<IpAddress> ip_pool = {{4, 3, 2, 1},
                                     {3, 3, 1, 2},
                                     {3, 1, 3, 2},
                                     {1, 3, 3, 2},
                                    };
        vector<IpAddress> ip_filt = filter_any(ip_pool, 1);
        ASSERT_EQ(ip_filt.size(), 4);        
    }   

    {
        vector<IpAddress> ip_pool = {{4, 3, 2, 1},
                                     {3, 3, 1, 2},
                                     {3, 1, 3, 2},
                                     {1, 3, 3, 2},
                                    };
        vector<IpAddress> ip_filt = filter_any(ip_pool, 4);
        ASSERT_EQ(ip_filt.size(), 1);
        IpAddress test_ip = {4, 3, 2, 1};
        ASSERT_EQ(ip_filt[0], test_ip);
    }
}