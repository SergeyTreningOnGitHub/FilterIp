#pragma once
#include<string>
#include<vector>
#include<iostream>

constexpr size_t SIZE_IPV4 = 4;
constexpr size_t SIZE_IPV6 = 6;
constexpr size_t SIZE_IP = SIZE_IPV4;

using IpAddress = std::vector<uint8_t>;

class VectorComparer{
public:
    bool operator()(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs);
};

std::ostream& operator<<(std::ostream& out, const IpAddress& ip_addr);

std::vector<std::string> split(const std::string &str, char d);
IpAddress ipValidator(const std::vector<std::string>& str_ip);
std::vector<IpAddress> getPoolIpAddresses(std::istream& in);

std::vector<IpAddress> filter(const std::vector<IpAddress>& in_pool, uint8_t first_b);
std::vector<IpAddress> filter(const std::vector<IpAddress>& in_pool, uint8_t first_b, uint8_t second_b);

std::vector<IpAddress> filter_any(const std::vector<IpAddress>& in_pool, uint8_t any_b);