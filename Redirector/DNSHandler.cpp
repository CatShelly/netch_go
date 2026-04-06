#include "DNSHandler.h"

#include "SocksHelper.h"
#include <algorithm>
#include <cctype>

extern bool dnsProx;
extern string dnsHost;
extern USHORT dnsPort;
extern vector<string> dnsDomainRules;

SOCKADDR_IN6 dnsAddr;

void HandleClientDNS(ENDPOINT_ID id, PSOCKADDR_IN6 target, char* packet, int length, PNF_UDP_OPTIONS option)
{
	int family = (dnsAddr.sin6_family == AF_INET) ? AF_INET : AF_INET6;
	auto remote = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (remote != INVALID_SOCKET)
	{
		bool ready = true;
		if (family == AF_INET6)
		{
			int v6only = 0;
			if (setsockopt(remote, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only)) == SOCKET_ERROR)
			{
				printf("[Redirector][DNSHandler] setsockopt(IPV6_V6ONLY) failed: %d\n", WSAGetLastError());
				ready = false;
			}
		}

		if (ready)
		{
			if (family == AF_INET)
			{
				SOCKADDR_IN addr;
				memset(&addr, 0, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

				if (bind(remote, (PSOCKADDR)&addr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
				{
					printf("[Redirector][DNSHandler] bind IPv4 failed: %d\n", WSAGetLastError());
					ready = false;
				}
			}
			else
			{
				SOCKADDR_IN6 addr;
				IN6ADDR_SETANY(&addr);

				if (bind(remote, (PSOCKADDR)&addr, sizeof(SOCKADDR_IN6)) == SOCKET_ERROR)
				{
					printf("[Redirector][DNSHandler] bind IPv6 failed: %d\n", WSAGetLastError());
					ready = false;
				}
			}

			if (ready)
			{
				int targetLen = (dnsAddr.sin6_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6));
				if (sendto(remote, packet, length, 0, (PSOCKADDR)&dnsAddr, targetLen) == length)
				{
					timeval timeout{};
					timeout.tv_sec = 4;

					fd_set fds;
					FD_ZERO(&fds);
					FD_SET(remote, &fds);

					int size = select(NULL, &fds, NULL, NULL, &timeout);
					if (size != 0 && size != SOCKET_ERROR)
					{
						char buffer[1024];

						size = recvfrom(remote, buffer, sizeof(buffer), 0, NULL, NULL);
						if (size != 0 && size != SOCKET_ERROR)
							nf_udpPostReceive(id, (PBYTE)target, buffer, size, option);
						else
							printf("[Redirector][DNSHandler] recvfrom failed: %d\n", WSAGetLastError());
					}
				}
				else
				{
					printf("[Redirector][DNSHandler] sendto failed: %d\n", WSAGetLastError());
				}
			}
		}
	}
	else
	{
		printf("[Redirector][DNSHandler] create UDP socket failed: %d\n", WSAGetLastError());
	}

	if (remote != INVALID_SOCKET)
		closesocket(remote);

	delete target;
	delete[] packet;
	delete[] option;
}

void HandleRemoteDNS(ENDPOINT_ID id, PSOCKADDR_IN6 target, char* packet, int length, PNF_UDP_OPTIONS option)
{
	auto remote = new SocksHelper::UDP();
	if (remote->Associate())
	{
		if (remote->CreateUDP())
		{
			if (remote->Send(&dnsAddr, packet, length) == length)
			{
				char buffer[1024];

				timeval timeout{};
				timeout.tv_sec = 4;

				int size = remote->Read(NULL, buffer, sizeof(buffer), &timeout);
				if (size != 0 && size != SOCKET_ERROR)
					nf_udpPostReceive(id, (PBYTE)target, buffer, size, option);
			}
		}
	}

	delete remote;
	delete target;
	delete[] packet;
	delete[] option;
}

bool DNSHandler::INIT()
{
	memset(&dnsAddr, 0, sizeof(dnsAddr));

	auto ipv4 = (PSOCKADDR_IN)&dnsAddr;
	if (inet_pton(AF_INET, dnsHost.c_str(), &ipv4->sin_addr) == 1)
	{
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(dnsPort);
		return true;
	}

	auto ipv6 = (PSOCKADDR_IN6)&dnsAddr;
	if (inet_pton(AF_INET6, dnsHost.c_str(), &ipv6->sin6_addr) == 1)
	{
		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons(dnsPort);
		return true;
	}

	return false;
}

static bool IsLikelyDNSPacket(const char* packet, int length)
{
	if (packet == nullptr || length < 12)
		return false;

	auto data = reinterpret_cast<const unsigned char*>(packet);
	USHORT flags = static_cast<USHORT>((data[2] << 8) | data[3]);
	USHORT opcode = static_cast<USHORT>((flags >> 11) & 0x0f);
	USHORT question = static_cast<USHORT>((data[4] << 8) | data[5]);
	USHORT answer = static_cast<USHORT>((data[6] << 8) | data[7]);
	USHORT authority = static_cast<USHORT>((data[8] << 8) | data[9]);
	USHORT additional = static_cast<USHORT>((data[10] << 8) | data[11]);
	bool isResponse = (flags & 0x8000) != 0;

	// Accept common DNS opcodes and require at least one section to be present.
	if (opcode > 5)
		return false;
	if (question + answer + authority + additional == 0)
		return false;
	if (!isResponse && question == 0)
		return false;
	return true;
}

bool DNSHandler::IsDNS(PSOCKADDR_IN6 target, const char* packet, int length)
{
	if (target->sin6_family == AF_INET)
	{
		if (((PSOCKADDR_IN)target)->sin_port == htons(53))
			return true;
	}
	else
	{
		if (target->sin6_port == htons(53))
			return true;
	}
	return IsLikelyDNSPacket(packet, length);
}

static string NormalizeLower(string value)
{
	size_t start = value.find_first_not_of(" \t\r\n");
	if (start == string::npos)
	{
		return "";
	}
	size_t end = value.find_last_not_of(" \t\r\n");
	value = value.substr(start, end - start + 1);
	transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
	return value;
}

static bool MatchWildcardPattern(const string& input, const string& pattern)
{
	size_t inputPos = 0;
	size_t patternPos = 0;
	size_t starPos = string::npos;
	size_t backtrackPos = 0;

	while (inputPos < input.size())
	{
		if (patternPos < pattern.size() && pattern[patternPos] == '*')
		{
			starPos = patternPos++;
			backtrackPos = inputPos;
			continue;
		}
		if (patternPos < pattern.size() && pattern[patternPos] == input[inputPos])
		{
			patternPos++;
			inputPos++;
			continue;
		}
		if (starPos != string::npos)
		{
			patternPos = starPos + 1;
			inputPos = ++backtrackPos;
			continue;
		}
		return false;
	}

	while (patternPos < pattern.size() && pattern[patternPos] == '*')
	{
		patternPos++;
	}

	return patternPos == pattern.size();
}

string DNSHandler::ExtractQueryDomain(const char* packet, int length)
{
	if (packet == nullptr || length < 13)
	{
		return "";
	}

	auto data = reinterpret_cast<const unsigned char*>(packet);
	USHORT qdCount = static_cast<USHORT>((data[4] << 8) | data[5]);
	if (qdCount == 0)
	{
		return "";
	}

	size_t offset = 12;
	string domain;
	bool hasLabel = false;

	while (offset < static_cast<size_t>(length))
	{
		unsigned char labelLength = data[offset];
		if (labelLength == 0)
		{
			offset++;
			break;
		}
		if ((labelLength & 0xC0) != 0)
		{
			return "";
		}

		offset++;
		if (offset + labelLength > static_cast<size_t>(length))
		{
			return "";
		}

		if (hasLabel)
		{
			domain.push_back('.');
		}
		for (unsigned char i = 0; i < labelLength; i++)
		{
			unsigned char ch = data[offset + i];
			if (ch < 32 || ch > 126)
			{
				return "";
			}
			domain.push_back(static_cast<char>(tolower(ch)));
		}
		offset += labelLength;
		hasLabel = true;
	}

	if (!hasLabel)
	{
		return "";
	}

	return domain;
}

bool DNSHandler::MatchDomainRules(const string& domain)
{
	auto normalizedDomain = NormalizeLower(domain);
	if (normalizedDomain.empty())
	{
		return false;
	}

	for (auto rawRule : dnsDomainRules)
	{
		auto rule = NormalizeLower(rawRule);
		if (rule.empty())
		{
			continue;
		}
		if (rule[0] == '.')
		{
			rule = "*" + rule;
		}
		if (MatchWildcardPattern(normalizedDomain, rule))
		{
			return true;
		}
	}

	return false;
}

wstring DNSHandler::GetRemoteDNS()
{
	WCHAR buffer[MAX_PATH] = L"";
	DWORD bufferLength = MAX_PATH;

	if (dnsAddr.sin6_family == AF_INET)
	{
		SOCKADDR_IN addr{};
		memcpy(&addr, &dnsAddr, sizeof(SOCKADDR_IN));
		WSAAddressToStringW((PSOCKADDR)&addr, sizeof(SOCKADDR_IN), NULL, buffer, &bufferLength);
	}
	else
	{
		WSAAddressToStringW((PSOCKADDR)&dnsAddr, sizeof(SOCKADDR_IN6), NULL, buffer, &bufferLength);
	}

	return buffer;
}

void DNSHandler::CreateHandler(ENDPOINT_ID id, PSOCKADDR_IN6 target, const char* packet, int length, PNF_UDP_OPTIONS options)
{
	auto remote = new SOCKADDR_IN6();
	auto buffer = new char[length]();
	auto option = (PNF_UDP_OPTIONS)new char[sizeof(NF_UDP_OPTIONS) + options->optionsLength];

	memcpy(remote, target, sizeof(SOCKADDR_IN6));
	memcpy(buffer, packet, length);
	memcpy(option, options, sizeof(NF_UDP_OPTIONS) + options->optionsLength - 1);

	if (!dnsProx)
		thread(HandleClientDNS, id, remote, buffer, length, option).detach();
	else
		thread(HandleRemoteDNS, id, remote, buffer, length, option).detach();
}
