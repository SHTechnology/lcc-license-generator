/*
 * CryptpHelperLinux.h
 *
 *  Created on: Sep 14, 2014
 *
 */

#ifndef CRYPTPHELPERLINUX_H_
#define CRYPTPHELPERLINUX_H_

#include <openssl/evp.h>
#include <cstddef>
#include <string>
#include <vector>
#include "../crypto_helper.hpp"

namespace license {
using namespace std;

class CryptoHelperLinux : public CryptoHelper {
private:
	static const int kBits = 1024;
	static const int kExp = 65537;
	EVP_PKEY *m_pktmp;
	const string Opensslb64Encode(const size_t slen, const unsigned char *signature) const;	
public:
	CryptoHelperLinux();
	// disable copy constructor
	CryptoHelperLinux(const CryptoHelperLinux &) = delete;

	virtual void generateKeyPair() override;
	const virtual string exportPrivateKey() const override;
	const virtual std::vector<unsigned char> exportPublicKey() const override;
	virtual void loadPrivateKey(const std::string &privateKey) override;
	const virtual string signString(const string &stringToBeSigned) const override;
	void exportPublicKeyPemFile(const std::string& path) const override; 
	
	virtual ~CryptoHelperLinux();
};

} /* namespace license */

#endif /* CRYPTPHELPERLINUX_H_ */
