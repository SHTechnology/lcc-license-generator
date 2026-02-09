/*
 * Project.cpp
 *
 *  Created on: Oct 22, 2019
 *      Author: GC
 */

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream>

#include "../inja/inja.hpp"
#include "../base_lib/base.h"
#include "../base_lib/crypto_helper.hpp"
#include "project.hpp"

namespace license {
namespace fs = boost::filesystem;
// using json = nlohmann::json;
using namespace std;


Project::Project(const std::string &name, const std::string &project_folder, bool force_overwrite)
	: m_name(name),
	  m_project_folder(project_folder),
	  m_force_overwrite(force_overwrite) {
	if (name.find('[') != std::string::npos || name.find(']') != std::string::npos ||
		name.find('/') != std::string::npos || name.find('\\') != std::string::npos) {
		throw invalid_argument("project name should not contain any of '[ ] / \' characters.");
	}
}

void Project::exportPublicKey(const std::string &path, const std::unique_ptr<CryptoHelper>& cryptoHelper) {
	cryptoHelper->exportPublicKeyPemFile(path);
}

FUNCTION_RETURN Project::initialize() {
	const fs::path destinationDir(fs::path(m_project_folder) / m_name);
	const fs::path publicKeyFile(destinationDir / PUBLIC_KEY_FNAME);
	const fs::path privateKeyFile(destinationDir / PRIVATE_KEY_FNAME);
	bool keyFilesExist = false;
	if (fs::exists(destinationDir)) {
		keyFilesExist = fs::exists(destinationDir / PRIVATE_KEY_FNAME);
		if (m_force_overwrite && keyFilesExist) {
			keyFilesExist = false;
			fs::remove(destinationDir / PRIVATE_KEY_FNAME);
			fs::remove(publicKeyFile);
		}
	} else if (!fs::create_directories(destinationDir) ) {
		throw std::runtime_error("Cannot create destination directory [" + destinationDir.string() + "]");
	}
	FUNCTION_RETURN result = FUNC_RET_OK;
	unique_ptr<CryptoHelper> cryptoHelper(CryptoHelper::getInstance());
	if (keyFilesExist) {
		if (!fs::exists(publicKeyFile)) {
			// how strange, private key was found, but public key is not.
			// Let's regenerate public key
			cryptoHelper->loadPrivateKey_file(privateKeyFile.string());
			exportPublicKey(publicKeyFile.string(), cryptoHelper);
		}
	} else {
		ofstream ofs;
		cryptoHelper->generateKeyPair();
		const std::string privateKey = cryptoHelper->exportPrivateKey();
		const string private_key_file_str = privateKeyFile.string();
		ofs.open(private_key_file_str.c_str(), std::fstream::trunc | std::fstream::binary);
		ofs << privateKey;
		ofs.close();
		exportPublicKey(publicKeyFile.string(), cryptoHelper);
	}
	return result;
}

Project::~Project() {}

} /* namespace license */
