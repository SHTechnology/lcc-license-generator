#define BOOST_TEST_MODULE test_project

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <fstream>
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <build_properties.h>

#include "../src/license_generator/project.hpp"
#include "../src/ini/SimpleIni.h"
#include "../src/base_lib/base.h"

namespace fs = boost::filesystem;
using namespace license;
using namespace std;

BOOST_AUTO_TEST_CASE(project_initialize) {
	const string project_name("TEST");
	const fs::path project_folder(fs::path(PROJECT_TEST_TEMP_DIR) / "product_initialize");
	const fs::path expectedPrivateKey(project_folder / project_name / PRIVATE_KEY_FNAME);
	const fs::path expectedPublicKey(project_folder / project_name / PUBLIC_KEY_FNAME);

	fs::remove_all(project_folder);
	BOOST_CHECK_MESSAGE(!fs::exists(expectedPrivateKey),
						"Private key " + expectedPrivateKey.string() + " can't be deleted.");
	BOOST_CHECK_MESSAGE(!fs::exists(expectedPrivateKey),
						"Public key " + expectedPrivateKey.string() + " can't be deleted.");

	Project prj(project_name, project_folder.string(), false);
	prj.initialize();

	BOOST_REQUIRE(fs::exists(expectedPrivateKey));
    BOOST_REQUIRE(fs::exists(expectedPublicKey));

    {
        std::ifstream in(expectedPublicKey.string());
        std::string content((std::istreambuf_iterator<char>(in)), {});

        BOOST_CHECK(content.find("BEGIN RSA PUBLIC KEY") != std::string::npos);
        BOOST_CHECK(content.find("END RSA PUBLIC KEY") != std::string::npos);
    }
    FILE* fp = fopen(expectedPublicKey.string().c_str(), "rb");
    BOOST_REQUIRE(fp);

    RSA* rsa = PEM_read_RSAPublicKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    BOOST_REQUIRE_MESSAGE(rsa != nullptr, "Public key format invalid");

    int bits = RSA_bits(rsa);
    BOOST_CHECK_MESSAGE(bits >= 1024, "RSA bits too small");

    RSA_free(rsa);
}

BOOST_AUTO_TEST_CASE(project_initialize_force)
{
    const string project_name("TEST");
    const fs::path project_folder(fs::path(PROJECT_TEST_TEMP_DIR) / "product_initialize_force");
    const fs::path privateKey(project_folder / project_name / PRIVATE_KEY_FNAME);
    const fs::path publicKey(project_folder / project_name / PUBLIC_KEY_FNAME);

    fs::remove_all(project_folder);
    {
        Project prj(project_name, project_folder.string(), false);
        prj.initialize();
    }

    BOOST_REQUIRE(fs::exists(privateKey));
    BOOST_REQUIRE(fs::exists(publicKey));

    std::ifstream in1(publicKey.string());
    std::string firstKey((std::istreambuf_iterator<char>(in1)), {});
    in1.close();

    {
        Project prj(project_name, project_folder.string(), true);  // ⭐ force
        prj.initialize();
    }

    BOOST_REQUIRE(fs::exists(publicKey));

    std::ifstream in2(publicKey.string());
    std::string secondKey((std::istreambuf_iterator<char>(in2)), {});
    in2.close();

    BOOST_CHECK_MESSAGE(firstKey != secondKey, "Force initialize should regenerate keys");
}

