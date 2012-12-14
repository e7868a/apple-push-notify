#ifdef _WIN32
#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>
#else 
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <netdb.h>
#	include <arpa/inet.h>
#	include <string.h>
#	include <unistd.h>
#	include <fcntl.h>
#	include <errno.h>
#endif 

#include <stdlib.h>
#include <stdint.h>
#include <cassert>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <sstream>

#define MAX_PAYLOAD_SIZE 256
#define TOKEN_SIZE 32

class DeviceToken2Binary 
{
public:
	DeviceToken2Binary(const char* sz) {
		char buf[3] = {0};
		for (int i = 0;i < TOKEN_SIZE;i++)
		{
			const char* pin = sz + i * 2;
			buf[0] = pin[0];
			buf[1] = pin[1];


			int val = 0;
			sscanf(buf, "%X", &val);
			_binary[i] = val;
		}
	}



	const void* binary() {
		return _binary;
	}

private:
	unsigned char _binary[TOKEN_SIZE];
};



class DeviceBinary2Token
{
public:
	DeviceBinary2Token(const void* data) {
		unsigned char* pdata = (unsigned char*)data;
		for (int i = 0;i < TOKEN_SIZE;i++)
		{
			sprintf(_token + i * 2, "%02x", pdata[i]);
		}
	}

	const char* token() {
		return _token;
	}

private:
	char _token[TOKEN_SIZE * 2 + 1];
};


void Closesocket(int socket)
{
#ifdef _WIN32
	closesocket(socket);
#else 
	close(socket);
#endif 
}

void init_openssl()
{
#ifdef _WIN32
	WSADATA wsaData;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif 

    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SSL_CTX* init_ssl_context(
        const char* clientcert,                 /* 客户端的证书 */
        const char* clientkey,                  /* 客户端的Key */
        const char* keypwd,                     /* 客户端Key的密码, 如果有的话 */
        const char* cacert)                     /* 服务器CA证书 如果有的话 */
{
    // set up the ssl context
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        return NULL;
    }

    // certificate
    if (SSL_CTX_use_certificate_file(ctx, clientcert, SSL_FILETYPE_PEM) <= 0) {
        return NULL;
    }

    // key
    if (SSL_CTX_use_PrivateKey_file(ctx, clientkey, SSL_FILETYPE_PEM) <= 0) {
        return NULL;
    }

    // make sure the key and certificate file match
    if (SSL_CTX_check_private_key(ctx) == 0) {
        return NULL;
    }

    // load ca if exist
    if (cacert) {
        if (!SSL_CTX_load_verify_locations(ctx, cacert, NULL)) {
            return NULL;
        }
    }

    return ctx;
}

int tcp_connect(const char* host, int port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock = -1;

    if (!(hp = gethostbyname(host))) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return -1;
    }

    return sock;
}

SSL* ssl_connect(SSL_CTX* ctx, int socket)
{
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_socket(socket, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_connect(ssl) <= 0) {
        return NULL;
    }

    return ssl;
}

int verify_connection(SSL* ssl, const char* peername)
{
    int result = SSL_get_verify_result(ssl);
    if (result != X509_V_OK) {
		fprintf(stderr, "WARNING! ssl verify failed: %d", result);
        return -1;
    }

    X509 *peer;
    char peer_CN[256] = {0};

    peer = SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 255);
	if (strcmp(peer_CN, peername) != 0) {
		fprintf(stderr, "WARNING! Server Name Doesn't match, got: %s, required: %s", peer_CN,
			peername);
	}
    return 0;
}

void json_escape(std::string& str)
{
	size_t found = 0;
	while ((found = str.find('\\',found)) != std::string::npos) {
		str.replace(found, 1, "\\\\");
	}
	found = 0;
	while ((found = str.find('"',found)) != std::string::npos) {
		str.replace(found, 1, "\\\"");
	}
}

// Payload example

// {"aps":{"alert" : "You got your emails.","badge" : 9,"sound" : "default"}}
int build_payload(char* buf, int &buflen, const char* msg, int badage, const char * sound)
{
	std::ostringstream stream;
	stream << "{\"aps\":{\"alert\":\"";
	if (msg) {
		std::string strmsg(msg);
		json_escape(strmsg);
		stream << strmsg;
	}
	stream << "\"";

	stream << ",\"badge\":";
	stream << badage;
	
	if (sound) {
		stream << ",\"sound\":\"";
		std::string strsound(sound);
		json_escape(strsound);
		stream << strsound;
		stream << "\"";
	}

	stream << "}}";

	std::string result = stream.str();
	if ((int)result.length() > buflen) {
		buflen = result.length();
		return -1;
	}

	if ((int)result.length() < buflen) {
		strcpy(buf, result.c_str());
	} else {
		strncpy(buf, result.c_str(), buflen);
	}
	buflen = result.length();

	return buflen;
}

int build_output_packet(char* buf, int buflen, const char* tokenbinary, const char* msg, int badage, const char * sound)
{
	assert(buflen >= 1 + 2 + TOKEN_SIZE + 2 + MAX_PAYLOAD_SIZE);

	char * pdata = buf;
	// command
	*pdata = 0;

	// token length
	pdata++;
	*(uint16_t*)pdata = htons(TOKEN_SIZE);
	
	// token binary
	pdata += 2;
	memcpy(pdata, tokenbinary, TOKEN_SIZE);

	pdata += TOKEN_SIZE;

	int payloadlen = MAX_PAYLOAD_SIZE;
	if (build_payload(pdata + 2, payloadlen, msg, badage, sound) < 0) {
		std::string strmsg(msg);
		strmsg.erase(strmsg.length() - (payloadlen - MAX_PAYLOAD_SIZE));
		payloadlen = MAX_PAYLOAD_SIZE;
		if (build_payload(pdata + 2, payloadlen, msg, badage, sound) <= 0) {
			return -1;
		}
	}
	*(uint16_t*)pdata = htons(payloadlen);

	return 1 + 2 + TOKEN_SIZE + 2 + payloadlen;
}

int send_message(SSL *ssl, const char* token, const char* msg, int badage, const char* sound)
{
	char buf[1 + 2 + TOKEN_SIZE + 2 + MAX_PAYLOAD_SIZE];
	int buflen = sizeof(buf);

	buflen = build_output_packet(buf, buflen, (const char*)DeviceToken2Binary(token).binary(), msg, badage, sound);
	if (buflen <= 0) {
		return -1;
	}

	return SSL_write(ssl, buf, buflen);
}

int build_output_packet_2(char* buf, int buflen, uint32_t messageid, uint32_t expiry, const char* tokenbinary,  const char* msg, int badage, const char * sound)
{
	assert(buflen >= 1 + 2 + 4 + 4 + TOKEN_SIZE + 2 + MAX_PAYLOAD_SIZE);

	char * pdata = buf;
	// command
	*pdata = 1;

	// messageid
	pdata++;
	*(uint32_t*)pdata = messageid;

	// expiry time
	pdata += 4;
	*(uint32_t*)pdata = htonl(expiry);

	// token length
	pdata += 4;
	*(uint16_t*)pdata = htons(TOKEN_SIZE);

	// token binary
	pdata += 2;
	memcpy(pdata, tokenbinary, TOKEN_SIZE);

	pdata += TOKEN_SIZE;

	int payloadlen = MAX_PAYLOAD_SIZE;
	if (build_payload(pdata + 2, payloadlen, msg, badage, sound) < 0) {
		std::string strmsg(msg);
		strmsg.erase(strmsg.length() - (payloadlen - MAX_PAYLOAD_SIZE));
		payloadlen = MAX_PAYLOAD_SIZE;
		if (build_payload(pdata + 2, payloadlen, msg, badage, sound) <= 0) {
			return -1;
		}
	}
	*(uint16_t*)pdata = htons(payloadlen);

	return 1 + 4 + 4 + 2 + TOKEN_SIZE + 2 + payloadlen;
}

int send_message_2(SSL *ssl, const char* token, uint32_t id, uint32_t expire , const char* msg, int badage, const char* sound)
{
	char buf[1 + 4 + 4 + 2 + TOKEN_SIZE + 2 + MAX_PAYLOAD_SIZE];
	int buflen = sizeof(buf);

	buflen = build_output_packet_2(buf, buflen, id, expire, (const char*)DeviceToken2Binary(token).binary(), msg, badage, sound);
	if (buflen <= 0) {
		return -1;
	}

	return SSL_write(ssl, buf, buflen);
}

int main(int argc, char** argv)
{
    init_openssl();

    SSL_CTX *ctx = init_ssl_context("develop.pem", "develop.pem", NULL, "entrust_2048_ca.pem");
    if (!ctx) {
        fprintf(stderr, "init ssl context failed: %s\n", 
                ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

	const char* host = "gateway.sandbox.push.apple.com";
	const int port = 2195;
    int socket = tcp_connect(host, port);
    if (socket < 0) {
        fprintf(stderr, "failed to connect to host %s\n",
                strerror(errno));
        return -1;
    }

    SSL *ssl = ssl_connect(ctx, socket);
    if (!ssl) {
        fprintf(stderr, "ssl connect failed: %s\n", 
                ERR_reason_error_string(ERR_get_error()));
        Closesocket(socket);
        return -1;
    }

	if (verify_connection(ssl, host) != 0) {
		fprintf(stderr, "verify failed\n");
		Closesocket(socket);
		return 1;
	}

	uint32_t msgid = 1;
	uint32_t expire = time(NULL) + 24 * 3600;	// expire 1 day

	const char* token = "0a8b9e7cbe68616cd5470e4c8abb4c1a3f4ba2bee4ca113ff02ae2c325948b8a";
	if (send_message_2(ssl, token, msgid++, expire, "Hello, This is a push message", 1, "default") <= 0) {
		fprintf(stderr, "send failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
	}

	SSL_shutdown(ssl);
	Closesocket(socket);
	return 0;
}
