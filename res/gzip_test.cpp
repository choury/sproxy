#include "gzip_test.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/util.h"
#include "misc/net.h"

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/eventfd.h>

static unsigned char in[16384];

GzipTest::GzipTest() {
    int fd = eventfd(1, O_NONBLOCK);
    if(fd < 0){
        LOGE("create evventfd failed: %s\n", strerror(errno));
        throw 0;
    }
    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int ret;
    if((ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY)) != Z_OK){
        LOGE("zlib init failed: %d\n", ret);
        throw 0;
    }

    rwer = new PacketRWer(fd, [this](int ret, int code){
        LOGE("gzip_test error: %d/%d\n", ret, code);
        deleteLater(ret);
    });

}

static size_t parseSize(std::string size){
	if(size.size() == 0 || !isdigit(size[0])){
		return 0;
	}
	size_t num = stoull(size);
	size_t unitPos = std::string::npos;
	for(size_t i = 0; i < size.size(); i++){
		if(!isdigit(size[i])){
			unitPos = i;
			break;
		}
	}
	if(unitPos == std::string::npos){
		return num;
	}
	std::string unit = size.substr(unitPos);
	switch(unit[0]){
	case 'k':
	case 'K':
		return num * 1024;
	case 'm':
	case 'M':
		return num * 1024 * 1024;
	case 'g':
	case 'G':
		return num * 1024 * 1024 * 1024;
	case 't':
	case 'T':
		return num * 1024 * 1024 * 1024 * 1024;
	}
	return 0;
}

void * GzipTest::request(HttpReqHeader* req) {
	HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
	res->set("Transfer-Encoding", "chunked");
	res->set("Content-Type", "application/octet-stream");
	res->set("Pragma", "no-cache");
	res->index = req->index;

	auto params = req->getparamsmap();
	if(params.count("size")){
		left = parseSize(params["size"]);
	}else{
		left = 1024ll*1024*1024*1024; //1T
	}
	const char* accept = req->get("Accept-Encoding");
	if(accept && strstr(accept, "gzip")){
		res->set("Content-Encoding", "gzip");
		rwer->SetReadCB(std::bind(&GzipTest::gzipreadHE, this, _1));
	}else{
		rwer->SetReadCB(std::bind(&GzipTest::rawreadHE, this, _1));
	}
	req->src->response(res);
	req_ptr = req->src;
	req_index = req->index;
	return (void*)1;
}

void GzipTest::gzipreadHE(size_t len) {
	rwer->consume(nullptr, len);
	rwer->buffer_insert(rwer->buffer_end(), (const void*)&left, 8);
	size_t chunk = req_ptr->bufleft(req_index);

	unsigned char* out = (unsigned char*)p_malloc(chunk);
	strm.next_out = out;
	strm.avail_out = chunk;
	/* run deflate() on input until output buffer not full, finish
	   compression if all of source has been read in */
	do {
		strm.next_in = in;
		strm.avail_in = Min(sizeof(in), left);
		left -= strm.avail_in;
		int ret = deflate(&strm, left ? Z_NO_FLUSH :Z_FINISH);    /* no bad return value */
		assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
	} while (strm.avail_out && left);

	req_ptr->Send(out, chunk - strm.avail_out, req_index);
	if(left == 0){
		(void)deflateEnd(&strm);
		req_ptr->finish(NOERROR | DISCONNECT_FLAG, req_index);
		deleteLater(NOERROR);
		return;
	}

	if(strm.avail_out == 0){
		rwer->delEpoll(EPOLLIN);
	}
}

void GzipTest::rawreadHE(size_t len) {
	rwer->consume(nullptr, len);
	rwer->buffer_insert(rwer->buffer_end(), (const void*)&left, 8);
	size_t chunk = req_ptr->bufleft(req_index);
	len = Min(chunk, left);
	if(len == chunk){
		rwer->delEpoll(EPOLLIN);
	}

	left -= len;
	unsigned char* out = (unsigned char*)p_malloc(len);
	req_ptr->Send(out, len, req_index);
	if(left == 0){
		(void)deflateEnd(&strm);
		req_ptr->finish(NOERROR | DISCONNECT_FLAG, req_index);
		deleteLater(NOERROR);
		return;
	}
}

ssize_t GzipTest::Send(void *buff, size_t size, __attribute__ ((unused)) void* index){
	assert((long)index == 1);
	p_free(buff);
	return size;
}

int32_t GzipTest::bufleft(__attribute__ ((unused)) void* index){
	assert((long)index == 1);
	return 0;
}

void GzipTest::finish(uint32_t flags, __attribute__ ((unused)) void* index){
	assert((long)index == 1);
	if(flags){
		(void)deflateEnd(&strm);
		deleteLater(flags);
	}
}

void GzipTest::dump_stat(Dumper dp, void* param){
	dp(param, "gzip_test: %p left=%zu\n", this, left);
}
