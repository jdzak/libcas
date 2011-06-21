#include <curl/curl.h>
#include <libxml/parser.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cas.h"

#ifndef CAS_INT_H
#define CAS_INT_H

#ifdef DEBUG
#define debug(format, args...) fprintf(stderr,"[%s(%d):%s] " format "\n", __FILE__,__LINE__,__func__,## args)
#else
#define debug(format, args...)
#endif

struct CAS {
	CURL* curl;

	struct {
		CAS_CODE code;
		union{
			char* principal;
			char* message;
		};
		//hashmap? attributes;
	} response;

};

typedef struct {
	size_t size;
	char* contents;
} CAS_BUFFER;

typedef struct {
	CAS* cas;
	enum {
		XML_FAIL=-1,
		XML_NEED_START_DOC=0,
		XML_NEED_OPEN_SERVICERESPONSE,
		XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE,
		XML_NEED_OPEN_USER,
		XML_READ_USER,
		XML_NEED_CLOSE_USER,
		XML_NEED_CLOSE_AUTHENTICATIONSUCCESS,
		XML_READ_FAILUREMESSAGE,
		XML_NEED_CLOSE_SERVICERESPONSE,
		XML_NEED_END_DOC,
		XML_COMPLETE,
	} xml_state;
} CAS_XML_STATE;



#endif
