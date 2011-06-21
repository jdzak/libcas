#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <libxml/parser.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cas.h"
#include "cas-int.h"

/*******************************************************************************
 *  cas_init: must be run only once to initialize resources
 */
void*
cas_init() {
	curl_global_init( CURL_GLOBAL_ALL );
	LIBXML_TEST_VERSION
}

/*******************************************************************************
 * cas_destroy: must be run only once to cleanup anything init'd by cas_init
 */
void*
cas_destroy() {
	curl_global_cleanup();
	xmlCleanupParser();
}

/*******************************************************************************
 * cas_new: create a new handle to the CAS server
 */
CAS*
cas_new() {
	CAS* cas = calloc( 1,sizeof( CAS ) );

	cas->curl = curl_easy_init();
	curl_easy_setopt(cas->curl,CURLOPT_USERAGENT, PACKAGE_STRING );
	curl_easy_setopt(cas->curl, CURLOPT_HEADER, 0L); 
	curl_easy_setopt(cas->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(cas->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(cas->curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(cas->curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(cas->curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);

#ifndef LIBCURL_NO_CURLPROTO
	curl_easy_setopt(cas->curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif
	
#ifdef DEBUG
	curl_easy_setopt(cas->curl, CURLOPT_VERBOSE, 1L);
#else
	curl_easy_setopt(cas->curl, CURLOPT_VERBOSE, 0L);
#endif

		
	//TODO: SSL Locking Functions
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_CTX_FUNCTION, cas_curl_ssl_ctx);
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_CTX_DATA, c);

	//TODO: Validate the server?
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_VERIFYPEER, (c->CASValidateServer != FALSE ? 1L : 0L));

	//TODO: Certificate Paths
	////if(f.filetype == APR_DIR)
		//curl_easy_setopt(cas->curl, CURLOPT_CAINFO, "/home/matt/Dropbox/Projects/test/test.crt");
	////else if (f.filetype == APR_REG)
		////curl_easy_setopt(cas->curl, CURLOPT_CAINFO, c->CASCertificatePath);
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_VERIFYHOST, (c->CASValidateServer != FALSE ? 2L : 0L));



	return( cas );
}

/*******************************************************************************
 * cas_zap: destroy and cleanup the CAS handle and attached resources
 */
void
cas_zap( CAS* cas ) {
	if( cas->curl ) curl_easy_cleanup( cas->curl );
	if( cas->response.principal ) free( cas->response.principal );
	if( cas ) free( cas );
}

/*******************************************************************************
 * cas_get_principal: Retrieve a resolved principal
 */
char*
cas_get_principal( CAS* cas ) {
	return( cas->response.principal );
}

/*******************************************************************************
 * cas_codestr: Resolve string from CAS_CODE
 */
char*
cas_codestr( CAS_CODE code ) {
	switch( code ) {
	case CAS_VALIDATION_SUCCESS:
		return( "CAS: Validation Succeeded" );
	case CAS1_VALIDATION_NO:
		return( "CAS1: Validation Failed" );
	case CAS2_INVALID_REQUEST:
		return( "CAS2: Not all of the required request parameters were present" );
	case CAS2_INVALID_TICKET:
		return( "CAS2: The ticket provided was not valid, or the ticket did not come from an initial login and \"renew\" was set on validation" );
	case CAS2_INVALID_SERVICE:
		return( "CAS2: The ticket provided was valid, but the service specified did not match the service associated with the ticket" );
	case CAS2_INTERNAL_ERROR:
		return( "CAS2: An internal error occurred during ticket validation" );
	case CAS_FAIL:
		return( "LIBCAS: Internal Failure" );
	case CAS_INVALID_RESPONSE:
		return( "LIBCAS: Server returned invalid response");
	case CAS2_INVALID_XML:
		return( "LIBCAS: Server returned unparseable response");
	case CAS_CURL_FAILURE:
		return( "CURL: Error with cURL Subsystem" );
	default:
		return( "UNKNOWN CODE" );
	}
}

