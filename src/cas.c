#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


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
void
cas_init() {
	curl_global_init( CURL_GLOBAL_ALL );
	LIBXML_TEST_VERSION
}

/*******************************************************************************
 * cas_destroy: must be run only once to cleanup anything init'd by cas_init
 */
void
cas_destroy() {
	curl_global_cleanup();
	xmlCleanupParser();
}

/*******************************************************************************
 * cas_new: create a new handle to the CAS server
 */
CAS*
cas_new() {
	CAS* cas = NULL;

	if((cas = calloc( 1,sizeof( CAS ) ))){
		cas->curl = curl_easy_init();
		curl_easy_setopt(cas->curl,CURLOPT_USERAGENT, PACKAGE_STRING );
		curl_easy_setopt(cas->curl, CURLOPT_HEADER, 0L); 
		curl_easy_setopt(cas->curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(cas->curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(cas->curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(cas->curl, CURLOPT_MAXREDIRS, 5L);
		curl_easy_setopt(cas->curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
		curl_easy_setopt(cas->curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS|CURLPROTO_FILE);
		
#define DEBUG 1
#ifdef DEBUG
		curl_easy_setopt(cas->curl, CURLOPT_VERBOSE, 1L);
#else
		curl_easy_setopt(cas->curl, CURLOPT_VERBOSE, 0L);
#endif

		
	//TODO: SSL Locking Functions
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_CTX_FUNCTION, cas_curl_ssl_ctx);
	////curl_easy_setopt(cas->curl, CURLOPT_SSL_CTX_DATA, c);

	}

	return( cas );
}

void
cas_set_ssl_ca( CAS* cas, const char* capath ){
	struct stat buf;
	stat(capath, &buf);
	
	if(S_ISDIR(buf.st_mode)){
		curl_easy_setopt(cas->curl, CURLOPT_CAPATH, capath);
		cas_debug("Setting CAPATH = %s",capath);
	}else if(S_ISREG(buf.st_mode)){
		curl_easy_setopt(cas->curl, CURLOPT_CAINFO, capath);
		cas_debug("Setting CAINFO = %s",capath);
	}else{
		cas_debug("I SHOULD NOT BE HERE - Setting SSL %s (%d)",capath, buf.st_mode);
	}
}

void
cas_set_ssl_validate_server( CAS* cas, int verify){
	curl_easy_setopt(cas->curl, CURLOPT_SSL_VERIFYPEER, (verify ? 1 : 0));
	curl_easy_setopt(cas->curl, CURLOPT_SSL_VERIFYHOST, (verify ? 2 : 0));
}

/*******************************************************************************
 * cas_zap: destroy and cleanup the CAS handle and attached resources
 */
void
cas_zap( CAS* cas ) {
	if(cas){
		if( cas->curl ) curl_easy_cleanup( cas->curl );
		if( cas->principal ) free( cas->principal );
		if( cas->pgtiou ) free( cas->pgtiou );
		if( cas->pgt ) free( cas->pgt );
		if( cas->proxy_ticket ) free( cas->proxy_ticket);
		if( cas->message ) free( cas->message );
		
		cas->curl=NULL;
		cas->principal=NULL;
		cas->pgtiou=NULL;
		cas->pgt=NULL;
		cas->proxy_ticket = NULL;
		cas->message=NULL;
		
		free( cas );
		
		cas=NULL;
	}
}

/*******************************************************************************
 * cas_get_principal: Retrieve a resolved principal
 */
char*
cas_get_principal( CAS* cas ) {
	return( cas->principal );
}

/*******************************************************************************
 * cas_get_message: Retrieve a resolved message
 */
char*
cas_get_message( CAS* cas ) {
	return( cas->message );
}

/*******************************************************************************
 * cas_get_pgtiou: Retrieve a resolved pgtiou
 */
char*
cas_get_pgtiou( CAS* cas ) {
	return( cas->pgtiou );
}

/*******************************************************************************
 * cas_get_pgt: Retrieve a resolved pgt
 */
char*
cas_get_pgt( CAS* cas ) {
	return( cas->pgt );
}

/*******************************************************************************
 * cas_get_proxy_ticket: Retrieve a proxy ticket
 */
char* 
cas_get_proxy_ticket( CAS* cas) {
	return( cas->proxy_ticket );
}

/*******************************************************************************
 * cas_code_str: Resolve string from CAS_CODE
 */
char*
cas_code_str( CAS_CODE code ) {
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
	case CAS_INVALID_PARAMETERS:
		return( "LIBCAS: Invalid Parameters Supplied" );
	default:
		return( "UNKNOWN CODE" );
	}
}
