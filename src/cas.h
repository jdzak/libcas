/**
 *
 * \mainpage cas.h - libcas API
 *
 * Basic library usage is as follows:
@code
#include <cas.h>

//Initialize and get handle
cas_init();
CAS* cas=cas_new();

//Set paramaters
cas_set_ssl_validate_server(cas,1);
cas_set_ssl_ca(cas,"/etc/ssl/certs");

//Do the validation
CAS_CODE code=cas_cas2_servicevalidate(cas, "http://localhost:12345/cas/serviceValidate", "http%3a%2f%2flocalhost%2f", cas_service_ticket, 0);

//Check the response and retrieve results
if( code==CAS_VALIDATION_SUCCESS ) {
	char* p=cas_get_principal( cas );
} else {
	char* m=cas_get_message(cas);
}

//Teardown
cas_zap( cas );
cas_destroy();
@endcode
 */
#ifndef CAS_H
#define CAS_H

typedef struct CAS CAS;

typedef enum {
	CAS_FAIL=-1,				// - Utter Failure, reason unknown
	CAS_VALIDATION_SUCCESS=0,	// - Successful validation, principal (and more?) retrieved
	CAS1_VALIDATION_NO,			// - CAS1 validation was successfully performed, but returned no principal
	CAS2_INVALID_REQUEST,		// - CAS2 not all of the required request parameters were present
	CAS2_INVALID_TICKET,		// - CAS2 the ticket provided was not valid, or the ticket did not come from an initial login and "renew" was set on validation. The body of the <cas:authenticationFailure> block of the XML response SHOULD describe the exact details.
	CAS2_INVALID_SERVICE,		// - CAS2 the ticket provided was valid, but the service specified did not match the service associated with the ticket. CAS MUST invalidate the ticket and disallow future validation of that same ticket.
	CAS2_INTERNAL_ERROR,		// - CAS2 an internal error occurred during ticket validation
	CAS2_BAD_PGT,           // - CAS2 the pgt provided was invalid
	CAS_INVALID_RESPONSE,		// - CAS Server responded with something unparseable
	CAS_CURL_FAILURE,			// - Failure in underlying cURL subsystem
	CAS2_INVALID_XML,			// - XML response invalid
	CAS_ENOMEM,					// - Out of memory
	CAS_INVALID_PARAMETERS,		// - Invalid parameters supplied

} CAS_CODE;

void cas_init();
void cas_destroy();

CAS* cas_new();
void cas_zap( CAS* cas );

/**
 *	Perform CAS1 validation
 *  @param cas a CAS handle supplied by cas_new(). cas_get_principal(cas) or cas_get_message(cas) can be used to fetch results of this function call.
 *  @param cas1_validate_url the URL for the CAS1 validation service.
 *  @param escaped_service the escaped service name.
 *  @param ticket the service ticket to be validated.
 *  @param renew flag (1=true) to specify that the ticket was obtained with renew.
 *  @return a CAS_CODE representing the status of the request.
 */
CAS_CODE cas_cas1_validate( CAS* cas, char* cas1_validate_url, char* escaped_service, char* ticket, int renew);
CAS_CODE cas_cas2_servicevalidate( CAS* cas, char* cas2_servicevalidate_baseurl, char* escaped_service, char* ticket, int renew);
CAS_CODE cas_cas2_serviceValidate_proxyTicketing( CAS* cas, char* cas2_servicevalidate_baseurl, char* escaped_service, char* ticket, int renew, char* escaped_pgt_receive_url, char* pgt_retrieve_url);
char* cas_cas2_serviceValidateUrl( char* cas2_servicevalidate_url, char* escaped_service, char* ticket, int renew, char* escaped_pgt_url);
char* cas_cas2_retrievePgtUrl(char* url, char* pgtiou);
char* cas_cas2_retrievePgt(char* url, CAS* cas);
CAS_CODE cas_cas2_proxy( CAS* cas, char* cas2_proxy_baseurl, char* escaped_service, char* proxy_granting_ticket);
char* cas_cas2_proxyUrl(char* base_url, char* escaped_service, char* proxy_granting_ticket );

char* cas_get_principal( CAS* cas );
char* cas_get_message( CAS* cas );
char* cas_get_pgtiou( CAS* cas );
char* cas_get_pgt( CAS* cas );
char* cas_get_proxy_ticket( CAS* cas);

#endif

#ifdef DEBUG
#define cas_debug(format, args...) fprintf(stderr,"\n**********\n[%s(%d):%s]:\n" format "\n**********\n", __FILE__,__LINE__,__func__,## args)
#else
#define cas_debug(format, args...)
#endif
