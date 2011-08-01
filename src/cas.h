#ifndef CAS_H
#define CAS_H

typedef struct CAS CAS;

typedef enum {
	CAS_FAIL=-1,              // - Utter Failure, reason unknown
	CAS_VALIDATION_SUCCESS=0, // - Successful validation, principal (and more?) retrieved
	CAS1_VALIDATION_NO,       // - CAS1 validation was successfully performed, but returned no principal
	CAS2_INVALID_REQUEST,     // - CAS2 not all of the required request parameters were present
	CAS2_INVALID_TICKET,      // - CAS2 the ticket provided was not valid, or the ticket did not come from an initial login and "renew" was set on validation. The body of the <cas:authenticationFailure> block of the XML response SHOULD describe the exact details.
	CAS2_INVALID_SERVICE,     // - CAS2 the ticket provided was valid, but the service specified did not match the service associated with the ticket. CAS MUST invalidate the ticket and disallow future validation of that same ticket.
	CAS2_INTERNAL_ERROR,      // - CAS2 an internal error occurred during ticket validation
	CAS_INVALID_RESPONSE,	  // - CAS Server responded with something unparseable
	CAS_CURL_FAILURE,
	CAS2_INVALID_XML,
	CAS_ENOMEM,
	
} CAS_CODE;

typedef enum {
	CAS1,
	CAS2,
//	SAML11,
//	SAML20
} CAS_PROTOCOL;

void cas_init();
void cas_destroy();

CAS* cas_new();
void cas_zap( CAS* cas );

CAS_CODE cas_cas1_validate( CAS* cas, char* cas1_validate_url, char* escaped_service, char* ticket, int renew);
CAS_CODE cas_cas2_servicevalidate( CAS* cas, char* cas2_servicevalidate_url, char* escaped_service, char* ticket, int renew);
const char* cas_protocol_str(CAS_PROTOCOL protocol);

char* cas_get_principal( CAS* cas );
#define cas_get_message cas_get_principal
#endif

#ifdef DEBUG
#define cas_debug(format, args...) fprintf(stderr,"\n**********\n[%s(%d):%s]:\n" format "\n**********\n", __FILE__,__LINE__,__func__,## args)
#else
#define cas_debug(format, args...)
#endif
