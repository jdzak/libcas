/*******************************************************************************
 * gcc -L../src/.libs -lxml2 -lcurl -lcas simple.c -o simple
 *******************************************************************************/
 
#include <stdio.h>
#include <string.h>
#include "../src/cas.h"

int
main( int argc, char** argv ) {
	CAS_CODE code=CAS_FAIL;
	char* cas_service_ticket=(argc>1)?(argv[1]):(NULL);
	
	//-- Init libcas, EXACTLY once per process, before threading
	cas_init();
	
	//-- Obtain new CAS handle -- cannot be shared across threads
	CAS* cas=cas_new();
	
	//-- Set SSL Certificate location
	cas_set_ssl_ca(cas,"/etc/ssl/certs");
	
	//-- Enable certificate validation (default)
	cas_set_ssl_validate_server(cas,1);
	
	//-- Call validation function for supplied protocol
	//--   cas_cas2_servicevalidate(CAS Handle, Validation URL, Escaped Service, Service Ticket, Renew Flag);
	code=cas_cas2_servicevalidate( cas,"http://localhost:12345/cas/serviceValidate","http%3a%2f%2flocalhost%2f",cas_service_ticket, 0);
	
	//-- Check code, act appropriately
	if( code==CAS_VALIDATION_SUCCESS ) {
		//--  Retrieve principal from response
		fprintf( stdout,"%s\n",cas_get_principal( cas ) );
	} else {
		//-- Retrieve error message from response
		fprintf( stderr,"(%d) %s: %s\n",code,cas_code_str( code ),cas_get_message(cas) );
	}

	//-- Destroy handle
	cas_zap( cas );
	
	//-- Destroy libcas session
	cas_destroy();

	return( code );
}
