#include <stdio.h>
#include "cas.h"

int
main( int argc, char** argv ) {
	CAS_CODE code=CAS_FAIL;


	if( argc<4 ) { //-- Check for arguments
		printf( "./casvalidate <protocol> <validation_url> <escaped_service> <ST>\n" );
		return( CAS_FAIL );
	}

	//-- Init libcas, obtain new CAS handle
	cas_init();
	CAS* cas=cas_new();

	//-- Call appropriate validation function for supplied protocol
	if( strcmp( "cas1",argv[1] )==0 ) {
		code=cas_cas1_validate( cas,argv[2],argv[3],argv[4],0 );
	} else if( strcmp( "cas2",argv[1] )==0 ) {
		code=cas_cas2_servicevalidate( cas,argv[2],argv[3],argv[4],0 );
	}

	//-- Check code, act appropriately
	if( code==CAS_VALIDATION_SUCCESS ) {
		fprintf( stdout,"%s\n",cas_get_principal( cas ) );
	} else {
		fprintf( stderr,"(%d) %s: %s\n",code,cas_codestr( code ),cas_get_message(cas) );
	}

	cas_zap( cas );
	cas_destroy();

	return( code );
}
