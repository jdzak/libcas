#include <stdio.h>
#include <string.h>
#include "../src/cas.h"
#include <unistd.h>

int
main( int argc, char** argv ) {
	CAS_CODE code=CAS_FAIL;
	
	int i,j,k=0;
	for(i=0; i<=100; i++){
		cas_init();
		for(j=0; j<=100; j++){
			CAS* cas=cas_new();

			for(k=0; k<=100; k++){
				//-- Call appropriate validation function for supplied protocol
				code=cas_cas2_servicevalidate( cas,"http://localhost:12345/serviceValidate","localhost","ST-12345", 0);

				//-- Check code, act appropriately
				if( code==CAS_VALIDATION_SUCCESS ) {
					fprintf( stdout,"%d:%d:%d %s\n",i,j,k,cas_get_principal( cas ) );
				} else {
					fprintf( stderr,"%d:%d:%d (%d) %s: %s\n",i,j,k,code,cas_code_str( code ),cas_get_message(cas) );
				}
			}
			cas_zap( cas );
		}
		cas_destroy();
	}
	return( code );
}
