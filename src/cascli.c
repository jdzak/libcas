#include <stdio.h>
#include <string.h>
#include "cas.h"

void
usage() {
	fprintf(stderr,"%s\n","\n\
casvalidate [-p <(cas1)|cas2>] [-r] [-k] [-c </path/to/CA>] <validation_url> <escaped_service> <ST>\n\
\n\
-p : CAS Protocol - cas1, cas2.  Default: cas1\n\
-r : CAS Renew\n\
-k : Disable CAS server certificate validation. Certificate validation enabled if not specified.\n\
-c : Path to certificate authority, must be either a file for the correct CA, or a directory of CA files as expected by OpenSSL.  Relevant only if server validation is enabled (-C on, the default). Default: use libcurl's default.\n\
	");
}

int
main( int argc, char** argv ) {
	CAS_CODE code=CAS_FAIL;
	char* protocol="cas2";
	int cas_renew=0;
	char* cas_ca_location=NULL;
	int cas_ca_verify=1;
	char* cas_validation_url;
	char* cas_escaped_service;
	char* cas_service_ticket;
	
	int i=1;

	//Parse parameters
	while(i<argc && (argv[i][0]=='-')){
		cas_debug("Checking argument %d/%d: %s",i,argc, argv[i]);
		if(strcmp(argv[i],"-p")==0){
			i++;
			if(strcmp(argv[i],"cas1")==0){
				protocol=argv[i];
			}else if(strcmp(argv[i],"cas2")==0){
				protocol=argv[i];
			}else{
				fprintf(stderr,"Unknown protocol %s\n",argv[i]);
				usage();
				return(CAS_FAIL);
			}
		}else if(strcmp(argv[i],"-r")==0){
			cas_renew=1;
		}else if(strcmp(argv[i],"-c")==0){
			i++;
			cas_ca_location=argv[i];
		}else if(strcmp(argv[i],"-k")==0){
			cas_ca_verify=0;
		}else{
			fprintf(stderr,"Unknown option %s\n",argv[i]);
			usage();
			return(CAS_FAIL);
		}
		i++;
	}
           
	if( (argc-i)!=3 ) { //-- Check for arguments
		fprintf(stderr,"Too many arguments %d-%d\n",argc,i);
		usage();
		return(CAS_FAIL);
	}
	
	cas_validation_url=argv[i++];
	cas_escaped_service=argv[i++];
	cas_service_ticket=argv[i++];
	
	cas_debug("\nValidation URL: %s\nEscaped Service: %s\nService Ticket:%s\nProtocol: %s\nMode: %s\nCertificate Path: %s\nVerify Server Certificate: %s\n",cas_validation_url,cas_escaped_service,cas_service_ticket,protocol,cas_code_str_str(mode),(cas_ca_location?(cas_ca_location):("libcurl default")),(cas_ca_verify?("yes"):("no")));
	
	//-- Init libcas, obtain new CAS handle
	cas_init();
	CAS* cas=cas_new();
	if(cas_ca_verify){
		if(cas_ca_location){
			cas_set_ssl_ca(cas,cas_ca_location);
		}
		cas_set_ssl_validate_server(cas,1);
	}else{
		cas_set_ssl_validate_server(cas,0);
	}
	
	//-- Call appropriate validation function for supplied protocol
	if( strcmp(protocol,"cas1")==0 ) {
		code=cas_cas1_validate( cas,cas_validation_url,cas_escaped_service,cas_service_ticket, cas_renew);
	} else if( strcmp(protocol,"cas2")==0 ) {
		code=cas_cas2_servicevalidate( cas,cas_validation_url,cas_escaped_service,cas_service_ticket, cas_renew);
	}

	//-- Check code, act appropriately
	if( code==CAS_VALIDATION_SUCCESS ) {
		fprintf( stdout,"%s\n",cas_get_principal( cas ) );
	} else {
		fprintf( stderr,"(%d) %s: %s\n",code,cas_code_str( code ),cas_get_message(cas) );
	}

	cas_zap( cas );
	cas_destroy();

	return( code );
}
