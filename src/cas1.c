#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cas.h"
#include "cas-int.h"

/*******************************************************************************
 * cas1_curl_callback: cURL callback accepting received data
 */
static size_t
cas_cas1_curl_callback( char* ptr, size_t size, size_t nmemb, CAS_BUFFER* buffer ) {
	size_t write_size=size*nmemb;

	buffer->contents=realloc( buffer->contents, buffer->size+write_size );
	memcpy( &buffer->contents[buffer->size],ptr,write_size );

	buffer->size=buffer->size+write_size;
	return( write_size );
}

/*******************************************************************************
 * cas_cas1_validate: Perform CAS1 validation protocol, parsing cas->buffer
 *  to obtain principal and store it in cas->response.principal.
 */
CAS_CODE
cas_cas1_validate( CAS* cas, char* cas1_validate_url, char* escaped_service, char* ticket, int renew ) {

	CAS_BUFFER buffer= {0,NULL};
	buffer.contents=malloc( 1*sizeof( char ) );
	strcpy( buffer.contents,"" );
	CAS_CODE rc=CAS_FAIL;

	//Build URL for validation
	//18=strlen("?service=")+strlen("&ticket=")+1
	//11=strlen("&renew=true")
	char* url=calloc( strlen( cas1_validate_url )+strlen( escaped_service )+strlen( ticket )+( renew?29:18 ),sizeof( char ) );
	strcpy( url,cas1_validate_url );
	strcat( url,"?service=" );
	strcat( url,escaped_service );
	strcat( url,"&ticket=" );
	strcat( url,ticket );

	//Setup curl connection
	curl_easy_setopt( cas->curl,CURLOPT_URL, url );

	//Set response handler
	curl_easy_setopt( cas->curl,CURLOPT_WRITEFUNCTION, ( curl_write_callback )cas_cas1_curl_callback );

	//Pass state to response handler
	curl_easy_setopt( cas->curl,CURLOPT_WRITEDATA, &buffer );

	int status=curl_easy_perform( cas->curl );
	if( status==0 ) {
		if( ( buffer.size )==4 && strncmp( buffer.contents,"no\n\n",4 )==0 ) {
			rc=CAS1_VALIDATION_NO;
		} else if( buffer.size>4 && strncmp( buffer.contents,"yes\n",4 )==0 ) {
			int i;
			for( i=0; ( buffer.contents[4+i]!='\0' && buffer.contents[4+i]!='\n' && i<=buffer.size ); i++ );
			cas->response.principal=realloc( cas->response.principal,( i )*sizeof( char ) );
			strncpy( cas->response.principal,&buffer.contents[4],i );
			cas->response.principal[buffer.size-4]='\0';
			rc=CAS_VALIDATION_SUCCESS;
		}else{
			rc=CAS_INVALID_RESPONSE;
		}
	} else {
		rc=CAS_CURL_FAILURE;
		cas->response.message=strdup(curl_easy_strerror(status));
	}
	
	
	free( buffer.contents );
	return( rc );
}
