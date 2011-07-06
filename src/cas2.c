/*******************************************************************************
 * cas2.c
 * 
 * CAS2 protocol handler
 * 
 * Why SAX instead of DOM?:
 * - Easy to prevent attack by never-ending XML (TODO)
 * - Easy to validate XML without an XML schema, and only as much as necessary
 * - I like hand- graphing and coding simple state machines
 */
 
/*******************************************************************************
 * [STATE, TOKEN] -> [STATE, ACTION]
 *******************************************************************************
 * [BEGIN, STARTDOC]->[NEED_OPENSERVICERESPONSE_WS,NULL]
 * 
 * [NEED_OPENSERVICERESPONSE_WS,WS] -> [NEED_OPENSERVICERESPONSE_WS,NULL]
 * [NEED_OPENSERVICERESPONSE_WS,OPENSERVICERESPONSE] -> [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_WS,NULL]
 * 
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_WS,WS] -> [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_WS, NULL]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_WS,OPENAUTHENTICATIONSUCCESS] -> [NEED_OPENUSER_WS,NULL]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_WS,OPENAUTHENTICATIONFAILURE] -> [NEED_FAILUREMESSAGE,setcode(code)]
 * 
 * [NEED_OPENUSER_WS,WS] -> [NEED_OPENUSER_WS,NULL]
 * [NEED_OPENUSER_WS,OPEN_USER] -> [NEED_USERCHARACTERS_CLOSEUSER,NULL]
 * 
 * [NEED_USERCHARACTERS_CLOSEUSER, CHARACTERS] -> [NEED_USERCHARACTERS_CLOSEUSER, append(principal,CHARACTERS)]
 * [NEED_USERCHARACTERS_CLOSEUSER, CLOSEUSER] -> [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 * 
 * [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, WS] -> [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 * [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, CLOSEAUTHENTICATIONSUCCESS] -> [NEED_CLOSESERVICERESPONSE_WS,NULL]
 *
 * [NEED_FAILUREMESSAGE, CHARACTERS] -> [NEED_FAILUREMESSAGE, append(message, CHARACTERS)]
 * [NEED_FAILUREMESSAGE, CLOSEAUTHENTICATIONFAILURE] -> [NEED_CLOSESERVICERESPONSE,NULL]
 *
 * 
 * [NEED_CLOSESERVICERESPONSE_WS,WS] -> [NEED_CLOSESERVICERESPONSE_WS,NULL]
 * [NEED_CLOSESERVICERESPONSE_WS,CLOSESERVICERESPONSE] -> [NEED_ENDDOC_WS,NULL]
 * 
 * [NEED_ENDDOC_WS,WS] -> [NEED_ENDDOC_WS,NULL]
 * [NEED_ENDDOC_WS,ENDDOC] -> [COMPLETE,COMPLETE]
 */

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <libxml/parser.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "cas.h"
#include "cas-int.h"

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


/*******************************************************************************
 * cas2_curl_callback: cURL callback accepting received data
 */
static size_t
cas_cas2_curl_callback( char* chunk, size_t size, size_t nmemb, xmlParserCtxtPtr ctx ) {
	size_t write_size=size*nmemb;
	xmlParseChunk( ctx,chunk,write_size,0 );
	return( write_size );
}

/*******************************************************************************
 * cas2 SAX handlers: SAX handlers to parse CAS2 XML and drive state machine
 */
static void
cas_cas2_startDocument( CAS_XML_STATE* ctx ) {
	switch(ctx->xml_state){
	case XML_NEED_START_DOC:
		debug( "XML_NEED_START_DOC->XML_NEED_OPEN_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_OPEN_SERVICERESPONSE;
	break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_serviceResponse( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_SERVICERESPONSE:
		debug( "XML_NEED_OPEN_SERVICERESPONSE->XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE" );
		ctx->xml_state=XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_authenticationSuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE:
		debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE->XML_NEED_OPEN_USER" );
		ctx->xml_state=XML_NEED_OPEN_USER;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_authenticationFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE:
		debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE->XML_READ_FAILUREMESSAGE" );
		int valuesz=attributes[4]-attributes[3];
		if(nb_attributes==1 && strncasecmp("code",attributes[0],4)==0){
			if(valuesz==15 && strncasecmp(attributes[3],"INVALID_REQUEST",valuesz)==0){
				ctx->cas->code=CAS2_INVALID_REQUEST;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else if(valuesz==14 && strncasecmp(attributes[3],"INVALID_TICKET",valuesz)==0){
				ctx->cas->code=CAS2_INVALID_TICKET;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else if(valuesz==15 && strncasecmp("INVALID_SERVICE",attributes[3],valuesz)==0){
				ctx->cas->code=CAS2_INVALID_SERVICE;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else if(valuesz==14 && strncasecmp("INTERNAL_ERROR",attributes[3],valuesz)==0){
				ctx->cas->code=CAS2_INTERNAL_ERROR;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else{
				ctx->xml_state=XML_FAIL;
			}
			debug("CODE=%d",ctx->cas->code);
		}else{
			ctx->xml_state=XML_FAIL;
		}
		
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_user( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_USER:
		debug( "XML_NEED_OPEN_USER->XML_READ_USER" );
		ctx->xml_state=XML_READ_USER;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_user( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_USER:
		debug( "XML_READ_USER->XML_NEED_CLOSE_AUTHENTICATIONSUCCESS" );
		ctx->xml_state=XML_NEED_CLOSE_AUTHENTICATIONSUCCESS;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_authenticationSuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_NEED_CLOSE_AUTHENTICATIONSUCCESS:
		debug( "XML_NEED_CLOSE_AUTHENTICATIONSUCCESS->XML_NEED_CLOSE_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_authenticationFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_FAILUREMESSAGE:
		debug( "XML_NEED_CLOSE_AUTHENTICATIONFAILURE->XML_NEED_CLOSE_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_serviceResponse( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch( ctx->xml_state){
	case XML_NEED_CLOSE_SERVICERESPONSE:
		debug( "XML_NEED_CLOSE_SERVICERESPONSE->XML_NEED_END_DOC" );
		ctx->xml_state=XML_NEED_END_DOC;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}

}

static void
cas_cas2_startElementNs( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	debug( "(%d) <(%s)%s:%s>",ctx->xml_state,prefix,URI,localname );
	if( strncasecmp( "http://www.yale.edu/tp/cas", URI, 26 )==0 ) {
		if ( strncasecmp( "serviceResponse",localname,15 )==0 ) {
			cas_cas2_start_cas_serviceResponse( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "authenticationSuccess",localname,21 )==0 ) {
			cas_cas2_start_cas_authenticationSuccess( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "authenticationFailure",localname,21 )==0 ) {
			cas_cas2_start_cas_authenticationFailure( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "user",localname,4 )==0 ) {
			cas_cas2_start_cas_user( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else {
			ctx->xml_state=XML_FAIL;
			debug( "XML_FAIL:(%d)",ctx->xml_state );
		}
	}
}

static void
cas_cas2_endElementNs( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	debug( "(%d) </(%s)%s:%s>",ctx->xml_state,prefix,URI,localname );
	if( strncasecmp( "http://www.yale.edu/tp/cas", URI, 26 )==0 ) {
		if ( strncasecmp( "serviceResponse",localname,15 )==0 ) {
			cas_cas2_end_cas_serviceResponse( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "authenticationSuccess",localname,21 )==0 ) {
			cas_cas2_end_cas_authenticationSuccess( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "authenticationFailure",localname,21 )==0 ) {
			cas_cas2_end_cas_authenticationFailure( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "user",localname,4 )==0 ) {
			cas_cas2_end_cas_user( ctx,localname,prefix,URI );
		} else {
			ctx->xml_state=XML_FAIL;
			debug( "XML_FAIL:(%d)",ctx->xml_state );
		}
	}
}

static void
cas_cas2_characters( CAS_XML_STATE* ctx, const xmlChar* ch, int len ) {
	int i;
	switch( ctx->xml_state ) {
	case XML_READ_USER:
		if( !ctx->cas->principal ) {
			ctx->cas->principal=calloc( len+1,sizeof( char ) );
			if(ctx->cas->principal==NULL) return;
			strncpy( ctx->cas->principal,ch,len );
			ctx->cas->principal[len]='\0';
		} else {
			void* tmp=ctx->cas->principal;
			ctx->cas->principal=realloc( ctx->cas->principal,strlen( ctx->cas->principal )+len+1 );
			if(ctx->cas->principal==NULL){
				free(tmp);
				return;
			}
			strncat( ctx->cas->principal,ch,len );
		}
	break;
	case XML_READ_FAILUREMESSAGE:
		if( !ctx->cas->message ) {
			ctx->cas->message=calloc( len+1,sizeof( char ) );
			if(ctx->cas->message==NULL) return;
			strncpy( ctx->cas->message,ch,len );
			ctx->cas->message[len]='\0';
		} else {
			
			void* tmp=ctx->cas->message;
			ctx->cas->message=realloc( ctx->cas->message,strlen( ctx->cas->message )+len+1 );
			if(ctx->cas->message==NULL){
				free(tmp);
				return;
			}
			strncat( ctx->cas->message,ch,len );
		}	
		debug("MESSAGE=%s",ctx->cas->message);
	break;
	default: //If unexpected characters are not whitespace, XML_FAIL
		for( i=0; i<len; i++ ) {
			if( !isspace( ch[i] ) ) ctx->xml_state=XML_FAIL;
		}
	}
}

static void
cas_cas2_endDocument( CAS_XML_STATE* ctx ) {
	if( ctx->xml_state==XML_NEED_END_DOC ) {
		debug( "XML_NEED_END_DOC->XML_COMPLETE" );
		ctx->xml_state=XML_COMPLETE;
	} else {
		ctx->xml_state=XML_FAIL;
		debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

/*******************************************************************************
 * cas_cas2_servicevalidate: Perform CAS2 validation protocol
 */
CAS_CODE
cas_cas2_servicevalidate( CAS* cas, char* cas1_validate_url, char* escaped_service, char* ticket, int renew ) {
	if(cas->principal) { free(cas->principal);cas->principal=NULL;}
	
	xmlSAXHandlerPtr sax=calloc( 1,sizeof( xmlSAXHandler ) );
	if(sax==NULL) return(CAS_ENOMEM);
	sax->initialized=XML_SAX2_MAGIC;

	sax->startElementNs=( startElementNsSAX2Func )cas_cas2_startElementNs;
	sax->endElementNs=( endElementNsSAX2Func )cas_cas2_endElementNs;
	sax->characters=( charactersSAXFunc )cas_cas2_characters;
	sax->startDocument=( startDocumentSAXFunc )cas_cas2_startDocument;
	sax->endDocument=( endDocumentSAXFunc )cas_cas2_endDocument;
	CAS_XML_STATE state= {cas,XML_NEED_START_DOC};

	xmlParserCtxtPtr ctx=xmlCreatePushParserCtxt( sax, &state, NULL,0,NULL );
	xmlCtxtUseOptions( ctx,XML_PARSE_NOBLANKS );

	//Build URL for validation
		//18=strlen("?service=")+strlen("&ticket=")+1
		//11=strlen("&renew=true")
	
	char* url;
	if(url=calloc( strlen( cas1_validate_url )+strlen( escaped_service )+strlen( ticket )+( renew?29:18 ),sizeof( char ) )){
		strcpy( url,cas1_validate_url );
		strcat( url,"?service=" );
		strcat( url,escaped_service );
		strcat( url,"&ticket=" );
		strcat( url,ticket );

		//Setup curl connection
		curl_easy_setopt( cas->curl,CURLOPT_URL, url );

		//Set response handler
		curl_easy_setopt( cas->curl,CURLOPT_WRITEFUNCTION, ( curl_write_callback )cas_cas2_curl_callback );

		//Pass state to response handler
		curl_easy_setopt( cas->curl,CURLOPT_WRITEDATA, ctx );
		int curl_status=curl_easy_perform( cas->curl );

		int xmlParseError = xmlParseChunk( ctx,NULL,0,1 );
		
		free(sax);
		free(url);
		xmlFreeParserCtxt(ctx);
		if(curl_status==0){
			if( state.xml_state==XML_COMPLETE ) {
				return( cas->code );
			}else if(xmlParseError){
				return(CAS2_INVALID_XML);
			}else{
				return(CAS_INVALID_RESPONSE);
			}
		} else {
			if(cas->message) { free(cas->message);}
			cas->message=strdup(curl_easy_strerror(curl_status));
			return(CAS_CURL_FAILURE);
		}
	}else{ //ENOMEM for url calloc
		return(CAS_ENOMEM);
	}
}
