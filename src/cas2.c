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
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS,WS] -> [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS, NULL]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS,OPENAUTHENTICATIONSUCCESS] -> [NEED_OPENUSER_WS,NULL]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS,OPENAUTHENTICATIONFAILURE] -> [NEED_FAILUREMESSAGE,setcode(code)]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS,OPENPROXYSUCCESS] -> [NEED_OPENPROXYTICKET_SW,NULL]
 * [NEED_OPENAUTHENTICATIONSUCCESS_OPENAUTHENTICATIONFAILURE_OPENPROXYSUCCESS_OPENPROXYFAILURE_WS,OPENPROXYFAILURE] -> [NEED_FAILUREMESSAGE,setcode(code)]
 * 
 * [NEED_OPENUSER_WS,WS] -> [NEED_OPENUSER_WS,NULL]
 * [NEED_OPENUSER_WS,OPEN_USER] -> [NEED_USERCHARACTERS_CLOSEUSER,NULL]
 * 
 * [NEED_USERCHARACTERS_CLOSEUSER, CHARACTERS] -> [NEED_USERCHARACTERS_CLOSEUSER, append(principal,CHARACTERS)]
 * [NEED_USERCHARACTERS_CLOSEUSER, CLOSEUSER] -> [NEED_OPENPGT_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 *
 * [NEED_OPENPROXYTICKET_WS,WS] -> [NEED_OPENPROXYTICKET_WS,NULL]
 * [NEED_OPENPROXYTICKET_WS,OPEN_PROXYTICKET] -> [NEED_PROXYTICKETCHARACTERS_CLOSEPROXYTICKET, NULL]
 *
 * [NEED_PROXYTICKETCHARACTERS_CLOSEPROXYTICKET_WS, CHARACTERS] -> [NEED_PROXYTICKETCHARACTERS_CLOSEPROXYTICKET, append(proxyticket),CHARACTERS)]
 * [NEED_PROXYTICKETCHARACTERS_CLOSEPROXYTICKET] -> [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 *
 * [NEED_OPENPGT_WS,WS] -> [NEED_OPENPGT_WS,NULL]
 * [NEED_OPENPGT_WS,OPEN_PGT] -> [NEED_PGTCHARACTERS_CLOSEPGT,NULL] 
 *
 * [NEED_PGTCHARACTERS_CLOSEPGT, CHARACTERS] -> [NEED_PGTCHARACTERS_CLOSEPGT, append(pgtiou,CHARACTERS)]
 * [NEED_PGTCHARACTERS_CLOSEPGT, CLOSEPGT] -> [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 *
 * [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, WS] -> [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, NULL]
 * [NEED_CLOSEAUTHENTICATIONSUCCESS_WS, CLOSEAUTHENTICATIONSUCCESS] -> [NEED_CLOSESERVICERESPONSE_WS,NULL]
 *
 * [NEED_FAILUREMESSAGE, CHARACTERS] -> [NEED_FAILUREMESSAGE, append(message, CHARACTERS)]
 * [NEED_FAILUREMESSAGE, CLOSEAUTHENTICATIONFAILURE_CLOSEPROXYFAILURE] -> [NEED_CLOSESERVICERESPONSE,NULL]
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
		XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE,
		XML_NEED_OPEN_USER,
		XML_READ_USER,
		XML_NEED_OPEN_PROXYGRANTINGTICKET_CLOSE_AUTHENTICATIONSUCCESS,
		XML_READ_PROXYGRANTINGTICKET,
		XML_NEED_OPEN_PROXYTICKET_CLOSE_PROXYSUCCESS,
		XML_READ_PROXYTICKET,
		XML_NEED_CLOSE_USER,
		XML_NEED_CLOSE_PROXYSUCCESS,
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
 * cas_cas2_curl_retrievepgt_callback: cURL callback accepting received pgt data
 */
static size_t
cas_cas2_curl_retrievepgt_callback( char* chunk, size_t size, size_t nmemb, void *userp  ) {
	char **response_ptr =  (char**)userp;
	*response_ptr = strndup(chunk, (size_t)(size *nmemb));
	return( size*nmemb );}

/*******************************************************************************
 * cas2 SAX handlers: SAX handlers to parse CAS2 XML and drive state machine
 */
static void
cas_cas2_startDocument( CAS_XML_STATE* ctx ) {
	switch(ctx->xml_state){
	case XML_NEED_START_DOC:
		cas_debug( "XML_NEED_START_DOC->XML_NEED_OPEN_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_OPEN_SERVICERESPONSE;
	break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_serviceResponse( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_SERVICERESPONSE:
		cas_debug( "XML_NEED_OPEN_SERVICERESPONSE->XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE" );
		ctx->xml_state=XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_authenticationSuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE:
		cas_debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE->XML_NEED_OPEN_USER" );
		ctx->xml_state=XML_NEED_OPEN_USER;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_authenticationFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE:
		cas_debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE->XML_READ_FAILUREMESSAGE" );
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
			cas_debug("CODE=%d",ctx->cas->code);
		}else{
			ctx->xml_state=XML_FAIL;
		}
		
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_proxyFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE:
		cas_debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE->XML_READ_FAILUREMESSAGE" );
		int valuesz=attributes[4]-attributes[3];
		if(nb_attributes==1 && strncasecmp("code",attributes[0],4)==0){
			if(valuesz==15 && strncasecmp(attributes[3],"INVALID_REQUEST",valuesz)==0){
				ctx->cas->code=CAS2_INVALID_REQUEST;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else if(valuesz==7 && strncasecmp(attributes[3],"BAD_PGT",valuesz)==0){
				ctx->cas->code=CAS2_BAD_PGT;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else if(valuesz==14 && strncasecmp("INTERNAL_ERROR",attributes[3],valuesz)==0){
				ctx->cas->code=CAS2_INTERNAL_ERROR;
				ctx->xml_state=XML_READ_FAILUREMESSAGE;
			}else{
				ctx->xml_state=XML_FAIL;
			}
			cas_debug("CODE=%d",ctx->cas->code);
		}else{
			ctx->xml_state=XML_FAIL;
		}
		
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_user( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	switch(ctx->xml_state){
	case XML_NEED_OPEN_USER:
		cas_debug( "XML_NEED_OPEN_USER->XML_READ_USER" );
		ctx->xml_state=XML_READ_USER;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_proxyGrantingTicket( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
  switch(ctx->xml_state){
	case XML_NEED_OPEN_PROXYGRANTINGTICKET_CLOSE_AUTHENTICATIONSUCCESS:
		cas_debug( "XML_NEED_OPEN_PROXYGRANTINGTICKET->XML_READ_PROXYGRANTINGTICKET" );
		ctx->xml_state=XML_READ_PROXYGRANTINGTICKET;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_proxySuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
  switch(ctx->xml_state){
	case XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE:
		cas_debug( "XML_NEED_OPEN_AUTHENTICATIONSUCCESS_AUTHENTICATIONFAILURE_PROXYSUCCESS_PROXYFAILURE->XML_NEED_OPEN_PROXYTICKET_CLOSE_PROXYSUCCESS" );
		ctx->xml_state=XML_NEED_OPEN_PROXYTICKET_CLOSE_PROXYSUCCESS;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_start_cas_proxyTicket( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
  switch(ctx->xml_state){
	case XML_NEED_OPEN_PROXYTICKET_CLOSE_PROXYSUCCESS:
		cas_debug( "XML_NEED_OPEN_PROXYTICKET_CLOSE_PROXYSUCCESS->XML_READ_PROXYTICKET" );
		ctx->xml_state=XML_READ_PROXYTICKET;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_user( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_USER:
		cas_debug( "XML_READ_USER->XML_NEED_OPEN_PROXYGRANTINGTICKET_CLOSE_AUTHENTICATIONSUCCESS" );
		ctx->xml_state=XML_NEED_OPEN_PROXYGRANTINGTICKET_CLOSE_AUTHENTICATIONSUCCESS;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_proxyGrantingTicket( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_PROXYGRANTINGTICKET:
		cas_debug( "XML_READ_PROXYGRANTINGTICKET->XML_NEED_CLOSE_AUTHENTICATIONSUCCESS" );
		ctx->xml_state=XML_NEED_CLOSE_AUTHENTICATIONSUCCESS;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_proxyTicket( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_PROXYTICKET:
		cas_debug( "XML_READ_PROXYTICKET->XML_NEED_CLOSE_PROXYSUCCESS" );
		ctx->xml_state=XML_NEED_CLOSE_PROXYSUCCESS;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_authenticationSuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_NEED_CLOSE_AUTHENTICATIONSUCCESS:
	case XML_NEED_OPEN_PROXYGRANTINGTICKET_CLOSE_AUTHENTICATIONSUCCESS:
		cas_debug( "%d->XML_NEED_CLOSE_SERVICERESPONSE", ctx->xml_state );
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_authenticationFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_FAILUREMESSAGE:
		cas_debug( "XML_NEED_CLOSE_AUTHENTICATIONFAILURE->XML_NEED_CLOSE_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_proxySuccess( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_NEED_CLOSE_PROXYSUCCESS:
		cas_debug( "XML_NEED_CLOSE_PROXYSUCCESS->XML_NEED_CLOSE_SERVICERESPONSE");
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_proxyFailure( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch(ctx->xml_state){
	case XML_READ_FAILUREMESSAGE:
		cas_debug( "XML_NEED_CLOSE_AUTHENTICATIONFAILURE->XML_NEED_CLOSE_SERVICERESPONSE" );
		ctx->xml_state=XML_NEED_CLOSE_SERVICERESPONSE;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

static void
cas_cas2_end_cas_serviceResponse( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	switch( ctx->xml_state){
	case XML_NEED_CLOSE_SERVICERESPONSE:
		cas_debug( "XML_NEED_CLOSE_SERVICERESPONSE->XML_NEED_END_DOC" );
		ctx->xml_state=XML_NEED_END_DOC;
		break;
	default:
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}

}

static void
cas_cas2_startElementNs( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix,const xmlChar* URI,int nb_namespaces,const xmlChar** namespaces,int nb_attributes,int nb_defaulted,const xmlChar** attributes ) {
	cas_debug( "(%d) <(%s)%s:%s>",ctx->xml_state,prefix,URI,localname );
	if( strncasecmp( "http://www.yale.edu/tp/cas", URI, 26 )==0 ) {
		if ( strncasecmp( "serviceResponse",localname,15 )==0 ) {
			cas_cas2_start_cas_serviceResponse( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "authenticationSuccess",localname,21 )==0 ) {
			cas_cas2_start_cas_authenticationSuccess( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "authenticationFailure",localname,21 )==0 ) {
			cas_cas2_start_cas_authenticationFailure( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "user",localname,4 )==0 ) {
			cas_cas2_start_cas_user( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "proxyGrantingTicket",localname,19 )==0 ) {
			cas_cas2_start_cas_proxyGrantingTicket( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "proxySuccess",localname,12 )==0 ) {
			cas_cas2_start_cas_proxySuccess( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "proxyFailure",localname,12 )==0 ) {
			cas_cas2_start_cas_proxyFailure( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else if ( strncasecmp( "proxyTicket",localname,11 )==0 ) {
			cas_cas2_start_cas_proxyTicket( ctx,localname,prefix,URI,nb_namespaces,namespaces,nb_attributes,nb_defaulted, attributes );
		} else {
			ctx->xml_state=XML_FAIL;
			cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
		}
	}
}

static void
cas_cas2_endElementNs( CAS_XML_STATE* ctx, const xmlChar* localname, const xmlChar* prefix, const xmlChar* URI ) {
	cas_debug( "(%d) </(%s)%s:%s>",ctx->xml_state,prefix,URI,localname );
	if( strncasecmp( "http://www.yale.edu/tp/cas", URI, 26 )==0 ) {
		if ( strncasecmp( "serviceResponse",localname,15 )==0 ) {
			cas_cas2_end_cas_serviceResponse( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "authenticationSuccess",localname,21 )==0 ) {
			cas_cas2_end_cas_authenticationSuccess( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "authenticationFailure",localname,21 )==0 ) {
			cas_cas2_end_cas_authenticationFailure( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "user",localname,4 )==0 ) {
			cas_cas2_end_cas_user( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "proxyGrantingTicket",localname,19 )==0 ) {
			cas_cas2_end_cas_proxyGrantingTicket( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "proxySuccess",localname,12 )==0 ) {
			cas_cas2_end_cas_proxySuccess( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "proxyFailure",localname,12 )==0 ) {
			cas_cas2_end_cas_proxyFailure( ctx,localname,prefix,URI );
		} else if ( strncasecmp( "proxyTicket",localname,11 )==0 ) {
			cas_cas2_end_cas_proxyTicket( ctx,localname,prefix,URI );
		} else {
			ctx->xml_state=XML_FAIL;
			cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
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
		cas_debug("MESSAGE=%s",ctx->cas->message);
	break;
	case XML_READ_PROXYGRANTINGTICKET:
		if( !ctx->cas->pgtiou ) {
			ctx->cas->pgtiou=calloc( len+1,sizeof( char ) );
			if(ctx->cas->pgtiou==NULL) return;
			strncpy( ctx->cas->pgtiou,ch,len );
			ctx->cas->pgtiou[len]='\0';
		} else {
			void* tmp=ctx->cas->pgtiou;
			ctx->cas->pgtiou=realloc( ctx->cas->pgtiou,strlen( ctx->cas->pgtiou )+len+1 );
			if(ctx->cas->pgtiou==NULL){
				free(tmp);
				return;
			}
			strncat( ctx->cas->pgtiou,ch,len );
		}
		cas_debug("PGTIOU=%s",ctx->cas->pgtiou);
	case XML_READ_PROXYTICKET:
		cas_debug("PROXY TICKET (RAW)=%s",ch);
		if( !ctx->cas->proxy_ticket ) {
			ctx->cas->proxy_ticket=calloc( len+1,sizeof( char ) );
			if(ctx->cas->proxy_ticket==NULL) return;
			cas_debug("PROXY TICKET=%s",ch);
			if ( strncasecmp( "PT-",ch,3 )==0 ) {
				strncpy( ctx->cas->proxy_ticket,ch,len );
				ctx->cas->proxy_ticket[len]='\0';
			} 
		} else {
			void* tmp=ctx->cas->proxy_ticket;
			ctx->cas->proxy_ticket=realloc( ctx->cas->proxy_ticket,strlen( ctx->cas->proxy_ticket )+len+1 );
			if(ctx->cas->proxy_ticket==NULL){
				free(tmp);
				return;
			}
			if ( strncasecmp( "PT-",ch,3 )==0 ) {
				strncat( ctx->cas->proxy_ticket,ch,len );
			}
		}
		cas_debug("PROXY TICKET=%s",ctx->cas->proxy_ticket);
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
		cas_debug( "XML_NEED_END_DOC->XML_COMPLETE" );
		ctx->xml_state=XML_COMPLETE;
	} else {
		ctx->xml_state=XML_FAIL;
		cas_debug( "XML_FAIL:(%d)",ctx->xml_state );
	}
}

/*******************************************************************************
 * cas_cas2_servicevalidate: Perform CAS2 validation protocol without proxy ticketing
 */
CAS_CODE
cas_cas2_servicevalidate( CAS* cas, char* cas2_servicevalidate_baseurl, char* escaped_service, char* ticket, int renew) {
	return cas_cas2_serviceValidate_proxyTicketing( cas, cas2_servicevalidate_baseurl, escaped_service, ticket, renew, NULL, NULL) ;
}
	
/*******************************************************************************
 * cas_cas2_servicevalidate_proxyticketing: Perform CAS2 validation protocol
 */
CAS_CODE
cas_cas2_serviceValidate_proxyTicketing( CAS* cas, char* cas2_servicevalidate_baseurl, char* escaped_service, char* ticket, int renew, char* escaped_pgt_receive_url, char* pgt_retrieve_baseurl) {
	cas_debug("cas->code: %d", cas->code);
	if(!cas && cas2_servicevalidate_baseurl && escaped_service && ticket) {
		return(CAS_INVALID_PARAMETERS);
	}
	if(cas->principal) { free(cas->principal);cas->principal=NULL;}
	if(cas->pgtiou) { free(cas->pgtiou);cas->pgtiou=NULL;}
	if(cas->pgt) { free(cas->pgtiou);cas->pgt=NULL;}
	
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

	char* url = cas_cas2_serviceValidateUrl(cas2_servicevalidate_baseurl, escaped_service, ticket, renew, escaped_pgt_receive_url);
	if (url != NULL) {
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
				if (cas->pgtiou != NULL) {
					char* pgt_retrieve_url = cas_cas2_retrievePgtUrl(pgt_retrieve_baseurl, cas->pgtiou);
					cas_debug( "pgt_retrieve_url:(%s)",pgt_retrieve_url );
					if (pgt_retrieve_url != NULL) {
						char* pgt = cas_cas2_retrievePgt(pgt_retrieve_url, cas);
						cas_debug( "pgt:(%s)",pgt );
						if (pgt != NULL && strncasecmp( "PGT-",pgt,4 )==0 ) {
							cas->pgt = pgt;
						} else {
							return(CAS_INVALID_RESPONSE);
						}
						free(pgt_retrieve_url);
					}
				}
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

/**************************************************************************
 * cas_cas2_servicevalidate_url: Builds CAS2 service ticket validation url
 */
char*
cas_cas2_serviceValidateUrl(char* cas2_servicevalidate_baseurl, char* escaped_service, char* ticket, int renew, char* escaped_pgt_receive_url) {
	int size = strlen( cas2_servicevalidate_baseurl ) + 
		9 + strlen( escaped_service ) + // 9 = strlen("?service=")
		8 + strlen( ticket ) + 			// 8 = strlen("&ticket=")
		(renew ? 11 : 0) +				// 11 = strlen("&renew=true")
		(escaped_pgt_receive_url ? ( 8 + strlen(escaped_pgt_receive_url) ) : 0); // 8 = strlen("&pgtUrl=")
		
	
	char* url;
	if (url=calloc(size,sizeof( char ) )){
		strcpy( url,cas2_servicevalidate_baseurl );
		strcat( url,"?service=" );
		strcat( url,escaped_service );
		strcat( url,"&ticket=" );
		strcat( url,ticket );
		if (renew) strcat( url, "&renew=true");
		if (escaped_pgt_receive_url) {
			strcat(url, "&pgtUrl=");
			strcat(url, escaped_pgt_receive_url);
		}
	} 
	return url;
}

char* 
cas_cas2_retrievePgtUrl(char* baseUrl, char* pgtiou) {
	int size = strlen( baseUrl ) +
		8 + strlen( pgtiou );	 // 8 = strlen("?pgtIou=")

	char* url;
	if (url=calloc(size,sizeof( char) )) {
		strcpy( url, baseUrl);
		strcat( url, "?pgtIou=");
		strcat( url, pgtiou);
	}
	return url;
}

char* 
cas_cas2_retrievePgt(char* url, CAS* cas) {
	char* pgt;

	curl_easy_setopt( cas->curl,CURLOPT_URL, url );
	curl_easy_setopt( cas->curl,CURLOPT_WRITEFUNCTION, ( curl_write_callback )cas_cas2_curl_retrievepgt_callback );
	curl_easy_setopt( cas->curl,CURLOPT_WRITEDATA, &pgt );

	curl_easy_perform( cas->curl );

	return pgt;
}


/*******************************************************************************
 * cas_cas2_proxy: Obtain a proxy ticket from the CAS2 server
 */
CAS_CODE
cas_cas2_proxy( CAS* cas, char* cas2_proxy_baseurl, char* escaped_service, char* proxy_granting_ticket) {
	cas_debug( "cas_cas2_proxy [proxy_granting_ticekt]: %s", proxy_granting_ticket );
	if(!cas && cas2_proxy_baseurl && escaped_service && proxy_granting_ticket) {
		return(CAS_INVALID_PARAMETERS);
	}
	if(cas->proxy_ticket) { free(cas->proxy_ticket);cas->proxy_ticket=NULL;}
	
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

	char* url = cas_cas2_proxyUrl(cas2_proxy_baseurl, escaped_service, proxy_granting_ticket);
	if (url != NULL) {
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
				return(CAS2_PROXY_SUCCESS);
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

char* 
cas_cas2_proxyUrl(char* base_url, char* escaped_service, char* proxy_granting_ticket ) {
	int size = strlen( base_url ) +
		15 + strlen( escaped_service ) +	 // 15 = strlen("?targetService=")
		5 + strlen( proxy_granting_ticket ); // 5 = strlen("&pgt=")

	char* url;
	if (url=calloc(size,sizeof( char) )) {
		strcpy( url, base_url);
		strcat( url, "?targetService=");
		strcat( url, escaped_service);
		strcat( url, "&pgt=");
		strcat( url, proxy_granting_ticket);
	}
	return url;
}