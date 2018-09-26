/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * src/kdc/kdc_acl.c
 *
 */

/*
 * kdc_acl.c - Handle Kerberos KDC ACL related functions.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>
#include <errno.h>

#include "k5-int.h"
#include "adm_proto.h"
#include "net-server.h"
#include "sys/syslog.h"
#include "kdc_acl.h"

/*
 * From kdc_util.h
 */
#ifdef KRB5_USE_INET6
#define ADDRTYPE2FAMILY(X)                                              \
    ((X) == ADDRTYPE_INET6 ? AF_INET6 : (X) == ADDRTYPE_INET ? AF_INET : -1)
#else
#define ADDRTYPE2FAMILY(X)                      \
    ((X) == ADDRTYPE_INET ? AF_INET : -1)
#endif

#ifndef KRB5_DEFAULT_KDC_ACL
#define KRB5_DEFAULT_KDC_ACL "kdc.acl"
#endif

typedef struct _kdc_acl_entry {
    struct _kdc_acl_entry *ae_next;
    krb5_int32            req_type;
    krb5_boolean          allow;
    char                  *tprinc;
    char                  *caddr;
    char                  *cprinc;
    regex_t               tprinc_rex;
    regex_t               caddr_rex;
    regex_t               cprinc_rex;
    regex_t               *tprinc_rexp;
    regex_t               *caddr_rexp;
    regex_t               *cprinc_rexp;
} kaent_t;

static int acl_inited = 0;
static int acl_debug_level = 0;

static char      *acl_acl_file = NULL;
static kaent_t   *acl_list_head = (kaent_t *) NULL;
static kaent_t   *acl_list_tail = (kaent_t *) NULL;

static const char *acl_line2long_msg = "%s: line %d too long, truncated";
static const char *acl_syn_err_msg = "%s: syntax error at line %d <%10s...>";
static const char *acl_cantopen_msg = "%s while opening ACL file %s";

static int kdc_acl_print_entry(const kaent_t *ae, int loglevel);
static int kdc_acl_entry_init(kaent_t *ae, int req_type, const char *mode,
                              const char *tprinc,const char *caddr,
                              const char *cprinc);
static int kdc_acl_entry_match(kaent_t *ae, int req_type,const char* tprinc,
                               const char* caddr, const char* cprinc);
static int kdc_acl_regex_ok(regex_t *regexp, const char  *input);
void kdc_acl_entry_destroy(kaent_t *ae);


/*
 * kdc_acl_regex_ok() - Is this regex matched ?
 */
int
kdc_acl_regex_ok(regexp,input)
     regex_t *regexp;
     const char  *input;
{
    int retval;
    retval = 0;

    if (input == NULL)
        return retval;

    else if(regexp != NULL &&
            regexec(regexp,input,0,NULL,0) == 0)
        retval = 1;

    return (retval);
}

/*
 * kdc_acl_print_entry() - Print a line for the entry
 */
static int
kdc_acl_print_entry(ae,loglevel)
     const kaent_t *ae;
     int           loglevel;
{
    if (ae->req_type == KAENT_REQ_TYPE_AS)
        krb5_klog_syslog(loglevel, "kdc_acl: AS_REQ: %s %s from %s for %s",
                         ae->allow ? "allow":"deny",
                         ae->tprinc ? ae->tprinc : "-",
                         ae->caddr ? ae->caddr : "-",
                         ae->cprinc ? ae->cprinc : "-");
    else if (ae->req_type == KAENT_REQ_TYPE_TGS)
        krb5_klog_syslog(loglevel, "kdc_acl: TGS_REQ: %s %s from %s for %s",
                         ae->allow ? "allow":"deny",
                         ae->tprinc ? ae->tprinc : "-",
                         ae->caddr ? ae->caddr : "-",
                         ae->cprinc ? ae->cprinc : "-");
    else
        krb5_klog_syslog(loglevel, "kdc_acl: Bad entry detected");
    return 0;
}

/*
 * kdc_acl_entry_init() - Intialize a kaent entry
 */
int
kdc_acl_entry_init(ae,req_type,mode,tprinc,caddr,cprinc)
     kaent_t *ae;
     int                 req_type;
     const char*         mode;
     const char*         tprinc;
     const char*         caddr;
     const char*         cprinc;
{
    int retval;

    retval = 1;

    if (tprinc == NULL || caddr == NULL || mode == NULL)
        goto out;
    if (req_type == KAENT_REQ_TYPE_TGS && cprinc == NULL)
        goto out;

    if (strncmp("allow",mode,6) == 0)
        ae->allow = 1;
    else if (strncmp("deny",mode,5) == 0)
        ae->allow = 0;
    else {
        goto out;
    }

    ae->req_type = req_type ;
    ae->ae_next = NULL ;
    ae->tprinc = strdup(tprinc);
    ae->caddr = strdup(caddr);
    if (cprinc != NULL)
        ae->cprinc = strdup(cprinc);
    else
        ae->cprinc = NULL;

    ae->tprinc_rexp = NULL;
    ae->caddr_rexp = NULL;
    ae->cprinc_rexp = NULL;

    if (ae->tprinc != NULL) {
        if (strncmp(ae->tprinc,"*",2) == 0)
            ae->tprinc_rexp = NULL;
        else if (regcomp(&(ae->tprinc_rex),ae->tprinc,REG_EXTENDED) == 0) {
            ae->tprinc_rexp = &(ae->tprinc_rex);
        }
        else
            goto err;
    }
    if (ae->caddr != NULL) {
        if (strncmp(ae->caddr,"*",2) == 0)
            ae->caddr_rexp = NULL;
        else if (regcomp(&(ae->caddr_rex),ae->caddr,REG_EXTENDED) == 0) {
            ae->caddr_rexp = &(ae->caddr_rex);
        }
        else
            goto err;
    }
    if (ae->cprinc != NULL) {
        if (strncmp(ae->cprinc,"*",2) == 0)
            ae->cprinc_rexp = NULL;
        else if (regcomp(&(ae->cprinc_rex),ae->cprinc,REG_EXTENDED) == 0) {
            ae->cprinc_rexp = &(ae->cprinc_rex);
        }
        else
            goto err;
    }
    retval = 0;
    kdc_acl_print_entry(ae,LOG_INFO);
    goto out;

 err:
    kdc_acl_entry_destroy(ae);

 out:
    return retval;
}

/*
 * kdc_acl_entry_match() - Return 1 if the entry matches the input fields
 */
int
kdc_acl_entry_match(ae,req_type,tprinc,caddr,cprinc)
     kaent_t *ae;
     int                 req_type;
     const char*         tprinc;
     const char*         caddr;
     const char*         cprinc;
{
    int retval;
    retval = 0;

    if ( ae->req_type == req_type &&
         ( strncmp(ae->tprinc,"*",2) == 0 ||
           kdc_acl_regex_ok(ae->tprinc_rexp,tprinc) ) &&
         ( strncmp(ae->caddr,"*",2) == 0 ||
           kdc_acl_regex_ok(ae->caddr_rexp,caddr) ) &&
         ( ( req_type == KAENT_REQ_TYPE_AS && !ae->cprinc ) ||
          ( strncmp(ae->cprinc,"*",2) == 0 ||
            kdc_acl_regex_ok(ae->cprinc_rexp,cprinc) ) )
         ) {
        retval = 1;
    }

    return retval;
}

/*
 * kdc_acl_entry_destroy() - Destroy a kaent entry
 */
void
kdc_acl_entry_destroy(ae)
     kaent_t *ae;
{
    if (ae->tprinc != NULL)
        free(ae->tprinc);
    ae->tprinc = NULL;
    if (ae->caddr != NULL)
        free(ae->caddr);
    ae->caddr = NULL;
    if (ae->cprinc != NULL)
        free(ae->cprinc);
    ae->cprinc = NULL;

    if (ae->tprinc_rexp != NULL)
        regfree(ae->tprinc_rexp);
    ae->tprinc_rexp = NULL;
    if (ae->caddr_rexp != NULL)
        regfree(ae->caddr_rexp);
    ae->caddr_rexp = NULL;
    if (ae->cprinc_rexp != NULL)
        regfree(ae->cprinc_rexp);
    ae->cprinc_rexp = NULL;

    ae->ae_next = NULL;
}

/*
 * kdc_acl_free_entries() - Free all ACL entries.
 */
static void
kdc_acl_free_entries()
{
    kaent_t      *ap;
    kaent_t      *np;

    DPRINT(DEBUG_CALLS, acl_debug_level, ("* kdc_acl_free_entries()\n"));

    for (ap=acl_list_head; ap; ap = np) {
        np = ap->ae_next;
        kdc_acl_entry_destroy(ap);
        free(ap);
    }
    acl_list_head = acl_list_tail = (kaent_t *) NULL;
    acl_inited = 0;

    DPRINT(DEBUG_CALLS, acl_debug_level, ("X kdc_acl_free_entries()\n"));
}

/*
 * kdc_acl_get_line() - Get a line from the ACL file.
 *                      Lines ending with \ are continued on the next line
 */
static char *
kdc_acl_get_line(fp, lnp)
     FILE        *fp;
     int         *lnp;           /* caller should set to 1 before first call */
{
    int         i, domore;
    static int  line_incr = 0;
    static char acl_buf[BUFSIZ];

    *lnp += line_incr;
    line_incr = 0;
    for (domore = 1; domore && !feof(fp); ) {
        /* Copy in the line, with continuations */
        for (i=0; (((unsigned int)i < sizeof acl_buf) && !feof(fp)); i++ ) {
            int byte;
            byte = fgetc(fp);
            acl_buf[i] = byte;
            if (byte == (char)EOF) {
                if (i > 0 && acl_buf[i-1] == '\\')
                    i--;
                break;          /* it gets nulled-out below */
            }
            else if (acl_buf[i] == '\n') {
                if (i == 0 || acl_buf[i-1] != '\\')
                    break;      /* empty line or normal end of line */
                else {
                    i -= 2;     /* back up over "\\\n" and continue */
                    line_incr++;
                }
            }
        }
        /* Check if we exceeded our buffer size */
        if (i == sizeof acl_buf && (i--, !feof(fp))) {
            int c1 = acl_buf[i], c2;

            krb5_klog_syslog(LOG_ERR, acl_line2long_msg, acl_acl_file, *lnp);

            while ((c2 = fgetc(fp)) != EOF) {
                if (c2 == '\n') {
                    if (c1 != '\\')
                        break;
                    line_incr++;
                }
                c1 = c2;
            }
        }
        acl_buf[i] = '\0';
        if (acl_buf[0] == (char) EOF)   /* ptooey */
            acl_buf[0] = '\0';
        else
            line_incr++;
        if ((acl_buf[0] != '#') && (acl_buf[0] != '\0'))
            domore = 0;
    }
    if (domore || (strlen(acl_buf) == 0))
        return((char *) NULL);
    else
        return(acl_buf);
}

/*
 * kdc_acl_parse_line() - Parse the contents of an ACL line.
 */
static kaent_t *
kdc_acl_parse_line(lp)
     const char *lp;
{
    kaent_t * acle;
    int nmatch;

    static char mode[BUFSIZ];
    static char tprinc[BUFSIZ];
    static char caddr[BUFSIZ];
    static char cprinc[BUFSIZ];

    DPRINT(DEBUG_CALLS, acl_debug_level,
           ("* kdc_acl_parse_line(line=%20s)\n", lp));

    /*
     * Format is :
     * entry ::= [<whitespace>] (AS_REQ|TGS_REQ): <whitespace> allow|deny
     *           <whitespace> target_princ_regexp <whitespace>
     *           from <whitespace> addr_regexp
     *           [<whitespace> for <whitespace> client_princ_regexp]
     *
     */
    acle = (kaent_t*) NULL;

    nmatch = sscanf(lp,"AS_REQ: %s %s from %s for %s",mode,
                    tprinc,caddr, cprinc);
    if ( nmatch == 4 )  {
        acle = (kaent_t *) malloc(sizeof(kaent_t));
        if (acle) {
            if (kdc_acl_entry_init(acle,KAENT_REQ_TYPE_AS,
                                   mode,tprinc,caddr,cprinc) != 0) {
                free(acle);
                acle = NULL;
                goto out;
            }
        }
    } else {
        nmatch = sscanf(lp,"AS_REQ: %s %s from %s",mode,
                        tprinc,caddr);
        if ( nmatch == 3 )  {
            acle = (kaent_t *) malloc(sizeof(kaent_t));
            if (acle) {
                if (kdc_acl_entry_init(acle,KAENT_REQ_TYPE_AS,
                                       mode,tprinc,caddr,NULL) != 0) {
                    free(acle);
                    acle = NULL;
                    goto out;
                }
            }
        } else {
            nmatch = sscanf(lp,"TGS_REQ: %s %s from %s for %s",mode,
                            tprinc,caddr,cprinc);
            if ( nmatch == 4 ) {
                acle = (kaent_t *) malloc(sizeof(kaent_t));
                if (acle) {
                    if (kdc_acl_entry_init(acle,KAENT_REQ_TYPE_TGS,
                                           mode,tprinc,caddr,cprinc) != 0) {
                        free(acle);
                        acle = NULL;
                        goto out;
                    }
                }
            }
        }
    }

 out:
    DPRINT(DEBUG_CALLS, acl_debug_level,
           ("X kdc_acl_parse_line() = %x\n", (long) acle));
    return (acle);
}

/*
 * kdc_acl_load_acl_file() - Open and parse the ACL file.
 */
static int
kdc_acl_load_acl_file()
{
    FILE        *afp;
    char        *alinep;
    kaent_t     **aentpp;
    int         alineno;
    int         retval = 1;

    DPRINT(DEBUG_CALLS, acl_debug_level, ("* kdc_acl_load_acl_file()\n"));

    /* Open the ACL file for read */
    afp = fopen(acl_acl_file, "r");
    if (afp) {
        set_cloexec_file(afp);
        alineno = 1;
        aentpp = &acl_list_head;

        /* Get a non-comment line */
        while ((alinep = kdc_acl_get_line(afp, &alineno))) {
            /* Parse it */
            *aentpp = kdc_acl_parse_line(alinep);
            /* If syntax error, then fall out */
            if (!*aentpp) {
                krb5_klog_syslog(LOG_ERR, acl_syn_err_msg,
                                 acl_acl_file, alineno, alinep);
                retval = 0;
                break;
            }
            acl_list_tail = *aentpp;
            aentpp = &(*aentpp)->ae_next;
        }
        fclose(afp);
    } else {
        krb5_klog_syslog(LOG_ERR, acl_cantopen_msg,
                         error_message(errno), acl_acl_file);
        retval = 0;
    }

    if (!retval) {
        kdc_acl_free_entries();
    }

    DPRINT(DEBUG_CALLS, acl_debug_level,
           ("X kdc_acl_load_acl_file() = %d\n", retval));
    return(retval);
}

/*
 * kdc_acl_init()  - Initialize ACL context.
 */
krb5_error_code
kdc_acl_init(kcontext, debug_level, acl_file)
     krb5_context        kcontext;
     int                 debug_level;
     char                *acl_file;
{
    krb5_error_code     kret;
    DPRINT(DEBUG_CALLS, acl_debug_level,("* kdc_acl_init(afile=%s)\n",
                                         ((acl_file) ? acl_file : "(null)")));
    kret = 0;
    acl_debug_level = debug_level;

    if (acl_acl_file == NULL)
        profile_get_string(kcontext->profile,KRB5_CONF_KDCDEFAULTS,
                           "kdc_acl", NULL,NULL, &acl_acl_file);
    else
        acl_acl_file = strdup(acl_file);
    if ( acl_acl_file ) {
        krb5_klog_syslog(LOG_INFO, "kdc_acl: initializing using %s",
                         acl_acl_file);
        acl_inited = kdc_acl_load_acl_file();
        if ( !acl_inited ) {
            krb5_klog_syslog(LOG_ERR, "kdc_acl: initialization failed");
            kret = KRB5_CONFIG_BADFORMAT;
        }
    }

    DPRINT(DEBUG_CALLS, acl_debug_level,("X kdc_acl_init() = %d\n", kret));
    return(kret);
}

/*
 * kdc_acl_finish  - Terminate ACL context.
 */
void
kdc_acl_finish(kcontext, debug_level)
     krb5_context        kcontext;
     int                 debug_level;
{
    DPRINT(DEBUG_CALLS, acl_debug_level, ("* kdc_acl_finish()\n"));

    kdc_acl_free_entries();
    free(acl_acl_file);

    DPRINT(DEBUG_CALLS, acl_debug_level, ("X kdc_acl_finish()\n"));
}

/*
 * kdc_acl_check_req() - Is this KDC REQ permitted ?
 */
krb5_boolean
kdc_acl_check_req(kcontext, req_type, tprinc, remote_addr, cprinc)
     krb5_context        kcontext;
     int                 req_type;
     const char*         tprinc;
     const krb5_fulladdr *remote_addr;
     const char*         cprinc;
{
    krb5_boolean        retval;
    const char          *fromstring;
    char                fromstringbuf[70];
    kaent_t             *entry;

    DPRINT(DEBUG_CALLS, acl_debug_level, ("* kdc_acl_check_req()\n"));

    retval = 1;

    fromstring = inet_ntop(ADDRTYPE2FAMILY (remote_addr->address->addrtype),
                           remote_addr->address->contents,
                           fromstringbuf, sizeof(fromstringbuf));
    if (!fromstring)
        fromstring = "<unknown>";

    /* Walk through the ACL entries */
    for (entry=acl_list_head; entry; entry = entry->ae_next) {
        if ( kdc_acl_entry_match(entry,req_type,tprinc,fromstring,cprinc) ) {
#ifdef DEBUG
            kdc_acl_print_entry(entry,LOG_DEBUG);
#endif
            if ( ! entry->allow )
                retval = 0;
            break;
        }
    }

    DPRINT(DEBUG_CALLS, acl_debug_level, ("X kdc_acl_check_req()\n"));
    return (retval);
}

/*
 * kdc_acl_check_as_req() - Is this KDC AS_REQ permitted ?
 */
krb5_boolean
kdc_acl_check_as_req(kcontext, tprinc, remote_addr, cprinc)
     krb5_context        kcontext;
     const char*         tprinc;
     const krb5_fulladdr *remote_addr;
     const char*         cprinc;
{
    return kdc_acl_check_req(kcontext,KAENT_REQ_TYPE_AS,
                             tprinc,remote_addr,cprinc);
}

/*
 * kdc_acl_check_tgs_req() - Is this KDC TGS_REQ permitted ?
 */
krb5_boolean
kdc_acl_check_tgs_req(kcontext, tprinc, remote_addr, cprinc)
     krb5_context        kcontext;
     const char*         tprinc;
     const krb5_fulladdr *remote_addr;
     const char*         cprinc;
{
    return kdc_acl_check_req(kcontext,KAENT_REQ_TYPE_TGS,
                             tprinc,remote_addr,cprinc);
}
