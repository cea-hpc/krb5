/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * src/kdc/kdc_acl.h
 *
 */

#ifndef KDC_ACL_H__
#define KDC_ACL_H__

/*
 * Debug definitions.
 */
#define DEBUG_CALLS     128
#ifdef  DEBUG
#define DPRINT(l1, cl, al)      if ((cl & l1) != 0) xprintf al
#else   /* DEBUG */
#define DPRINT(l1, cl, al)
#endif  /* DEBUG */

#define KAENT_REQ_TYPE_AS  1
#define KAENT_REQ_TYPE_TGS 2

krb5_error_code kdc_acl_init(krb5_context, int, char *);
void kdc_acl_finish(krb5_context, int);
krb5_boolean kdc_acl_check_req(krb5_context, int,
		  const char*,
		  const krb5_fulladdr *from,
		  const char*);
krb5_boolean kdc_acl_check_as_req(krb5_context,
                                  const char*,
                                  const krb5_fulladdr *from,
                                  const char*);
krb5_boolean kdc_acl_check_tgs_req(krb5_context,
                                   const char*,
                                   const krb5_fulladdr *from,
                                   const char*);

#endif  /* KDC_ACL_H__ */
