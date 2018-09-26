/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kadmin/ktutil/ktutil_funcs.c */
/*
 *(C) Copyright 1995, 1996 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Utility functions for ktutil.
 */

#include "k5-int.h"
#include "k5-hex.h"
#include "ktutil.h"
#include <string.h>
#include <ctype.h>

/*
 * Free a kt_list
 */
krb5_error_code ktutil_free_kt_list(context, list)
    krb5_context context;
    krb5_kt_list list;
{
    krb5_kt_list lp, prev;
    krb5_error_code retval = 0;

    for (lp = list; lp;) {
        retval = krb5_kt_free_entry(context, lp->entry);
        free(lp->entry);
        if (retval)
            break;
        prev = lp;
        lp = lp->next;
        free(prev);
    }
    return retval;
}

/*
 * Delete a numbered entry in a kt_list.  Takes a pointer to a kt_list
 * in case head gets deleted.
 */
krb5_error_code ktutil_delete(context, list, idx)
    krb5_context context;
    krb5_kt_list *list;
    int idx;
{
    krb5_kt_list lp, prev;
    int i;

    for (lp = *list, i = 1; lp; prev = lp, lp = lp->next, i++) {
        if (i == idx) {
            if (i == 1)
                *list = lp->next;
            else
                prev->next = lp->next;
            lp->next = NULL;
            return ktutil_free_kt_list(context, lp);
        }
    }
    return EINVAL;
}

/*
 * Create a new keytab entry and add it to the keytab list.
 * Based on the value of use_pass, either prompt the user for a
 * password or key.  If the keytab list is NULL, allocate a new
 * one first.
 */
krb5_error_code ktutil_add(context, list, princ_str, kvno,
                           enctype_str, use_pass, salt_str)
    krb5_context context;
    krb5_kt_list *list;
    char *princ_str;
    krb5_kvno kvno;
    char *enctype_str;
    int use_pass;
    char *salt_str;
{
    krb5_keytab_entry *entry;
    krb5_kt_list lp = NULL, prev = NULL;
    krb5_principal princ;
    krb5_enctype enctype;
    krb5_timestamp now;
    krb5_error_code retval;
    krb5_data password, salt, defsalt = empty_data();
    krb5_keyblock key;
    char buf[BUFSIZ];
    char promptstr[1024];
    uint8_t *keybytes;
    size_t keylen;
    unsigned int pwsize = BUFSIZ;

    retval = krb5_parse_name(context, princ_str, &princ);
    if (retval)
        return retval;
    /* now unparse in order to get the default realm appended
       to princ_str, if no realm was specified */
    retval = krb5_unparse_name(context, princ, &princ_str);
    if (retval)
        return retval;
    retval = krb5_string_to_enctype(enctype_str, &enctype);
    if (retval)
        return KRB5_BAD_ENCTYPE;
    retval = krb5_timeofday(context, &now);
    if (retval)
        return retval;

    if (*list) {
        /* point lp at the tail of the list */
        for (lp = *list; lp->next; lp = lp->next);
    }
    entry = (krb5_keytab_entry *) malloc(sizeof(krb5_keytab_entry));
    if (!entry) {
        return ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));

    if (!lp) {          /* if list is empty, start one */
        lp = (krb5_kt_list) malloc(sizeof(*lp));
        if (!lp) {
            return ENOMEM;
        }
    } else {
        lp->next = (krb5_kt_list) malloc(sizeof(*lp));
        if (!lp->next) {
            return ENOMEM;
        }
        prev = lp;
        lp = lp->next;
    }
    lp->next = NULL;
    lp->entry = entry;

    if (use_pass) {
        password.length = pwsize;
        password.data = (char *) malloc(pwsize);
        if (!password.data) {
            retval = ENOMEM;
            goto cleanup;
        }

        snprintf(promptstr, sizeof(promptstr), _("Password for %.1000s"),
                 princ_str);
        retval = krb5_read_password(context, promptstr, NULL, password.data,
                                    &password.length);
        if (retval)
            goto cleanup;
        if (salt_str != NULL) {
            salt = string2data(salt_str);
        } else {
            retval = krb5_principal2salt(context, princ, &defsalt);
            if (retval)
                goto cleanup;
            salt = defsalt;
        }
        retval = krb5_c_string_to_key(context, enctype, &password,
                                      &salt, &key);
        if (retval)
            goto cleanup;
        memset(password.data, 0, password.length);
        password.length = 0;
        lp->entry->key = key;
    } else {
        printf(_("Key for %s (hex): "), princ_str);
        fgets(buf, BUFSIZ, stdin);
        /*
         * We need to get rid of the trailing '\n' from fgets.
         * If we have an even number of hex digits (as we should),
         * write a '\0' over the '\n'.  If for some reason we have
         * an odd number of hex digits, force an even number of hex
         * digits by writing a '0' into the last position (the string
         * will still be null-terminated).
         */
        buf[strlen(buf) - 1] = strlen(buf) % 2 ? '\0' : '0';
        if (strlen(buf) == 0) {
            fprintf(stderr, _("addent: Error reading key.\n"));
            retval = 0;
            goto cleanup;
        }

        retval = k5_hex_decode(buf, &keybytes, &keylen);
        if (retval) {
            if (retval == EINVAL) {
                fprintf(stderr, _("addent: Illegal character in key.\n"));
                retval = 0;
            }
            goto cleanup;
        }

        lp->entry->key.enctype = enctype;
        lp->entry->key.contents = keybytes;
        lp->entry->key.length = keylen;
    }
    lp->entry->principal = princ;
    lp->entry->vno = kvno;
    lp->entry->timestamp = now;

    if (!*list)
        *list = lp;

    return 0;

cleanup:
    if (prev)
        prev->next = NULL;
    ktutil_free_kt_list(context, lp);
    krb5_free_data_contents(context, &defsalt);
    return retval;
}

/*
 * Read in a keytab and append it to list.  If list starts as NULL,
 * allocate a new one if necessary.
 */
krb5_error_code ktutil_read_keytab(context, name, list)
    krb5_context context;
    char *name;
    krb5_kt_list *list;
{
    krb5_kt_list lp = NULL, tail = NULL, back = NULL;
    krb5_keytab kt;
    krb5_keytab_entry *entry;
    krb5_kt_cursor cursor;
    krb5_error_code retval = 0;

    if (*list) {
        /* point lp at the tail of the list */
        for (lp = *list; lp->next; lp = lp->next);
        back = lp;
    }
    retval = krb5_kt_resolve(context, name, &kt);
    if (retval)
        return retval;
    retval = krb5_kt_start_seq_get(context, kt, &cursor);
    if (retval)
        goto close_kt;
    for (;;) {
        entry = (krb5_keytab_entry *)malloc(sizeof (krb5_keytab_entry));
        if (!entry) {
            retval = ENOMEM;
            break;
        }
        memset(entry, 0, sizeof (*entry));
        retval = krb5_kt_next_entry(context, kt, entry, &cursor);
        if (retval)
            break;

        if (!lp) {              /* if list is empty, start one */
            lp = (krb5_kt_list)malloc(sizeof (*lp));
            if (!lp) {
                retval = ENOMEM;
                break;
            }
        } else {
            lp->next = (krb5_kt_list)malloc(sizeof (*lp));
            if (!lp->next) {
                retval = ENOMEM;
                break;
            }
            lp = lp->next;
        }
        if (!tail)
            tail = lp;
        lp->next = NULL;
        lp->entry = entry;
    }
    if (entry)
        free(entry);
    if (retval) {
        if (retval == KRB5_KT_END)
            retval = 0;
        else {
            ktutil_free_kt_list(context, tail);
            tail = NULL;
            if (back)
                back->next = NULL;
        }
    }
    if (!*list)
        *list = tail;
    krb5_kt_end_seq_get(context, kt, &cursor);
close_kt:
    krb5_kt_close(context, kt);
    return retval;
}


/*
 * Extract recent entries from a keytab and append it to list after rekeying
 * and vno increase.
 * If list starts as NULL, allocate a new one if necessary.
 */
krb5_error_code ktutil_upgrade_keytab(context, name, princ_str, list)
    krb5_context context;
    char *name;
    char *princ_str;
    krb5_kt_list *list;
{
    krb5_timestamp now;
    krb5_principal princ;
    krb5_kt_list head = NULL, lp = NULL, tail = NULL, back = NULL, lt = NULL;
    krb5_keytab kt;
    krb5_keytab_entry *entry, *ent;
    krb5_kt_cursor cursor;
    krb5_error_code retval;
    int found;

    retval = krb5_timeofday(context, &now);
    if (retval)
        return retval;

    if ( princ_str != NULL) {
        retval = krb5_parse_name(context, princ_str, &princ);
        if (retval) {
            fprintf(stderr,_("ukt: Unable to initialize principal %s"
                             ", aborting\n"),princ_str);
            return retval;
        }
    }

    if (*list) {
        /* point lp at the tail of the list */
        for (lp = *list; lp->next; lp = lp->next);
        back = lp;
        head = *list;
    }

    retval = krb5_kt_resolve(context, name, &kt);
    if (retval)
        goto exit_princ;
    retval = krb5_kt_start_seq_get(context, kt, &cursor);
    if (retval)
        goto close_kt;

    /* extract only entries with different enctype and highest vnos */
    for (;;) {
        entry = (krb5_keytab_entry *)malloc(sizeof (krb5_keytab_entry));
        if (!entry) {
            retval = ENOMEM;
            break;
        }
        memset(entry, 0, sizeof (*entry));
        retval = krb5_kt_next_entry(context, kt, entry, &cursor);
        if (retval)
            break;

        if (princ_str != NULL &&
            !krb5_principal_compare(context,princ,entry->principal)) {
            krb5_kt_free_entry(context,entry);
            free(entry);
            entry = NULL;
            continue;
        }

        found = 0;
        for(lt = head; lt ; lt = lt->next) {
            if (!krb5_principal_compare(context,lt->entry->principal,entry->principal))
                continue;
            if (lt->entry->key.enctype == entry->key.enctype
                && lt->entry->vno >= entry->vno) {
                /* previous one has a higher kvno, skip the addition */
                found++;
                break;
            } else if (lt->entry->key.enctype == entry->key.enctype) {
                /* swap the previous one with this one having a higher kvno */
                ent = lt->entry;
                lt->entry = entry;
                entry = ent;
                found++;
                break;
            }
        }

        /* if already a slot for this enctype, skip the addition to the list */
        if (found) {
            krb5_kt_free_entry(context,entry);
            free(entry);
            entry = NULL;
            continue;
        }

        /* add the entry to the list */
        if (!lp) {              /* if list is empty, start one */
            lp = (krb5_kt_list)malloc(sizeof (*lp));
            if (!lp) {
                retval = ENOMEM;
                break;
            }
            head = lp;
        } else {
            lp->next = (krb5_kt_list)malloc(sizeof (*lp));
            if (!lp->next) {
                retval = ENOMEM;
                break;
            }
            lp = lp->next;
        }
        if (!tail)
            tail = lp;
        lp->next = NULL;
        lp->entry = entry;
    }
    if (entry)
        free(entry);
    if (retval) {
        if (retval == KRB5_KT_END)
            retval = 0;
        else {
            ktutil_free_kt_list(context, tail);
            tail = NULL;
            if (back)
                back->next = NULL;
        }
    }
    if (!tail) {
        fprintf(stdout,"Nothing to upgrade\n");
    } else {
        int i = 0;
        krb5_enctype enctype;
        for(lt = tail; lt ; lt = lt->next) {
            enctype = lt->entry->key.enctype;
            lt->entry->vno++;
            lt->entry->timestamp = now;
            krb5_free_keyblock_contents(context, &(lt->entry->key));
            retval = krb5_c_make_random_key(context,enctype,&(lt->entry->key));
            if (retval) {
                fprintf(stderr,_("ukt: Unable to generate "
                                 "random key, aborting\n"));
                break;
            }
            i++;
        }
        if (retval) {
            ktutil_free_kt_list(context, tail);
            tail = NULL;
            if (back)
                back->next = NULL;
            i = 0;
        }
        fprintf(stdout,"%d entry(s) upgraded\n",i);
    }
    if (!*list)
        *list = tail;
    krb5_kt_end_seq_get(context, kt, &cursor);
close_kt:
    krb5_kt_close(context, kt);
exit_princ:
    if (princ_str)
        krb5_free_principal(context,princ);
    return retval;
}


/*
 * Takes a kt_list and writes it to the named keytab.
 */
krb5_error_code ktutil_write_keytab(context, list, name)
    krb5_context context;
    krb5_kt_list list;
    char *name;
{
    krb5_kt_list lp;
    krb5_keytab kt;
    char ktname[MAXPATHLEN+sizeof("WRFILE:")+1];
    krb5_error_code retval = 0;
    int result;

    result = snprintf(ktname, sizeof(ktname), "WRFILE:%s", name);
    if (SNPRINTF_OVERFLOW(result, sizeof(ktname)))
        return ENAMETOOLONG;
    retval = krb5_kt_resolve(context, ktname, &kt);
    if (retval)
        return retval;
    for (lp = list; lp; lp = lp->next) {
        retval = krb5_kt_add_entry(context, kt, lp->entry);
        if (retval)
            break;
    }
    krb5_kt_close(context, kt);
    return retval;
}

/*
 * Read in a named krb4 srvtab and append to list.  Allocate new list
 * if needed.
 */
krb5_error_code ktutil_read_srvtab(context, name, list)
    krb5_context context;
    char *name;
    krb5_kt_list *list;
{
    char *ktname;
    krb5_error_code result;

    if (asprintf(&ktname, "SRVTAB:%s", name) < 0)
        return ENOMEM;
    result = ktutil_read_keytab(context, ktname, list);
    free(ktname);
    return result;
}
