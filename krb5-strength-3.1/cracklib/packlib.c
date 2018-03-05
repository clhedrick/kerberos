/*
 * This program is copyright Alec Muffett 1993. The author disclaims all 
 * responsibility or liability with respect to it's usage or its effect 
 * upon hardware or computer systems, and maintains copyright as set out 
 * in the "LICENCE" document which accompanies distributions of Crack v4.0 
 * and upwards.
 */

/*
 * Modified as part of the krb5-strength project as follows:
 *
 * 2007-03-23  Russ Allbery <eagle@eyrie.org>
 *   - Apply Debian patch to improve the search logic.
 *   - Don't crash if the dictionary is corrupt.
 *   - Additional system includes for other functions.
 * 2009-10-14  Russ Allbery <eagle@eyrie.org>
 *   - Add ANSI C protototypes for all functions.
 *   - Tweaks for const cleanliness.
 *   - Add parentheses around assignment used for its truth value.
 *   - Make internal functions static.
 *   - Remove unused variables.
 * 2009-11-18  Russ Allbery <eagle@eyrie.org>
 *   - Fixed the data format output by packer to properly pad the end.
 * 2013-09-24  Russ Allbery <eagle@eyrie.org>
 *   - Add a missing ANSI C prototype.
 *   - Remove last block optimization in GetPW and start fresh each time.
 * 2013-12-13  Russ Allbery <eagle@eyrie.org>
 *   - Close the wfp file handle on PWClose if it's open.
 * 2016-11-06  Russ Allbery <eagle@eyrie.org>
 *   - Remove unused vers_id to silence GCC warnings.
 */

#include <stdio.h>
#include <string.h>

#include "packer.h"

PWDICT *
PWOpen(const char *prefix, const char *mode)
{
    static PWDICT pdesc;
    char iname[STRINGSIZE];
    char dname[STRINGSIZE];
    char wname[STRINGSIZE];
    FILE *dfp;
    FILE *ifp;
    FILE *wfp;

    if (pdesc.header.pih_magic == PIH_MAGIC)
    {
	fprintf(stderr, "%s: another dictionary already open\n", prefix);
	return ((PWDICT *) 0);
    }

    memset(&pdesc, '\0', sizeof(pdesc));

    sprintf(iname, "%s.pwi", prefix);
    sprintf(dname, "%s.pwd", prefix);
    sprintf(wname, "%s.hwm", prefix);

    if (!(pdesc.dfp = fopen(dname, mode)))
    {
	perror(dname);
	return ((PWDICT *) 0);
    }

    if (!(pdesc.ifp = fopen(iname, mode)))
    {
	fclose(pdesc.dfp);
	perror(iname);
	return ((PWDICT *) 0);
    }

    if ((pdesc.wfp = fopen(wname, mode)) != NULL)
    {
	pdesc.flags |= PFOR_USEHWMS;
    }

    ifp = pdesc.ifp;
    dfp = pdesc.dfp;
    wfp = pdesc.wfp;

    if (mode[0] == 'w')
    {
	pdesc.flags |= PFOR_WRITE;
	pdesc.header.pih_magic = PIH_MAGIC;
	pdesc.header.pih_blocklen = NUMWORDS;
	pdesc.header.pih_numwords = 0;

	fwrite((char *) &pdesc.header, sizeof(pdesc.header), 1, ifp);
    } else
    {
	pdesc.flags &= ~PFOR_WRITE;

	if (!fread((char *) &pdesc.header, sizeof(pdesc.header), 1, ifp))
	{
	    fprintf(stderr, "%s: error reading header\n", prefix);

	    pdesc.header.pih_magic = 0;
	    fclose(ifp);
	    fclose(dfp);
	    if (wfp != NULL)
	    {
		fclose(wfp);
	    }
	    return ((PWDICT *) 0);
	}

	if (pdesc.header.pih_magic != PIH_MAGIC)
	{
	    fprintf(stderr, "%s: magic mismatch\n", prefix);

	    pdesc.header.pih_magic = 0;
	    fclose(ifp);
	    fclose(dfp);
	    if (wfp != NULL)
	    {
		fclose(wfp);
	    }
	    return ((PWDICT *) 0);
	}

	if (pdesc.header.pih_blocklen != NUMWORDS)
	{
	    fprintf(stderr, "%s: size mismatch\n", prefix);

	    pdesc.header.pih_magic = 0;
	    fclose(ifp);
	    fclose(dfp);
	    if (wfp != NULL)
	    {
		fclose(wfp);
	    }
	    return ((PWDICT *) 0);
	}

	if (pdesc.flags & PFOR_USEHWMS)
	{
	    if (fread(pdesc.hwms, 1, sizeof(pdesc.hwms), wfp) != sizeof(pdesc.hwms))
	    {
		pdesc.flags &= ~PFOR_USEHWMS;
	    }
	}
    }

    return (&pdesc);
}

int
PWClose(PWDICT *pwp)
{
    if (pwp->header.pih_magic != PIH_MAGIC)
    {
	fprintf(stderr, "PWClose: close magic mismatch\n");
	return (-1);
    }

    if (pwp->flags & PFOR_WRITE)
    {
	pwp->flags |= PFOR_FLUSH;
	PutPW(pwp, (char *) 0);	/* flush last index if necess */

	if (fseek(pwp->ifp, 0L, 0))
	{
	    fprintf(stderr, "index magic fseek failed\n");
	    return (-1);
	}

	if (!fwrite((char *) &pwp->header, sizeof(pwp->header), 1, pwp->ifp))
	{
	    fprintf(stderr, "index magic fwrite failed\n");
	    return (-1);
	}

	if (pwp->flags & PFOR_USEHWMS)
	{
	    int i;
	    for (i=1; i<=0xff; i++)
	    {
	    	if (!pwp->hwms[i])
	    	{
	    	    pwp->hwms[i] = pwp->hwms[i-1];
	    	}
#ifdef DEBUG
	    	printf("hwm[%02x] = %d\n", i, pwp->hwms[i]);
#endif
	    }
	    fwrite(pwp->hwms, 1, sizeof(pwp->hwms), pwp->wfp);
	}
    }

    fclose(pwp->ifp);
    fclose(pwp->dfp);
    if (pwp->wfp != NULL)
    {
	fclose(pwp->wfp);
    }

    pwp->header.pih_magic = 0;

    return (0);
}

int
PutPW(PWDICT *pwp, const char *string)
{
    if (!(pwp->flags & PFOR_WRITE))
    {
	return (-1);
    }

    if (string)
    {
	strncpy(pwp->data[pwp->count], string, MAXWORDLEN);
	pwp->data[pwp->count][MAXWORDLEN - 1] = '\0';

	pwp->hwms[string[0] & 0xff]= pwp->header.pih_numwords;

	++(pwp->count);
	++(pwp->header.pih_numwords);

    } else if (!(pwp->flags & PFOR_FLUSH))
    {
	return (-1);
    }

    if ((pwp->flags & PFOR_FLUSH) || !(pwp->count % NUMWORDS))
    {
	int i;
	int32 datum;
	register char *ostr;

	datum = (int32) ftell(pwp->dfp);

	fwrite((char *) &datum, sizeof(datum), 1, pwp->ifp);

	fputs(pwp->data[0], pwp->dfp);
	putc(0, pwp->dfp);

	ostr = pwp->data[0];

	for (i = 1; i < NUMWORDS; i++)
	{
	    register int j;
	    register char *nstr;
	    nstr = pwp->data[i];

	    if (nstr[0])
	    {
		for (j = 0; ostr[j] && nstr[j] && (ostr[j] == nstr[j]); j++);
		putc(j & 0xff, pwp->dfp);
		fputs(nstr + j, pwp->dfp);
	    } else
	    {
		putc(0, pwp->dfp);
	    }
	    putc(0, pwp->dfp);

	    ostr = nstr;
	}

	memset(pwp->data, '\0', sizeof(pwp->data));
	pwp->count = 0;
    }
    return (0);
}

static char *
GetPW(PWDICT *pwp, int32 number)
{
    int32 datum;
    register int i;
    register char *ostr;
    register char *nstr;
    register char *bptr;
    char buffer[NUMWORDS * MAXWORDLEN];
    static char data[NUMWORDS][MAXWORDLEN];
    int32 thisblock;

    thisblock = number / NUMWORDS;

    if (fseek(pwp->ifp, sizeof(struct pi_header) + (thisblock * sizeof(int32)), 0))
    {
	perror("(index fseek failed)");
	return ((char *) 0);
    }

    if (!fread((char *) &datum, sizeof(datum), 1, pwp->ifp))
    {
	perror("(index fread failed)");
	return ((char *) 0);
    }

    if (fseek(pwp->dfp, datum, 0))
    {
	perror("(data fseek failed)");
	return ((char *) 0);
    }

    if (!fread(buffer, 1, sizeof(buffer), pwp->dfp))
    {
	perror("(data fread failed)");
	return ((char *) 0);
    }

    bptr = buffer;

    for (ostr = data[0]; (*(ostr++) = *(bptr++)) != '\0'; /* nothing */ );

    ostr = data[0];

    for (i = 1; i < NUMWORDS; i++)
    {
	nstr = data[i];
	strcpy(nstr, ostr);

	ostr = nstr + *(bptr++);
	while ((*(ostr++) = *(bptr++)) != '\0');

	ostr = nstr;
    }

    return (data[number % NUMWORDS]);
}

int32
FindPW(PWDICT *pwp, const char *string)
{
    register int32 lwm;
    register int32 hwm;
    register int32 middle;
    register char *this;
    int idx;

    if (pwp->flags & PFOR_USEHWMS)
    {
	idx = string[0] & 0xff;
    	lwm = idx ? pwp->hwms[idx - 1] : 0;
    	hwm = pwp->hwms[idx];
    } else
    {
    	lwm = 0;
    	hwm = PW_WORDS(pwp) - 1;
    }

#ifdef DEBUG
    printf("---- %lu, %lu ----\n", lwm, hwm);
#endif

    for (;;)
    {
	int cmp;

#ifdef DEBUG
	printf("%lu, %lu\n", lwm, hwm);
#endif

	middle = lwm + ((hwm - lwm + 1) / 2);

	/*
	 * If GetPW returns NULL, we have a corrupt dictionary.	 It's hard to
	 * figure out the best thing to do here.  Returning true for every
	 * password seems better than just crashing the program.
	 */
	this = GetPW(pwp, middle);
	if (this == NULL)
	{
	    return (middle);
	}
	cmp = strcmp(string, this);		/* INLINE ? */

	if (cmp < 0)
	{
	   /* The following may be a little non-obvious... it's
	    * basically doing:
	    *
	    *	hwm = middle - 1;
	    *	if (hwm < lwm)
	    *	    break;
	    *
	    * which is much clearer, but it unfortunately doesn't work
	    * because hwm is unsigned and middle may legitimately be
	    * zero, which would lead to hwm being set to a very high
	    * number.  So instead we have...
	    */
	   if (middle == lwm)
	       break;
	   hwm = middle - 1;
	} else if (cmp > 0)
	{
	   if (middle == hwm)
	       break;
	   lwm = middle + 1;
	} else
	{
	    return (middle);
	}
    }

    return (PW_WORDS(pwp));
}
