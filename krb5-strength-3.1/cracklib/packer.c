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
 * 2009-10-14  Russ Allbery <eagle@eyrie.org>
 *   - Add ANSI C protototypes for all functions.
 * 2010-03-14  Russ Allbery <eagle@eyrie.org>
 *   - Use unsigned long instead of int32 to avoid printf warnings.
 * 2016-11-06  Mark Sirota <msirota@isc.upenn.edu>
 *   - Display a warning when processing out-of-order input.
 */

#include "packer.h"

int
main(int argc, char *argv[])
{
    unsigned long readed;
    unsigned long wrote;
    PWDICT *pwp;
    char buffer[STRINGSIZE], prev[STRINGSIZE];

    if (argc <= 1)
    {
	fprintf(stderr, "Usage:\t%s dbname\n", argv[0]);
	return (-1);
    }

    if (!(pwp = PWOpen(argv[1], "w")))
    {
	perror(argv[1]);
	return (-1);
    }

    wrote = 0;
    prev[0] = '\0';

    for (readed = 0; fgets(buffer, STRINGSIZE, stdin); /* nothing */)
    {
    	readed++;

	buffer[MAXWORDLEN - 1] = '\0';

	Chop(buffer);

	if (!buffer[0])
	{
	    fprintf(stderr, "skipping line: %lu\n", readed);
	    continue;
	}

	/*
	 * If this happens, strcmp() in FindPW() in packlib.c will be unhappy.
	 */
	if (strcmp(buffer, prev) < 0)
	{
	    fprintf(stderr, "warning: input out of order: '%s' should not"
		    " follow '%s' (line %lu), skipping\n", buffer, prev,
		    readed);
	    continue;
	}
	strcpy(prev, buffer);

	if (PutPW(pwp, buffer))
	{
	    fprintf(stderr, "error: PutPW '%s' line %luy\n", buffer, readed);
	}

	wrote++;
    }

    PWClose(pwp);

    printf("%lu %lu\n", readed, wrote);

    return (0);
}
