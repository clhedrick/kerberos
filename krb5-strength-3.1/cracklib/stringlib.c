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
 *   - Additional system includes for other functions.
 * 2009-10-14  Russ Allbery <eagle@eyrie.org>
 *   - Add ANSI C protototypes for all functions.
 *   - Remove unused Clone function.
 * 2016-11-06  Russ Allbery <eagle@eyrie.org>
 *   - Remove unused vers_id to silence GCC warnings.
 */

#include <string.h>
#include <stdlib.h>

#include "packer.h"

char
Chop(char *string)
{
    register char c;
    register char *ptr;
    c = '\0';

    for (ptr = string; *ptr; ptr++);
    if (ptr != string)
    {
	c = *(--ptr);
	*ptr = '\0';
    }
    return (c);
}

char *
Trim(char *string)
{
    register char *ptr;
    for (ptr = string; *ptr; ptr++);

    while ((--ptr >= string) && isspace(*ptr));

    *(++ptr) = '\0';

    return (ptr);
}
