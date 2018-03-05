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
 *   - Add ANSI C prototypes and prototype additional functions.
 * 2009-10-14  Russ Allbery <eagle@eyrie.org>
 *   - Prototype changes for const cleanliness.
 * 2010-03-14  Russ Allbery <eagle@eyrie.org>
 *   - Fix int8, int16, and int32 definitions.
 * 2013-10-01  Russ Allbery <eagle@eyrie.org>
 *   - Set hidden visibility on all symbols by default.
 */

#include <config.h>
#include <portable/system.h>

#include <ctype.h>

#define STRINGSIZE	1024
#define TRUNCSTRINGSIZE	(STRINGSIZE/4)

typedef uint8_t int8;
typedef uint16_t int16;
typedef uint32_t int32;
#ifndef NUMWORDS
#define NUMWORDS 	16
#endif
#define MAXWORDLEN	32
#define MAXBLOCKLEN 	(MAXWORDLEN * NUMWORDS)

struct pi_header
{
    int32 pih_magic;
    int32 pih_numwords;
    int16 pih_blocklen;
    int16 pih_pad;
};

typedef struct
{
    FILE *ifp;
    FILE *dfp;
    FILE *wfp;

    int32 flags;
#define PFOR_WRITE	0x0001
#define PFOR_FLUSH	0x0002
#define PFOR_USEHWMS	0x0004

    int32 hwms[256];

    struct pi_header header;

    int count;
    char data[NUMWORDS][MAXWORDLEN];
} PWDICT;

#define PW_WORDS(x) ((x)->header.pih_numwords)
#define PIH_MAGIC 0x70775631

/* Default to a hidden visibility for all CrackLib functions. */
#pragma GCC visibility push(hidden)

extern PWDICT *PWOpen(const char *, const char *);
extern int32 FindPW(PWDICT *, const char *);
extern int PutPW(PWDICT *, const char *);
extern int PWClose(PWDICT *);
extern char *Mangle(const char *, const char *);
extern const char *FascistCheck(const char *, const char *);
extern char Chop(char *);
extern char *Trim(char *);
extern int PMatch(const char *, const char *);
extern char *Reverse(const char *);
extern char *Lowercase(const char *);

/* Undo default visibility change. */
#pragma GCC visibility pop

#define CRACK_TOLOWER(a) 	(isupper(a)?tolower(a):(a)) 
#define CRACK_TOUPPER(a) 	(islower(a)?toupper(a):(a)) 
#define STRCMP(a,b)		strcmp((a),(b))
