// this is a demo file from the libcurl project
// for doing a post. We've tailored it a bit
// and added an option to do a PATCH. Adding a
// quota uses POST. Adjusting an existing one uses PATCH.

// We've adjusted the URL to call
// The data to POST
// Added a user/password and the -k option
// But mostly this is the sample code.

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * Make a HTTP POST with data from memory and receive response in memory.
 * </DESC>
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern char *quotamanagerp;

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}
int change_quota(char *uuid, long quota, char *vol, char *qtree, const char *username)
{
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;

  // json to PATCH for adjusting a quota
  static const char *posttemplate = "{  \"space\": {    \"hard_limit\": %ld  }}";
  static const char *urltemplate = "https://cluster.lcsr.rutgers.edu/api/storage/quota/rules/%s";
  static const char *addurl = "https://cluster.lcsr.rutgers.edu/api/storage/quota/rules";
  // json to POST for adding a quota
  static const char *addtemplate = "{ \"qtree\": {\"name\": \"%s\" }, \"space\": { \"hard_limit\":  %lu }, \"svm\": { \"name\": \"koko.lcsr.rutgers.edu\" }, \"type\": \"user\",  \"user_mapping\": \"off\", \"users\": [ { \"name\": \"%s\" } ],  \"volume\": { \"name\": \"%s\" } }";

  char *postthis;
  char *url;

  if (uuid) {
    (void)asprintf(&postthis, posttemplate, quota);
    (void)asprintf(&url, urltemplate, uuid);
  } else {
    (void)asprintf(&postthis, addtemplate, qtree, quota, username, vol);
    (void)asprintf(&url, "%s", addurl);
  }

  chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
  chunk.size = 0;    /* no data at this point */
  struct curl_slist *list = NULL;

  
  //  fprintf(stderr, "point 1\n");
  //  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "curl_easy_init failed\n");
    exit(1);
  }
  fprintf(stderr, "curl_easy_init ret %d\n", curl);
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    if (uuid)
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* some servers don't like requests that are made without a user-agent
       field, so we provide one */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl, CURLOPT_USERPWD, quotamanagerp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postthis);

    list = curl_slist_append(list, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

    /* if we don't provide POSTFIELDSIZE, libcurl will strlen() by
       itself */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postthis));

    printf("patch %s %s\n", url, postthis);
    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
      exit(1);
    }
    else {
      /*
       * Now, our chunk.memory points to a memory block that is chunk.size
       * bytes big and contains the remote file.
       *
       * Do something nice with it!
       */
      fprintf(stderr, "%s\n",chunk.memory);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  free(chunk.memory);
  //  curl_global_cleanup();
  return 0;
}

#ifdef MAIN
main (int argc, char **argv) {
  curl_global_init(CURL_GLOBAL_ALL);
  change_quota(NULL, 10000L, "vol1", "ilab", "testuser");
}
#endif
