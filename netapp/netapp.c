/*
 * Copyright (c) 2009-2016 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

// This is the netapp-specific code, called from reviewquotas.
// Its main job is to pull all existng quotas from the netapp
// and call the callback for each user to see if their quota
// needs to change.

// However we also have to add quotas for users that don't have
// them, if the amount they get isn't the default.
// We build a list of all users with directories, and a hash
// table into that list. When we see a user's entry from the
// netapp, we note that we've seen that user.

// Then at the end we go through the list processing all users
// that haven't been seen. Those are the new ones.

// They have to be done separately because updating a quota
// and adding one are different API operatinos. Updating a
// quota requires the UUID of the existing quota rule. Adding
// a new one needs the username, volume and qtree.


#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <dirent.h>

#include <curl/curl.h>
#include <jansson.h>

#define BUFFER_SIZE (20 * 1024 * 1024) /* 20 MB - currently ilab is 4 MB */

#define INIT_URL "https://cluster.lcsr.rutgers.edu/api/storage/quota/rules?qtree.name=%s&fields=space.hard_limit,users.name"
  
#define URL_SIZE   256

// code to process a single user. Quota list is the parsed
// entries from the quota file, which we interpret to see
// plus all the data needed to add or update a quota

char *getstatsp = NULL;
char *quotamanagerp = NULL;

extern int us_callback(void *quotalist, const char *uuid, const char *username, long space, char *vol, char *qtree);

// There is a hash table for users that have directories
// on this file system. The hash table is actually two data structures.
// When we look at quotas we have a username and need
// to get to the entry. we use the hash for that.
//   However the C hash table doesn't have any way to go through
// all the entries. So the entries include a pointer. We link all
// of them into a list. That lets us go through them all
//   The following declaration is for the data that is put into
// the hash table. The username is the key. It retrieves this
// struct as the data. But we can also go through the list and
// get to all the entries one by one.

struct userentry {
  int seen;
  char *user;
  struct userentry *next;
};

// this is the list that goes through all the entries
struct userentry *userlist = NULL;

/* Return the offset of the first newline in text or the length of
   text if there's no newline */
static int newline_offset(const char *text) {
    const char *newline = strchr(text, '\n');
    if (!newline)
        return strlen(text);
    else
        return (int)(newline - text);
}

struct write_result {
    char *data;
    int pos;
};

// boilerplate for to process a big JSON struction from the netapp

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream) {
    struct write_result *result = (struct write_result *)stream;

    if (result->pos + size * nmemb >= BUFFER_SIZE - 1) {
        fprintf(stderr, "error: too small buffer\n");
        return 0;
    }

    memcpy(result->data + result->pos, ptr, size * nmemb);
    result->pos += size * nmemb;

    return size * nmemb;
}

// more bolierplate for libcurl. Set up the query
// for curl. Note that we specify the user:password
// here, and also the equivlent of -k. 

static char *request(const char *url) {
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    // first see if we need the passwords
    if (!getstatsp) {
      FILE *fp = fopen("/etc/netapp.conf", "r");
      char *line = NULL;
      size_t len = 0;

      if (!fp) {
	fprintf(stderr, "Can't open  /etc/netapp.conf");
	exit(1);
      }

      while (getline(&line, &len, fp) != -1) {
	if (strncmp(line, "getstats:", strlen("getstats:")) == 0) {
	  size_t eol = strlen(line) - 1;
	  if (line[eol] == '\n')
	    line[eol] = '\0';
	  getstatsp = strdup(line);
	} else if (strncmp(line, "quotamanager:", strlen("quotamanager:")) == 0) {
	  size_t eol = strlen(line) - 1;
	  if (line[eol] == '\n')
	    line[eol] = '\0';
	  quotamanagerp = strdup(line);
	}
      }
    }

    if (!getstatsp || !quotamanagerp) {
      fprintf(stderr, "Didn't get both netapp passwords\n");
      exit(1);
    }

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl)
        goto error;

    data = malloc(BUFFER_SIZE);
    if (!data)
        goto error;

    struct write_result write_result = {.data = data, .pos = 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* GitHub commits API v3 requires a User-Agent header */
    headers = curl_slist_append(headers, "User-Agent: Jansson");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);
    curl_easy_setopt(curl, CURLOPT_USERPWD, getstatsp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

    status = curl_easy_perform(curl);
    if (status != 0) {
        fprintf(stderr, "error: unable to request data from %s:\n", url);
        fprintf(stderr, "%s\n", curl_easy_strerror(status));
        goto error;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code != 200) {
        fprintf(stderr, "error: server responded with code %ld\n", code);
        goto error;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    /* zero-terminate the result */
    data[write_result.pos] = '\0';

    return data;

error:
    if (data)
        free(data);
    if (curl)
        curl_easy_cleanup(curl);
    if (headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();
    return NULL;
}

// See the comment where userentry is declared.
// This is a slightly odd data structure.

// when going through list of directories
// add a user to the user hash table
// that table is used to detect users with
// directories but no quota

void addtohash (char *username) {
  ENTRY entry;
  struct userentry *userentry;

  userentry = malloc(sizeof(struct userentry));
  // set seen when we process an existing
  // quota for this user. Those without seen
  // set are new users. May need new quotas for them.
  userentry->seen = 0;
  userentry->user = username;
  // userlist is a linked list. append this to list
  userentry->next = userlist;
  userlist = userentry;

  entry.key = username;
  entry.data = userentry;

  hsearch(entry, ENTER);
}

// for user who has quota entry,
// if they also have a directory entry
// say we've seen the user. Users who have directories
// but haven't been seen may need new quota entris
void markasseen(const char *username) {
  ENTRY hentry;
  ENTRY *hptr;
  struct userentry *userentry;

  hentry.key = (char *)username;
  hentry.data = NULL;
  hptr = hsearch(hentry, FIND);
  if (hptr) {
    userentry = (struct userentry *) hptr->data;
    userentry->seen = 1;
  }
}



// the main code for this module
// prcess one file system. some of the args are needed
// by the callback, so we have to pass them through.

// main approach:
//   look at all directories, saving the username in the hash table
//   look at all existing quotas
//      if the quota is wrong, fix it
//      remember in the hash table that we've seen a quota for this user
//   review all users in the hash (i.e. with directories). If any don't
//     have quotas, maybe add one

int procfs(char *dirname, char *vol, void *quotalist, char *qtree) {
    size_t i;
    char *text;
    char url[URL_SIZE];
    const char *nexturl;
    long default_quota = 0L;
    struct dirent **namelist;
    int numdirs;
    struct userentry *userentry;

    json_t *root;
    json_error_t error;
    json_t *records;
    json_t *users;
    json_t *name;
    json_t *space;
    json_t *hard;

    if (dirname == NULL && vol == NULL && quotalist == NULL)
      return;
    if (dirname == NULL || vol == NULL || quotalist == NULL) {
      fprintf(stderr, "incomplete section %s %s\n", dirname?dirname:"", vol?vol:"");
      exit(1);
    }

    // get lits of users in directory, so we can add quotas
    // for any that don't have them

    // max number of uids simulteaneously logged in 
    hcreate(10000);

    //    printf("point 1\n");
    numdirs = scandir(dirname, &namelist, NULL, alphasort);
    if (numdirs < 0) {
      fprintf(stderr, "Couldn't scan %s", dirname);
      exit(1);
    }

    for (i = 0; i < numdirs; i++) {
      char *uname = strdup(namelist[i]->d_name);
      
      // make sure it's a user
      if (!getpwnam(uname))
	continue;
	
      addtohash(uname);

    }
    //    printf("point 2\n");

    snprintf(url, URL_SIZE, INIT_URL, qtree);

    // we have all the users with directories
    // now get all the quotas

    text = request(url);
    if (!text)
      exit(1);

    root = json_loads(text, 0, &error);
    free(text);

    if (!root) {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
	exit(1);
    }

    // now process the qtree results. For each user with
    // an entry, get the data out of the json struct
    // and use the callback to see if they need adustment

    if (!json_is_object(root)) {
        fprintf(stderr, "error: root is not an object\n");
        json_decref(root);
	exit(1);
    }

    records = json_object_get(root, "records");
    if (!json_is_array(records)) {
      fprintf(stderr, "error: no records\n");
      json_decref(root);
      exit(1);
    }

    for (i = 0; i < json_array_size(records); i++) {
    	json_t *data, *user, *uuid;
        const char *username;
	long long hardlimit = 0;
	const char *uuids;

        data = json_array_get(records, i);
        if (!json_is_object(data)) {
            fprintf(stderr, "error: rules data %d is not an object\n", (int)(i + 1));
	    fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
            json_decref(root);
	    exit(1);
        }

	users = json_object_get(data, "users");
        if (!json_is_array(users)) {
	  // some kind of overhead entry
	  continue;
	}
	if (json_array_size(users) != 1) {
	  // haven't seen this one
	  fprintf(stderr, "user array size %d, skipping\n", json_array_size(users));
	  fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
	  exit(1);
	}
	user = json_array_get(users, 0);
        if (!json_is_object(user)) {
	  // haven't seen this one
	  fprintf(stderr, "error: user not an object\n");
	  json_decref(root);
	  fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
	  exit(1);
        }
	name = json_object_get(user, "name");
	if (!json_is_string(name)) {
	  // haven't seen this
	  fprintf(stderr, "username not a string\n");
	  fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
	  exit(1);
	}
	username = json_string_value(name);
	// null username is the default

	// say we've seen this user
	markasseen(username);

	uuid = json_object_get(data, "uuid");

	if (!json_is_string(uuid)) {
	  fprintf(stderr, "uuid not a string\n");
	  fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
	  exit(1);
	}

	uuids = json_string_value(uuid);

	space = json_object_get(data, "space");
        if (!json_is_object(space)) {
	  // no quota
	  hardlimit = -1L;
	  goto havequota;
        }
	hard = json_object_get(space, "hard_limit");
	if (!json_is_number(hard)) {
	  // one quota is simply -. treat it as no quota
	  hardlimit = -1L;
	  goto havequota;
	}
	if (json_is_integer(hard)) {
	  hardlimit = json_integer_value(hard);
	} else if (json_is_real(hard)) {
	  hardlimit = (long long)json_real_value(hard);
	} else {
	  fprintf(stderr, "hard limit unknown number type");
	  fprintf(stderr, "%s\n", json_dumps(data, JSON_INDENT(3)));
	  exit(1);
	}
    havequota:

	// we now have all the info we need for this user.
	// cal the callback

	// zero length username is the default quota
	// save it for user in processing new users
	if (strlen(username) > 0)
	  us_callback(quotalist, uuids, username, hardlimit, NULL, NULL);
	else
	  default_quota = hardlimit;

    }

    // now add quotas for users that don't have them
    // userlist is a list of everything in the hash table
    // i.e. all users with directories. If we haven't seen
    // a quota, add one if needed

    // loop over users with directories
    userentry = userlist;
    while (userentry) {
      struct userentry *next = userentry->next;
      // if we haven't seen an existing entry for this
      // user, use the callback to maybe add a quota
      // for them. Pass the Netapp's default quota as 
      // current value. That way no entry will be created
      // if it would be the same as the Netapp's default.
      if (!userentry->seen)
	us_callback(quotalist, NULL, userentry->user, default_quota, vol, qtree);
      if (userentry->user)
	free(userentry->user);
      free(userentry);
      userentry = next;
    }      

    userlist = NULL;
    hdestroy();

    // remember, this is just one file system
    // the quotas file may have more than one. 
    // we return to the main loop over file systems


}
