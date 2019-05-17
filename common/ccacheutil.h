// all dependency upon specific cache types should be in this library

char *convert_to_collection(const char *ptr, uid_t uid);

uid_t ccname_to_uid(const char *ptr, uid_t uid);

int is_collection_type(const char *ccname);

int is_collection(const char *ccname);

char * get_cc_type(const char *ccname);



