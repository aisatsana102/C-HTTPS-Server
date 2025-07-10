/*######################################
##                                    ##
##                                    ##
######################################*/

struct {
	char *ext;
	char *fileType;
} extensions[] = {
         {"gif", "image/gif" },  {"jpg", "image/jpg" }, {"jpeg","image/jpeg"},
         {"png", "image/png" },  {"ico", "image/ico" },  {"zip", "application/zip" },
         {"gz",  "application/gzip"  },  {"tar", "applicatoin/x-tar" },  {"htm", "text/html" },
	 {"html","text/html" }, {"css", "text/css"},  {0,0}
};
