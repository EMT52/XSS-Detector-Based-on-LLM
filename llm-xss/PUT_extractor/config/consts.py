import re
import os
import json

PHP_EXTENSION = ["php", "inc", "phtml"]

NONLOCAL_FUNCTIONS = {"pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
                    "mysqli_real_query", "mysql_fetch_array", "mysql_num_rows", "fbird_query", "fbird_fetch_row",
                    "fbird_blob_open", "fbird_blob_info", "fbird_blob_get", "fbird_blob_close", "fbird_errmsg", 
                    "mysqli_errno", "mysqli_error", "file_put_contents", "connect", "mysql_connect", "mysqli_connect", 
                    "mysql_real_escape_string", "mysqli_real_escape_string", "sqlite_escape_string", "curl_init",
                    "curl_setopt", "curl_exec", "curl_close"}