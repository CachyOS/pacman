/*
 *  update-notice.c
 *
 *  Copyright (c) 2023 by Vladislav Nepogodin <vnepogodin@cachyos.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* intmax_t */
#include <string.h>
#include <errno.h>
#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#endif

#include <alpm.h>
#include <alpm_list.h>

#define JSMN_STATIC
#include "jsmn.h"

/* pacman */
#include "update-notice.h"
#include "util.h"
#include "conf.h"

struct url_data {
    size_t size;
    char* data;
};

static size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data) {
    const size_t index = data->size;
    const size_t n = (size * nmemb);

    data->size += (size * nmemb);

    char* tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */
    if (tmp) {
        data->data = tmp;
    } else {
        if(data->data) {
            free(data->data);
        }
        return 0;
    }

    memcpy((data->data + index), ptr, n);
    data->data[data->size] = '\0';

    return size * nmemb;
}

static int write_data_to_file(const char *filepath, const char *content) {
    FILE *fp = NULL;
    if((fp = fopen(filepath, "wb")) == NULL) {
        return -1;
    }

    const size_t contentLength = strlen(content);
    fwrite(content, sizeof(char), contentLength, fp);
    fclose(fp);

    return 0;
}

static char *read_whole_file(const char* filepath) {
    FILE *fp = NULL;
    if((fp = fopen(filepath, "rb")) == NULL) {
        return NULL;
    }

    fseek(fp, 0u, SEEK_END);
    const size_t size = ftell(fp);
    fseek(fp, 0u, SEEK_SET);

    char *buf = (char *) malloc(size + 1);
    buf[0] = '\0';

    const size_t read = fread(buf, sizeof(char), size, fp);
    if (read != size) {
        return NULL;
    }
    fclose(fp);

    buf[size] = '\0';
    return buf;
}

static char *handle_url(const char* url) {
    struct url_data data;
    data.size = 0;
    data.data = malloc(4096); /* reasonable size initial buffer */
    if (data.data == NULL) {
        return NULL;
    }

    data.data[0] = '\0';

    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            free(data.data);
            return NULL;
        }

        curl_easy_cleanup(curl);

    }
    return data.data;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

static int check_cachyos_repos(void) {
    alpm_list_t* dbs = alpm_get_syncdbs(config->handle);
    for (alpm_list_t* i = dbs; i; i = i->next) {
        const char* db_name = alpm_db_get_name(i->data);
        if(strstr(db_name, "cachyos") != NULL) {
            return 0;
        }
    }

    return -1;
}

static int retrive_data_from_json(const char* jsondata, char** msg_id, char** msg_body) {
    jsmn_parser p;
    jsmntok_t t[128]; /* We expect no more than 4 tokens */

    jsmn_init(&p);
    int key_count = jsmn_parse(&p, jsondata, strlen(jsondata), t, sizeof(t) / sizeof(t[0]));
    if (key_count < 0) {
        return -1;
    }

    /* Assume the top-level element is an object */
    if (key_count < 1 || t[0].type != JSMN_OBJECT) {
        return -1;
    }

    /* Loop over all keys of the root object */
    for (int i = 1; i < key_count; ++i) {
        if (jsoneq(jsondata, &t[i], "id") == 0) {
            *msg_id = strndup(jsondata + t[i + 1].start, t[i + 1].end - t[i + 1].start);
        } else if (jsoneq(jsondata, &t[i], "body") == 0) {
            *msg_body = strndup(jsondata + t[i + 1].start, t[i + 1].end - t[i + 1].start);
        }
    }

    return 0;
}

static void replace_all_chars(const char *st, const char *subst, char c) {
    /* find first occurrence of substring */
    register char *loc = strstr(st, subst);
    register char *next = loc;
    while (loc) {
        *next++ = c;
        register char *tail = loc + strlen(subst);

        /* find next occurrence of substring */
        if ((loc = strstr(tail, subst))) {
            ptrdiff_t copy_len = loc - tail;

            /* move the remaining characters to their new positions */
            memmove(next, tail, copy_len);
            next += copy_len;
        } else {
            /* copy the remaining tail characters including the null terminator */
            memmove(next, tail, strlen(tail) + 1);
        }
    }
}

int do_update_notice(void) {
    /* check if we have cachyos repositories */
    int ret = check_cachyos_repos();
    if (ret != 0) {
        return 0;
    }

    char* data = handle_url("https://iso-stats.cachyos.org/api/v2/last_update_notice");
    if (!data) {
        return 0;
    }

    char* msg_id = NULL;
    char* msg_body = NULL;
    if (retrive_data_from_json(data, &msg_id, &msg_body) != 0) {
        pm_printf(ALPM_LOG_ERROR, _("invalid update notice server response\n"));
        ret = -1;
        goto cleanup;
    }

    char* prev_file_id = NULL;
    char noticepath[PATH_MAX];
    snprintf(noticepath, PATH_MAX, "%slocal/CACHY_UPDATE_NOTICE", config->dbpath);

    if (msg_id && (prev_file_id = read_whole_file(noticepath)) != NULL
        && strcmp(msg_id, prev_file_id) == 0) {
        free(prev_file_id);
        goto cleanup;
    }

    if (msg_body) {
        /* cover case when we receive multiline message */
        replace_all_chars(msg_body, "\\n", '\n');

        printf(_("%sUpdate notice: %s%s\n"), config->colstr.warn,
                            config->colstr.nocolor, msg_body);
        if (yesno(_("Do you want to continue?")) == 0) {
            ret = -1;
            goto cleanup;
        }
        if (write_data_to_file(noticepath, msg_id) != 0)  {
            pm_printf(ALPM_LOG_ERROR, _("could not save notice id: %s\n"), strerror(errno));
            ret = -1;
            goto cleanup;
        }
    }

cleanup:
    if (msg_id) {
        free(msg_id);
    }
    if (msg_body) {
        free(msg_body);
    }
    free(data);

    return ret;
}
