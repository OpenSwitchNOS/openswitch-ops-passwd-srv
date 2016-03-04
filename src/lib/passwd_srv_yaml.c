/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include <yaml.h>

#include "openvswitch/vlog.h"
#include "passwd_srv_pub.h"

VLOG_DEFINE_THIS_MODULE(ops_passwd_srv_yaml);

const char *passwd_srv_yaml_key[PASSWD_SRV_YAML_MAX] =
{
        "values",
        "type",
        "path",
        "description"
};

static passwd_yaml_file_path_t *s_yaml_entry = NULL;

/**
 * Add description of the path
 *
 * @param entry yaml_path node that holds description
 * @param desc  description of path
 * @return PASSWD_ERR_SUCCESS if successfully added description
 */
static
int add_yaml_path_desc(passwd_yaml_file_path_t *entry, const char *desc)
{
    if ((NULL == entry) || (NULL == desc))
    {
        return PASSWD_ERR_FATAL;
    }
    else if (PASSWD_SRV_MAX_STR_SIZE < strlen(desc))
    {
        return PASSWD_ERR_FATAL;
    }

    memcpy(entry->desc, desc, strlen(desc));

    return PASSWD_ERR_SUCCESS;
}

/**
 * Add file path to the yaml entry
 *
 * @param entry yaml_path node that holds file path
 * @param file_path file path
 * @return PASSWD_ERR_SUCCESS if file path is added ok
 */
static
int add_yaml_file_path(passwd_yaml_file_path_t *entry, const char *file_path)
{
    if ((NULL == entry) || (NULL == file_path))
    {
        return PASSWD_ERR_FATAL;
    }
    else if (PASSWD_SRV_MAX_STR_SIZE < strlen(file_path))
    {
        return PASSWD_ERR_FATAL;
    }

    memcpy(entry->path, file_path, strlen(file_path));

    return PASSWD_ERR_SUCCESS;
}

/**
 * Create a yaml entry to hold a file path. The entry is created based on type
 * of the path
 *
 * @param type file path type
 * @return newly created yaml entry or NULL if fail to create one
 */
static
passwd_yaml_file_path_t *add_yaml_entry(enum PASSWD_yaml_path_type_e type)
{
    passwd_yaml_file_path_t *new_entry, *cur_entry;


    if (NULL == (new_entry =
            (passwd_yaml_file_path_t*) calloc(1, sizeof(*new_entry))))
    {
        VLOG_ERR("Failed to alloc memory for new entry");
        return NULL;
    }

    /* initialize new entry */
    new_entry->type = type;
    new_entry->next = NULL;

    /* get head of the list */
    cur_entry = s_yaml_entry;

    if (NULL == s_yaml_entry)
    {
        /**
         * linked-list for yaml entry is empty, make new entry a head
         */
        s_yaml_entry = new_entry;
    }
    else
    {
        /* go to the end of linked-list */
        while(cur_entry->next)
        {
            cur_entry = cur_entry->next;
        }
        cur_entry->next = new_entry;
    }

    return new_entry;
}

/**
 * Find yaml entry based on type
 *
 * @param type yaml-type
 * @return pointer to found entry, NULL if none found
 */
static
passwd_yaml_file_path_t *find_yaml_entry(enum PASSWD_yaml_path_type_e type)
{
    passwd_yaml_file_path_t *cur_entry = s_yaml_entry;

    while(cur_entry)
    {
        if (type == cur_entry->type)
        {
            return cur_entry;
        }

        cur_entry = cur_entry->next;
    }

    return NULL;
}

/**
 * Add path type to the linked-list.  Since path type is the first entry in
 * yaml, adding path type should create a new yaml entry and add path type into
 * the entry.  If entry already exists, it is an error but not critical.  use
 * entry that was found and log it in the system.
 *
 * @param path_type path type
 * @return pointer to newly created entry, NULL if failed to create one
 */
static
passwd_yaml_file_path_t *add_path_type(const char *path_type)
{
    int path_type_len, type_len, type;
    passwd_yaml_file_path_t *new_entry = NULL, *cur_entry = NULL;
    enum PASSWD_yaml_path_type_e new_type = PASSWD_SRV_YAML_PATH_NONE;

    const char *path_types[PASSWD_SRV_YAML_MAX] = {
            "NONE",
            "SOCKET",
            "PUB_KEY"
    };

    if (NULL == path_type)
    {
        /* yaml_entry cannot be NULL */
        return PASSWD_SRV_YAML_PATH_NONE;
    }

    path_type_len = strlen(path_type);

    /* identify correct path type */
    for(type = (int)PASSWD_SRV_YAML_PATH_SOCK; type < PASSWD_SRV_YAML_MAX; type++)
    {
        type_len = strlen(path_types[type]);
        if ((type_len == path_type_len) &&
                (0 == strncmp(path_type, path_types[type], type_len)))
        {
            new_type = (enum PASSWD_yaml_path_type_e)type;
            break;
        }
    }

    if (PASSWD_SRV_YAML_PATH_NONE == new_type)
    {
        /* wrong path type */
        VLOG_WARN("Entry for type %s is not found", path_type);
        return NULL;
    }

    cur_entry = find_yaml_entry(new_type);

    if (NULL == cur_entry)
    {
        /* yaml entry is not found which means it is new */
       new_entry = add_yaml_entry(new_type);
    }
    else
    {
        /*
         * yaml entry is found which is an error. path type is the first entry
         * in yaml file so entry shouldn't exist. Since it is not critical
         * error, log it and return found entry
         */
        VLOG_WARN("Entry for type %s is found", path_type);
        new_entry = cur_entry;
    }

    return new_entry;
}

/**
 * Verify what was parsed and return the key that was parsed
 *
 * @param event
 * @return key description what was parsed
 */
static
enum PASSWD_yaml_key_e check_yaml_event(const char *event)
{
    int type = (int) PASSWD_SRV_YAML_PATH_TYPE;
    int event_len, key_len;

    if (NULL == event)
    {
        return PASSWD_SRV_YAML_MAX;
    }

    event_len = strlen(event);

    for(type = (int) PASSWD_SRV_YAML_PATH_TYPE; type < (int)PASSWD_SRV_YAML_MAX; type++)
    {
        key_len = strlen(passwd_srv_yaml_key[type]);

        if (key_len != event_len)
        {
            continue;
        }

        if (0 == strncmp(event, passwd_srv_yaml_key[type], key_len))
        {
            return (enum PASSWD_yaml_key_e) type;
        }
    }
    return PASSWD_SRV_YAML_VALUE;
}

/**
 * Parse yaml file to store file path
 *
 * @return PASSWD_ERR_SUCCESS if parsed ok
 */
int parse_passwd_srv_yaml()
{
    FILE *fp = NULL;
    yaml_parser_t parser;
    yaml_event_t  event;
    enum PASSWD_yaml_key_e event_value, current_state;
    passwd_yaml_file_path_t *yaml_entry = NULL;

    memset(&parser, 0, sizeof(parser));
    memset(&event, 0, sizeof(event));

    event_value = current_state = PASSWD_SRV_YAML_MAX;

    if(!yaml_parser_initialize(&parser))
    {
        VLOG_ERR("Failed to initialize parser");
        return PASSWD_ERR_FATAL;
    }

    if(NULL == (fp = fopen(PASSWD_SRV_YAML_FILE, "r")))
    {
        VLOG_ERR("Failed to open yaml file");
        yaml_parser_delete(&parser);
        return PASSWD_ERR_YAML_FILE;
    }

    /* setup input yaml file */
    yaml_parser_set_input_file(&parser, fp);

    if (!yaml_parser_parse(&parser, &event))
    {
        VLOG_ERR("Failed to parse yaml file");
        yaml_parser_delete(&parser);
        yaml_event_delete(&event);
        return PASSWD_ERR_FATAL;
    }

    while(YAML_STREAM_END_EVENT != event.type)
    {
        if(YAML_SCALAR_EVENT == event.type)
        {
            event_value = check_yaml_event((const char *)event.data.scalar.value);

            switch(event_value)
            {
            case PASSWD_SRV_YAML_VALUE:
            {
                switch(current_state)
                {
                case PASSWD_SRV_YAML_PATH_TYPE:
                {
                    if (NULL == (yaml_entry =
                            add_path_type((const char *)event.data.scalar.value)))
                    {
                        VLOG_ERR("Cannot add path type to the list");
                        return PASSWD_ERR_FATAL;
                    }

                    break;
                }
                case PASSWD_SRV_YAML_PATH:
                {
                    if (NULL == yaml_entry)
                    {
                        /* yaml_entry must not be null at this point */
                        VLOG_ERR("Cannot add file path to the list");
                        return PASSWD_ERR_FATAL;
                    }
                    if (PASSWD_ERR_SUCCESS !=
                            add_yaml_file_path(yaml_entry,
                                    (const char *)event.data.scalar.value))
                    {
                        /* yaml_entry must not be null at this point */
                        VLOG_ERR("Cannot add path to the yaml entry");
                        return PASSWD_ERR_FATAL;
                    }
                    break;
                }
                case PASSWD_SRV_YAML_DESC:
                {
                    if (NULL == yaml_entry)
                    {
                        /* yaml_entry must not be null at this point */
                        VLOG_ERR("Cannot add file path to the list");
                        return PASSWD_ERR_FATAL;
                    }
                    if (PASSWD_ERR_SUCCESS !=
                            add_yaml_path_desc(yaml_entry,
                                    (const char *)event.data.scalar.value))
                    {
                        /* yaml_entry must not be null at this point */
                        VLOG_ERR("Cannot add desc to the yaml entry");
                        return PASSWD_ERR_FATAL;
                    }
                    break;
                }
                default:
                {
                    break;
                }
                }
                break;
            }
            case PASSWD_SRV_YAML_PATH_TYPE:
            case PASSWD_SRV_YAML_PATH:
            case PASSWD_SRV_YAML_DESC:
            {
                current_state = event_value;
                break;
            }
            default:
                break;
            }
        } /* if(YAML_SCALAR_EVENT == event.type) */

        if (YAML_STREAM_END_EVENT != event.type)
        {
            yaml_event_delete(&event);
        }
        if (!yaml_parser_parse(&parser, &event))
        {
            VLOG_ERR("Parser error %d\n", parser.error);
            yaml_parser_delete(&parser);
            yaml_event_delete(&event);
            fclose(fp);
            return PASSWD_ERR_FATAL;
        }
    } /* while */

    /* clean up before exit */
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fp);

    return PASSWD_ERR_SUCCESS;
}

/**
 * Get string (file path) from the list based on the file path type
 *
 * @param type file path type
 * @return file path if found one, null otherwisse
 */
char *get_file_path(enum PASSWD_yaml_path_type_e type)
{
    passwd_yaml_file_path_t *cur_entry = s_yaml_entry;

    while(cur_entry)
    {
        if (type == cur_entry->type)
        {
            return cur_entry->path;
        }
        cur_entry = cur_entry->next;
    }

    return NULL;
}

/**
 * Wrapper to return socket file descriptor path
 */
char *get_socket_descriptor_path()
{
    return get_file_path(PASSWD_SRV_YAML_PATH_SOCK);
}

/**
 * Wrapper to return public key path
 */
char *get_public_key_path()
{
    return get_file_path(PASSWD_SRV_YAML_PATH_PUB_KEY);
}

/**
 * Remove all yaml entries previously parsed from the yaml file
 */
int uninit_yaml_parser()
{
    passwd_yaml_file_path_t *cur_entry = s_yaml_entry;
    passwd_yaml_file_path_t *temp = NULL;

    if (NULL == cur_entry)
    {
        /* entry is empty, nothing to uninit */
        return PASSWD_ERR_SUCCESS;
    }

    while(cur_entry->next)
    {
        temp = cur_entry;
        cur_entry = cur_entry->next;

        memset(temp, 0, sizeof(*temp));
        free(temp);
    }

    memset(cur_entry, 0, sizeof(*cur_entry));
    free(cur_entry);

    s_yaml_entry = NULL;

    return PASSWD_ERR_SUCCESS;
}

/**
 * Call parser API to initialize yaml structure used to get file path
 *
 * @return PASSWD_ERR_SUCCESS if successfully parsed and added entries
 */
int init_yaml_parser()
{
    return parse_passwd_srv_yaml();
}
