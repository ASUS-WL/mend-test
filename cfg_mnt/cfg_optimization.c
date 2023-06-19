#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <amas_path.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_slavelist.h"
#include "cfg_capability.h"
#include "cfg_optimization.h"
// 23_0223 fix prefer

struct Node
{
    float opt_cost, now_cost;
    // this node's info
    char *unique_mac, *ap2g, *ap5g, *ap5g1, *ap6g;
    // this node pap mac from cfg table
    char *pap2g, *pap5g, *pap6g;
    // this node pap rssi from cfg table
    int pap_rssi2g, pap_rssi5g, pap_rssi6g;
    // is linked in opt topology or not
    int opt_linked, now_linked;
    // has prefer pap or not
    int has_prefer;
    // to store nodes seen in this node's site survey report
    struct Seen_node_list *seen_node_list;
    // to store nodes might be pap
    struct Seen_node_list *now_pap_list;
    // to store this node's child nodes in topology of opt and now
    struct Node_list *opt_childs, *now_childs;
    // pap node in opt
    struct Seen_node *opt_parent, *now_parent;
};

struct Seen_node
{
    // seen node is a node that this node can see in side survey
    // with bssid, rssi, antenna_num, bandwidth, prefer
    char *bssid;
    // band == 1 means eth
    int rssi, antenna_num, bandwidth, prefer, band;
    // link to target of this seen node
    struct Node *target_node;
    float cost;
};

struct Node_list
{
    // a list of node
    int capacity, size;
    struct Node **node;
};

struct Seen_node_list
{
    // a list of seen node
    int capacity, size;
    struct Seen_node **seen_node;
};

int get_cfg_table();
int parse_wifi_info_json(json_object *wifi_info_json, struct Node_list *node_list);
int parse_eth_info_json(json_object *wifi_info_json, struct Node_list *node_list);
int parse_cfg_table(P_CM_CLIENT_TABLE cfgTbl, struct Node_list *node_list);

int minimum_spanning_tree_opt(struct Node_list *node_list);
int minimum_spanning_tree_now(struct Node_list *node_list);
void print_tree(struct Node *node);
json_object *print_tree_to_jso_from_cap(struct Node *cap);
void print_tree_to_jso_re(struct Node *node, json_object *result_jso, int *sequence, int pap_changed);
float rssi_score(struct Seen_node *seen_node);
float calculate_cost_by_rssi(float rssi_score, int rssi);
void print_node_list(struct Node_list *node_list);
void print_seen_node_list(struct Seen_node_list *seen_node_list);
struct Node *new_node(char *node_unique_mac);
struct Seen_node *new_seen_node(const char *bssid, int rssi, int antenna_num, int bandwidth, int prefer, int band);

struct Node_list *new_node_list();
int node_list_add(struct Node_list *list, struct Node *new_node);
struct Seen_node_list *new_seen_node_list();
int seen_node_list_add(struct Seen_node_list *list, struct Seen_node *new_seen_node);

void free_node(struct Node *node);
void free_node_list(struct Node_list *node_list);
void free_seen_node(struct Seen_node *seen_node);
void free_seen_node_list(struct Seen_node_list *seen_node_list);

struct Node *find_node_by_bssid(char *target_macaddr, struct Node_list *node_list);
struct Node *find_node_by_unique_mac(char *target_macaddr, struct Node_list *node_list);

/*
========================================================================
Routine Description:
    Check all RE support central optimization or not.

Arguments:
    cfgTbl  - client table

Return Value:
    -1		- error
    0		- not support
    1		- support

========================================================================
*/
int cm_isAllReSupportCentralOpt(CM_CLIENT_TABLE *cfgTbl)
{
    int i = 0, ret = 1;
    char mac[18];

    for (i = 1; i < cfgTbl->count; i++)
    {
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->realMacAddr[i][0], cfgTbl->realMacAddr[i][1],
                 cfgTbl->realMacAddr[i][2], cfgTbl->realMacAddr[i][3],
                 cfgTbl->realMacAddr[i][4], cfgTbl->realMacAddr[i][5]);

        if (cm_isCapSupported(mac, RC_SUPPORT, CENTRAL_OPTMZ) != 1)
        {
            DBG_LOG("RE (%s) doesn't support central optimization", mac);
            ret = 0;
            break;
        }
    }

    return ret;
} /* End of cm_isAllReSupportCentralOpt */

/*
========================================================================
Routine Description:
    Update the follow rule of optimization.

Arguments:
    cfgTbl		- client table
    mac		- RE's mac

Return Value:
    None

========================================================================
*/
void cm_updateOptFollowRule(CM_CLIENT_TABLE *cfgTbl, char *mac)
{
    if (mac)
    {
        if (cm_isCapSupported(mac, RC_SUPPORT, CENTRAL_OPTMZ) != 1)
        {
            DBG_LOG("RE (%s) doesn't support central optimization, follow old", mac);
            if (nvram_get_int("cfg_opt_follow") != OPT_FOLLOW_OLD)
                nvram_set_int("cfg_opt_follow", OPT_FOLLOW_OLD);
        }
        else if (cm_isAllReSupportCentralOpt(cfgTbl))
        {
            DBG_LOG("all RE support central optimization, follow new");
            if (nvram_get_int("cfg_opt_follow") != OPT_FOLLOW_NEW)
                nvram_set_int("cfg_opt_follow", OPT_FOLLOW_NEW);
        }
    }
    else
    {
        if (cm_isAllReSupportCentralOpt(cfgTbl))
        {
            DBG_LOG("all RE support central optimization, follow new");
            if (nvram_get_int("cfg_opt_follow") != OPT_FOLLOW_NEW)
                nvram_set_int("cfg_opt_follow", OPT_FOLLOW_NEW);
        }
        else
        {
            DBG_LOG("any RE doesn't support central optimization, follow old");
            if (nvram_get_int("cfg_opt_follow") != OPT_FOLLOW_OLD)
                nvram_set_int("cfg_opt_follow", OPT_FOLLOW_OLD);
        }
    }
} /* End of cm_updateOptFollowRule */

/*
========================================================================
Routine Description:
    Get the band index by band and use

Arguments:
    mac		- RE's mac
    band		- band for compare

Return Value:
    bnad index

Note:
========================================================================
*/
int cm_getIndexByBandUse(char *mac, int band)
{
    int index = -1;
    json_object *fileRoot = NULL, *bandObj = NULL, *useObj = NULL, *indexObj = NULL;
    char filePath[64] = {0};

    snprintf(filePath, sizeof(filePath), "%s/%s.wlc", TEMP_ROOT_PATH, mac);

    if ((fileRoot = json_object_from_file(filePath)))
    {
        json_object_object_foreach(fileRoot, key, val)
        {
            json_object_object_get_ex(val, CFG_STR_BAND, &bandObj);
            /* check band */
            if (bandObj && json_object_get_int(bandObj) == band)
            {
                json_object_object_get_ex(val, CFG_STR_USE, &useObj);
                /* check use */
                if (useObj && json_object_get_int(useObj) == 1)
                {
                    json_object_object_get_ex(val, CFG_STR_INDEX, &indexObj);
                    if (indexObj)
                    {
                        index = json_object_get_int(indexObj);
                        break;
                    }
                }
            }
        }
    }

    json_object_put(fileRoot);

    return index;
} /* End of cm_getIndexByBandUse */

/*
========================================================================
Routine Description:
    Update rssi info by ap's bssid

Arguments:
    mac		- RE's mac
    bssid   	- ap's bssid
    bandIndex       - band index
    rssi        - rssi

Return Value:
    0       - no update
    1       - update

Note:
========================================================================
*/
int cm_updateRssiInfoByBssid(char *mac, char *bssid, char *bandIndex, int rssi)
{
    json_object *fileRoot = NULL, *macObj = NULL, *bandIndexObj = NULL;
    json_object *rssiObj = NULL, *newRssiObj = NULL, *rssiEntry = NULL;
    int update = 0, rssiArrayLength = 0, i = 0;
    int rssiCumMaxTimes = nvram_get_int("cfg_rcmt") ?: RSSI_CUMULATIVE_MAX_TIMES;

    pthread_mutex_lock(&rssiInfoLock);

    if ((fileRoot = json_object_from_file(RSSI_INFO_FILE_PATH)) == NULL)
    {
        if ((fileRoot = json_object_new_object()) == NULL)
        {
            DBG_ERR("fileRoot is NULL");
            goto cm_updateRssiInfoByBssid_exit;
        }
    }

    /* {"20:CF:30:00:AA:08":{"2":{"20:CF:30:00:AA:08":[-19]}}} */
    json_object_object_get_ex(fileRoot, mac, &macObj);
    if (macObj)
    {
        json_object_object_get_ex(macObj, bandIndex, &bandIndexObj);
        if (bandIndexObj)
        {
            json_object_object_get_ex(bandIndexObj, bssid, &rssiObj);
            if (rssiObj)
            {
                rssiArrayLength = json_object_array_length(rssiObj);
                if (rssiArrayLength < rssiCumMaxTimes)
                {
                    json_object_array_add(rssiObj, json_object_new_int(rssi));
                    update = 1;
                }
                else
                {
                    if ((newRssiObj = json_object_new_array()))
                    {
                        for (i = 1; i < rssiArrayLength; i++)
                        {
                            rssiEntry = json_object_array_get_idx(rssiObj, i);
                            json_object_array_add(newRssiObj, json_object_new_int(json_object_get_int(rssiEntry)));
                        }

                        json_object_array_add(newRssiObj, json_object_new_int(rssi));
                        json_object_object_del(bandIndexObj, bssid);
                        json_object_object_add(bandIndexObj, bssid, newRssiObj);
                        update = 1;
                    }
                }
            }
            else
            {
                if ((rssiObj = json_object_new_array()))
                {
                    json_object_array_add(rssiObj, json_object_new_int(rssi));
                    json_object_object_add(bandIndexObj, bssid, rssiObj);
                    update = 1;
                }
            }
        }
        else
        {
            if ((bandIndexObj = json_object_new_object()))
            {
                if ((rssiObj = json_object_new_array()))
                {
                    json_object_array_add(rssiObj, json_object_new_int(rssi));
                    json_object_object_add(bandIndexObj, bssid, rssiObj);
                    json_object_object_add(macObj, bandIndex, bandIndexObj);
                    update = 1;
                }
                else
                {
                    json_object_put(bandIndexObj);
                }
            }
        }
    }
    else
    {
        if ((macObj = json_object_new_object()))
        {
            if ((bandIndexObj = json_object_new_object()))
            {
                if ((rssiObj = json_object_new_array()))
                {
                    json_object_array_add(rssiObj, json_object_new_int(rssi));
                    json_object_object_add(bandIndexObj, bssid, rssiObj);
                    json_object_object_add(macObj, bandIndex, bandIndexObj);
                    json_object_object_add(fileRoot, mac, macObj);
                    update = 1;
                }
                else
                {
                    json_object_put(macObj);
                    json_object_put(bandIndexObj);
                }
            }
            else
            {
                json_object_put(macObj);
            }
        }
    }

    if (update)
        json_object_to_file(RSSI_INFO_FILE_PATH, fileRoot);

cm_updateRssiInfoByBssid_exit:

    json_object_put(fileRoot);
    pthread_mutex_unlock(&rssiInfoLock);

    return update;
} /* End of cm_updateRssiInfoByBssid */

/*
========================================================================
Routine Description:
    Compute average rssi by ap's bssid

Arguments:
    mac		- RE's mac
    bssid   	- ap's bssid
    bandIndex       - band index

Return Value:
    average rssi

Note:
========================================================================
*/
int cm_computeAverageRssiByBssid(char *mac, char *bssid, char *bandIndex)
{
    json_object *fileRoot = NULL, *macObj = NULL, *bandIndexObj = NULL, *rssiObj = NULL, *rssiEntry = NULL;
    int sumRssi = 0, avgRssi = 0, rssiArrayLength = 0, i = 0;

    pthread_mutex_lock(&rssiInfoLock);

    if ((fileRoot = json_object_from_file(RSSI_INFO_FILE_PATH)) == NULL)
    {
        DBG_ERR("fileRoot is NULL");
        goto cm_computeAverageRssiByBssid_exit;
    }

    /* {"20:CF:30:00:AA:08":{"2":{"20:CF:30:00:AA:08":[-19]}}} */
    json_object_object_get_ex(fileRoot, mac, &macObj);
    if (macObj)
    {
        json_object_object_get_ex(macObj, bandIndex, &bandIndexObj);
        if (bandIndexObj)
        {
            json_object_object_get_ex(bandIndexObj, bssid, &rssiObj);
            if (rssiObj)
            {
                rssiArrayLength = json_object_array_length(rssiObj);
                for (i = 0; i < rssiArrayLength; i++)
                {
                    rssiEntry = json_object_array_get_idx(rssiObj, i);
                    sumRssi += json_object_get_int(rssiEntry);
                }

                if (sumRssi < 0 && rssiArrayLength > 0)
                {
                    avgRssi = sumRssi / rssiArrayLength;
                    if (nvram_get("cfg_opt_dbg"))
                    {
                        DBG_LOG("bssid(%s) sumRssi(%d) rssiArrayLength(%d) avgRssi(%d)\n",
                                bssid, sumRssi, rssiArrayLength, avgRssi);
                    }
                }
            }
        }
    }

cm_computeAverageRssiByBssid_exit:

    json_object_put(fileRoot);
    pthread_mutex_unlock(&rssiInfoLock);

    return avgRssi;
} /* End of cm_computeAverageRssiByBssid */

/*
========================================================================
Routine Description:
    Get connection information that RE is under ethenet backhaul.

Arguments:
    cfgTbl		- client table

Return Value:
    connection info that RE is under ethernet backhaul

========================================================================
*/
json_object *cm_getEthConnInfo(CM_CLIENT_TABLE *cfgTbl)
{
    int i = 0, c = 0, r = 0, ebrLen = 0, reLen = 0;
    int wiredPath = ETH | ETH_2 | ETH_3 | ETH_4;
    char mac[18];
    json_object *listObj = NULL, *reObj = NULL, *eciObj = NULL, *ebrObj = NULL, *ebrEntryObj = NULL;
    json_object *reEntryObj = NULL, *eciEntry = NULL;

    if ((ebrObj = json_object_new_array()) && (listObj = json_object_from_file(MAC_LIST_JSON_FILE)))
    {
        if ((eciObj = json_object_new_object()))
        {
            /* record which RE is under ethernet backhaul */
            for (i = 1; i < cfgTbl->count; i++)
            {
                if (cfgTbl->activePath[i] & wiredPath)
                {
                    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                             cfgTbl->realMacAddr[i][0], cfgTbl->realMacAddr[i][1],
                             cfgTbl->realMacAddr[i][2], cfgTbl->realMacAddr[i][3],
                             cfgTbl->realMacAddr[i][4], cfgTbl->realMacAddr[i][5]);

                    json_object_array_add(ebrObj, json_object_new_string(mac));
                }
            }

            /* check RE connect to which based on ebrObj */
            ebrLen = json_object_array_length(ebrObj);
            for (c = 0; c < ebrLen; c++)
            {
                if ((ebrEntryObj = json_object_array_get_idx(ebrObj, c)))
                {
                    for (i = cfgTbl->count; i >= 0; i--)
                    {
                        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 cfgTbl->realMacAddr[i][0], cfgTbl->realMacAddr[i][1],
                                 cfgTbl->realMacAddr[i][2], cfgTbl->realMacAddr[i][3],
                                 cfgTbl->realMacAddr[i][4], cfgTbl->realMacAddr[i][5]);

                        json_object_object_get_ex(listObj, mac, &reObj);
                        if (reObj)
                        {
                            reLen = json_object_array_length(reObj);
                            for (r = 0; r < reLen; r++)
                            {
                                if ((reEntryObj = json_object_array_get_idx(reObj, r)))
                                {
                                    if (strcmp(json_object_get_string(reEntryObj),
                                               json_object_get_string(ebrEntryObj)) == 0)
                                    {
                                        if ((eciEntry = json_object_new_object()))
                                        {
                                            json_object_object_add(eciEntry, CFG_STR_PARENT_RE, json_object_new_string(mac));
                                            json_object_object_add(eciObj, json_object_get_string(ebrEntryObj), eciEntry);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    json_object_put(ebrObj);
    json_object_put(listObj);

    return eciObj;
} /* End of cm_getEthConnInfo */

/*
========================================================================
Routine Description:
    Compute best topology and get connection information for optimization.

Arguments:
    cfgTbl  - client table
    ssrTbl  - table for site survey result
    eciTbl	- table for ethenet connection information

Return Value:
    RE connection information for optimization

========================================================================
*/
// main function
json_object *cm_getOptConnectionInfo(CM_CLIENT_TABLE *cfgTbl, json_object *ssrTbl, json_object *eciTbl)
{
    json_object *result_json = NULL;
    // convert json to node list
    struct Node_list *node_list;
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("Start of optimization");

    node_list = new_node_list();
    if (node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("cm_getOptConnectionInfo(): new_node_list alloc failed");
        }
        free_node_list(node_list);
        return NULL;
    }

    if (cfgTbl)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("parse_cfg_table()");
        if (parse_cfg_table(cfgTbl, node_list))
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("parse_cfg_table() failed");
            }
            free_node_list(node_list);
            return NULL;
        }
    }
    else
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("Can't find CM_CLIENT_TABLE");
        }
        free_node_list(node_list);
        return NULL;
    }

    if (ssrTbl)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("parse_wifi_info_json()");
        if (parse_wifi_info_json(ssrTbl, node_list))
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("parse_wifi_info_json() failed");
            }
            free_node_list(node_list);
            return NULL;
        }
    }
    // if ssrTbl is empty, return null for no need to change
    else
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("Can't find ssrTbl");
        }
        free_node_list(node_list);
        return NULL;
    }

    if (eciTbl)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("parse_eth_info_json()");
        if (parse_eth_info_json(eciTbl, node_list))
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("parse_eth_info_json() failed");
            }
            free_node_list(node_list);
            return NULL;
        }
    }

    // link all interface of seen_node to the node it self
    for (int i = 0; i < node_list->size; i++)
    {
        for (int j = 0; j < node_list->node[i]->seen_node_list->size; j++)
        {
            node_list->node[i]->seen_node_list->seen_node[j]->target_node = find_node_by_bssid(node_list->node[i]->seen_node_list->seen_node[j]->bssid, node_list);

            // if can't find correspond node
            if (node_list->node[i]->seen_node_list->seen_node[j]->target_node == NULL)
            {
                // temperally ignore the node in minimun spanning tree
                node_list->node[i]->seen_node_list->seen_node[j]->rssi = 12345678;
                node_list->node[i]->seen_node_list->seen_node[j]->target_node = node_list->node[0];
            }
        }
        // also link now pap list
        for (int j = 0; j < node_list->node[i]->now_pap_list->size; j++)
        {
            node_list->node[i]->now_pap_list->seen_node[j]->target_node = find_node_by_bssid(node_list->node[i]->now_pap_list->seen_node[j]->bssid, node_list);

            // if can't find correspond node
            if (node_list->node[i]->now_pap_list->seen_node[j]->target_node == NULL)
            {
                // temperally ignore the node in minimun spanning tree
                node_list->node[i]->now_pap_list->seen_node[j]->rssi = 12345678;
                node_list->node[i]->now_pap_list->seen_node[j]->target_node = node_list->node[0];
            }
        }
    }

    // construct the topology using now
    // also calculate cost
    int result_of_opt_minimun_spaning_tree, result_of_now_minimun_spaning_tree;

    // minimun_spaning_tree will return the number of node that not in topology tree
    // if return 0 means all node joined the tree successfully

    result_of_now_minimun_spaning_tree = minimum_spanning_tree_now(node_list);
    result_of_opt_minimun_spaning_tree = minimum_spanning_tree_opt(node_list);

    if (result_of_now_minimun_spaning_tree != 0)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("Now Topology has missing nodes: %d", result_of_opt_minimun_spaning_tree);
        }
    }
    // the case of topology tree not included all node
    if (result_of_opt_minimun_spaning_tree != 0)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("OPT Topology has missing nodes: %d", result_of_opt_minimun_spaning_tree);
        }
    }

    if (nvram_get("cfg_opt_dbg"))
    {
        DBG_LOG("Node not in spanning tree, now: %d, opt: %d", result_of_now_minimun_spaning_tree, result_of_opt_minimun_spaning_tree);
    }

    // check if any node is using now but not in opt topology
    int opt_has_missing_node = 0;
    for (int i = 1; i < node_list->size; i++)
    {
        if (node_list->node[i]->now_parent != NULL && node_list->node[i]->opt_parent == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("%s is in now topology, but isn't in opt topology!", node_list->node[i]->unique_mac);
            }
            opt_has_missing_node = 1;
        }
    }
    if (opt_has_missing_node)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("opt topology has missing node, skip optimize this time.");
        }
        free_node_list(node_list);
        return NULL;
    }

    if (nvram_get("cfg_opt_dbg"))
    {
        DBG_LOG("print_node_list: ");
        print_node_list(node_list);
    }

    // out put topology to json
    // if any node opt cost is better than now cost more than 20%, all node should turn to new topology
    // if not, skip topology optimize this time
    int topology_should_change = 0;
    for (int i = 0; i < node_list->size; i++)
    {
        if ((float)node_list->node[i]->opt_cost < (float)node_list->node[i]->now_cost * 0.8)
        {
            topology_should_change = 1;
            break;
        }
    }

    if (topology_should_change)
        result_json = print_tree_to_jso_from_cap(node_list->node[0]);
    else
        result_json = json_object_new_object();

    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("result_json: %s", json_object_to_json_string(result_json));

    free_node_list(node_list);

    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("End of optimization");

    return result_json;
} /* End of cm_getOptConnectionInfo */

int parse_wifi_info_json(json_object *wifi_info_json, struct Node_list *node_list)
{
    struct Node *tmp_node;
    struct Seen_node *tmp_seen_node, *tmp_now_pap;
    json_object *rssiObj = NULL, *antenna_numObj = NULL, *bandwidthObj = NULL, *preferObj = NULL, *bandObj = NULL;
    int rssi = 0, antenna_num = 0, bandwidth = 0, prefer = 0, band = 0;
    // node wifi scan
    // json level 1: RE scan
    json_object_object_foreach(wifi_info_json, node_unique_mac, seen_node_info_json)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("%s : Json Data recieved:", node_unique_mac);
            DBG_LOG(" %s", json_object_get_string(seen_node_info_json));
        }
        tmp_node = find_node_by_bssid(node_unique_mac, node_list);
        if (tmp_node == NULL)
        {
            tmp_node = new_node(node_unique_mac);
            if (tmp_node == NULL)
            {
                if (nvram_get("cfg_opt_dbg"))
                    DBG_LOG("parse_wifi_info_json() new_node alloc failed");
                return -1;
            }
            node_list_add(node_list, tmp_node);
        }

        // level 2: the info of the node seen by RE
        json_object_object_foreach(seen_node_info_json, seen_node_bssi, seen_node_elements_info_json)
        {
            // level 3: get elements info jso inside seen_node_info_json

            json_object_object_get_ex(seen_node_elements_info_json, "rssi", &rssiObj);
            json_object_object_get_ex(seen_node_elements_info_json, "antenna_num", &antenna_numObj);
            json_object_object_get_ex(seen_node_elements_info_json, "bandwidth", &bandwidthObj);
            json_object_object_get_ex(seen_node_elements_info_json, "prefer", &preferObj);
            json_object_object_get_ex(seen_node_elements_info_json, "band", &bandObj);

            rssi = -999;
            antenna_num = 0;
            bandwidth = 0;
            prefer = 0;
            band = 0;
            if (rssiObj)
                rssi = json_object_get_int(rssiObj);
            if (antenna_numObj)
                antenna_num = json_object_get_int(antenna_numObj);
            if (bandwidthObj)
                bandwidth = json_object_get_int(bandwidthObj);
            if (preferObj)
                prefer = json_object_get_int(preferObj);
            if (bandObj)
                band = json_object_get_int(bandObj);

            tmp_seen_node = new_seen_node(seen_node_bssi, rssi, antenna_num, bandwidth, prefer, band);
            if (tmp_seen_node == NULL)
            {
                if (nvram_get("cfg_opt_dbg"))
                    DBG_LOG("parse_wifi_info_json() new_seen_node alloc failed");
                return -1;
            }
            // add to seen node list
            if (seen_node_list_add(tmp_node->seen_node_list, tmp_seen_node) == -1)
            {
                if (nvram_get("cfg_opt_dbg"))
                    DBG_LOG("seen_node_list_add() add seen node list failed");
                return -1;
            }
            // record this node has a prefer pap
            if (prefer == 1)
            {
                tmp_node->has_prefer = 1;
            }
            // update now cost to new one(the latest site survey report),
            // if seen node is a pap of this node
            for (int i = 0; i < tmp_node->now_pap_list->size; i++)
            {
                tmp_now_pap = tmp_node->now_pap_list->seen_node[i];
                if (strcmp(tmp_seen_node->bssid, tmp_now_pap->bssid) == 0)
                {
                    tmp_now_pap->rssi = tmp_seen_node->rssi;
                    tmp_now_pap->cost = tmp_seen_node->cost;

                    tmp_now_pap->prefer = tmp_seen_node->prefer;
                }
            }
        }
    }
    return 0;
}

int parse_eth_info_json(json_object *eth_info_json, struct Node_list *node_list)
{
    struct Node *tmp_node;
    struct Seen_node *tmp_seen_node;
    json_object *eth_parentObj = NULL;
    char *eth_parent;
    // ether
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("parse_eth_info_json() data received: %s", json_object_get_string(eth_info_json));
    json_object_object_foreach(eth_info_json, eth_node_unique_mac, eth_perant_info)
    {

        tmp_node = find_node_by_unique_mac(eth_node_unique_mac, node_list);
        // if the node is not created
        if (tmp_node == NULL)
        {
            tmp_node = new_node(eth_node_unique_mac);
            if (tmp_node == NULL)
            {
                if (nvram_get("cfg_opt_dbg"))
                    DBG_LOG("parse_eth_info_json() new_node alloc failed");
                return -1;
            }
            node_list_add(node_list, tmp_node);
        }

        json_object_object_get_ex(eth_perant_info, "pre", &eth_parentObj);
        eth_parent = NULL;

        if (eth_parentObj == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("parse_eth_info_json() json_object_object_get_ex failed");
            return -1;
        }
        eth_parent = (char *)json_object_get_string(eth_parentObj);

        // using eth as backhaul, so set a very good number
        // rssi = 0, antenna_num = 10, bandwidth = 1000, prefer = 0;

        // TODO: add eth linkrate
        tmp_seen_node = new_seen_node(eth_parent, 0, 10, 1000, 1, 0);
        if (tmp_seen_node == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("parse_eth_info_json() tmp_seen_node alloc failed");
            return -1;
        }
        // add eth pap to seen_node_list and now_pap_list
        seen_node_list_add(tmp_node->seen_node_list, tmp_seen_node);

        tmp_seen_node = new_seen_node(eth_parent, 0, 10, 1000, 1, 0);
        if (tmp_seen_node == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("parse_eth_info_json() tmp_seen_node alloc failed");
            return -1;
        }
        seen_node_list_add(tmp_node->now_pap_list, tmp_seen_node);
    }
    return 0;
}

int parse_cfg_table(P_CM_CLIENT_TABLE cfgTbl, struct Node_list *node_list)
{
    // start of cfg table
    // read cfg table info to node list
    char realMacAddr_buf[32];
    char ap2g_buf[32], ap5g_buf[32], ap5g1_buf[32], ap6g_buf[32];
    char pap2g_buf[32], pap5g_buf[32], pap6g_buf[32];
    struct Node *tmp_node;
    struct Seen_node *tmp_seen_node;

    for (int i = 0; i < cfgTbl->count; i++)
    {
        // get node unique mac
        memset(realMacAddr_buf, 0, sizeof(realMacAddr_buf));
        snprintf(realMacAddr_buf, sizeof(realMacAddr_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->realMacAddr[i][0], cfgTbl->realMacAddr[i][1],
                 cfgTbl->realMacAddr[i][2], cfgTbl->realMacAddr[i][3],
                 cfgTbl->realMacAddr[i][4], cfgTbl->realMacAddr[i][5]);

        // try to find the node by unique mac
        tmp_node = find_node_by_bssid(realMacAddr_buf, node_list);

        // if can't find the node with mac, add to node list
        if (tmp_node == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("Can't find '%s' in node list, add to node list", realMacAddr_buf);
            }
            tmp_node = new_node(realMacAddr_buf);
            if (tmp_node == NULL)
            {
                if (nvram_get("cfg_opt_dbg"))
                    DBG_LOG("parse_cfg_table() tmp_node alloc failed");
                return -1;
            }
            node_list_add(node_list, tmp_node);
        }

        // first node is CAP
        if (i == 0)
        {
            // set CAP as is linked
            tmp_node->opt_linked = 1;
            tmp_node->now_linked = 1;
            tmp_node->opt_cost = 0;
            tmp_node->now_cost = 0;
        }
        else
        {
            // init non cap node cost to a huge number
            tmp_node->opt_cost = 9999;
            tmp_node->now_cost = 9999;
        }

        memset(ap2g_buf, 0, sizeof(ap2g_buf));
        memset(ap5g_buf, 0, sizeof(ap5g_buf));
        memset(ap5g1_buf, 0, sizeof(ap5g1_buf));
        memset(ap6g_buf, 0, sizeof(ap6g_buf));
        memset(pap2g_buf, 0, sizeof(pap2g_buf));
        memset(pap5g_buf, 0, sizeof(pap5g_buf));
        memset(pap6g_buf, 0, sizeof(pap6g_buf));

        // if find the node, import the info of that node to node list
        snprintf(ap2g_buf, sizeof(ap2g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->ap2g[i][0], cfgTbl->ap2g[i][1],
                 cfgTbl->ap2g[i][2], cfgTbl->ap2g[i][3],
                 cfgTbl->ap2g[i][4], cfgTbl->ap2g[i][5]);

        snprintf(ap5g_buf, sizeof(ap5g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->ap5g[i][0], cfgTbl->ap5g[i][1],
                 cfgTbl->ap5g[i][2], cfgTbl->ap5g[i][3],
                 cfgTbl->ap5g[i][4], cfgTbl->ap5g[i][5]);

        snprintf(ap5g1_buf, sizeof(ap5g1_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->ap5g1[i][0], cfgTbl->ap5g1[i][1],
                 cfgTbl->ap5g1[i][2], cfgTbl->ap5g1[i][3],
                 cfgTbl->ap5g1[i][4], cfgTbl->ap5g1[i][5]);

        snprintf(ap6g_buf, sizeof(ap6g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->ap6g[i][0], cfgTbl->ap6g[i][1],
                 cfgTbl->ap6g[i][2], cfgTbl->ap6g[i][3],
                 cfgTbl->ap6g[i][4], cfgTbl->ap6g[i][5]);

        snprintf(pap2g_buf, sizeof(pap2g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->pap2g[i][0], cfgTbl->pap2g[i][1],
                 cfgTbl->pap2g[i][2], cfgTbl->pap2g[i][3],
                 cfgTbl->pap2g[i][4], cfgTbl->pap2g[i][5]);

        snprintf(pap5g_buf, sizeof(pap5g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->pap5g[i][0], cfgTbl->pap5g[i][1],
                 cfgTbl->pap5g[i][2], cfgTbl->pap5g[i][3],
                 cfgTbl->pap5g[i][4], cfgTbl->pap5g[i][5]);

        snprintf(pap6g_buf, sizeof(pap6g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfgTbl->pap6g[i][0], cfgTbl->pap6g[i][1],
                 cfgTbl->pap6g[i][2], cfgTbl->pap6g[i][3],
                 cfgTbl->pap6g[i][4], cfgTbl->pap6g[i][5]);

        strcpy(tmp_node->ap2g, (strcmp(ap2g_buf, "00:00:00:00:00:00") ? ap2g_buf : "None"));
        strcpy(tmp_node->ap5g, (strcmp(ap5g_buf, "00:00:00:00:00:00") ? ap5g_buf : "None"));
        strcpy(tmp_node->ap5g1, (strcmp(ap5g1_buf, "00:00:00:00:00:00") ? ap5g1_buf : "None"));
        strcpy(tmp_node->ap6g, (strcmp(ap6g_buf, "00:00:00:00:00:00") ? ap6g_buf : "None"));
        strcpy(tmp_node->pap2g, (strcmp(pap2g_buf, "00:00:00:00:00:00") ? pap2g_buf : "None"));
        strcpy(tmp_node->pap5g, (strcmp(pap5g_buf, "00:00:00:00:00:00") ? pap5g_buf : "None"));
        strcpy(tmp_node->pap6g, (strcmp(pap6g_buf, "00:00:00:00:00:00") ? pap6g_buf : "None"));

        // rssi of RE to pap from cfgtable
        // add all pap to node's pap seen node list
        // if pap2g is not empty
        if (strcmp(tmp_node->pap2g, "None"))
        {
            tmp_seen_node = new_seen_node(tmp_node->pap2g, cfgTbl->rssi2g[i], 4, 20, 0, 2);
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("node: %s, pap2g: %s", tmp_node->unique_mac, tmp_node->pap2g);
            seen_node_list_add(tmp_node->now_pap_list, tmp_seen_node);
        }
        // 5g
        if (strcmp(tmp_node->pap5g, "None"))
        {
            tmp_seen_node = new_seen_node(tmp_node->pap5g, cfgTbl->rssi5g[i], 4, 80, 0, 5);
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("node: %s, pap5g: %s", tmp_node->unique_mac, tmp_node->pap5g);
            seen_node_list_add(tmp_node->now_pap_list, tmp_seen_node);
        }
        // 6g
        if (strcmp(tmp_node->pap6g, "None"))
        {
            tmp_seen_node = new_seen_node(tmp_node->pap6g, cfgTbl->rssi6g[i], 4, 160, 0, 6);
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("node: %s, pap6g: %s", tmp_node->unique_mac, tmp_node->pap6g);
            seen_node_list_add(tmp_node->now_pap_list, tmp_seen_node);
        }
    }
    // end of cfg table
    return 0;
}

struct Node *new_node(char *node_unique_mac)
{
    if (node_unique_mac == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node: node_unique_mac is NULL ptr");
        return NULL;
    }

    struct Node *node = calloc(1, sizeof(struct Node));
    if (node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node: calloc memory alloc failed");
        return NULL;
    }

    node->seen_node_list = new_seen_node_list();
    if (node->seen_node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node(): new_seen_node_list() alloc failed");
        free(node);
        return NULL;
    }
    node->now_pap_list = new_seen_node_list();
    if (node->now_pap_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node(): now_pap_list() alloc failed");
        free_seen_node_list(node->seen_node_list);
        free(node);
        return NULL;
    }

    node->opt_cost = 11111111;
    node->now_cost = 11111111;

    node->has_prefer = 0;

    node->opt_linked = 0;
    node->now_linked = 0;

    node->opt_childs = new_node_list();
    node->now_childs = new_node_list();
    if (node->opt_childs == NULL || node->now_childs == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node(): new_node_list() alloc failed");
        free_node(node);
        return NULL;
    }
    node->unique_mac = calloc(18, sizeof(char));
    node->ap2g = calloc(18, sizeof(char));
    node->ap5g = calloc(18, sizeof(char));
    node->ap5g1 = calloc(18, sizeof(char));
    node->ap6g = calloc(18, sizeof(char));
    node->pap2g = calloc(18, sizeof(char));
    node->pap5g = calloc(18, sizeof(char));
    node->pap6g = calloc(18, sizeof(char));

    if ((node->unique_mac && node->ap2g && node->ap5g && node->ap5g1 && node->ap6g && node->pap2g && node->pap5g && node->pap6g) == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node: calloc memory alloc failed");
        free_node(node);
        return NULL;
    }
    strcpy(node->unique_mac, node_unique_mac);
    return node;
}

void free_node(struct Node *node)
{
    if (node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("free_node: get a NULL ptr");
        return;
    }
    if (node->seen_node_list)
    {
        free_seen_node_list(node->seen_node_list);
        node->seen_node_list = NULL;
    }
    if (node->now_pap_list)
    {
        free_seen_node_list(node->now_pap_list);
        node->now_pap_list = NULL;
    }

    if (node->opt_childs)
    {
        free(node->opt_childs->node);
        free(node->opt_childs);
    }
    if (node->now_childs)
    {
        free(node->now_childs->node);
        free(node->now_childs);
    }

    free(node->unique_mac);
    free(node->ap2g);
    free(node->ap5g);
    free(node->ap5g1);
    free(node->ap6g);
    free(node->pap2g);
    free(node->pap5g);
    free(node->pap6g);

    free(node);

    return;
}

struct Seen_node *new_seen_node(const char *bssid, int rssi, int antenna_num, int bandwidth, int prefer, int band)
{
    if (bssid == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_seen_node: get a NULL bssid ptr");
        return NULL;
    }
    struct Seen_node *seen_node = calloc(1, sizeof(struct Seen_node));
    if (seen_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_seen_node: calloc memory alloc failed");
        return NULL;
    }

    seen_node->bssid = calloc(18, sizeof(char));
    if (seen_node->bssid == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_seen_node: calloc memory alloc failed");
        free(seen_node);
        return NULL;
    }
    strcpy(seen_node->bssid, bssid);

    seen_node->rssi = rssi;
    seen_node->antenna_num = antenna_num;
    seen_node->bandwidth = bandwidth;
    seen_node->prefer = prefer;
    seen_node->band = band;
    seen_node->cost = rssi_score(seen_node);

    return seen_node;
}
void free_seen_node(struct Seen_node *seen_node)
{
    if (seen_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("free_seen_node: get a NULL ptr");
        return;
    }
    free(seen_node->bssid);
    free(seen_node);
}

// to manage the limit of node_list
struct Node_list *new_node_list()
{

    struct Node_list *new_node_list;
    new_node_list = calloc(1, sizeof(struct Node_list));

    if (new_node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node_list: calloc memory alloc failed");
        return NULL;
    }
    new_node_list->capacity = 8;
    new_node_list->size = 0;

    new_node_list->node = calloc(new_node_list->capacity, sizeof(struct Node *));
    if (new_node_list->node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_node_list: calloc memory alloc failed");
        free(new_node_list);
        return NULL;
    }

    return new_node_list;
}
void free_node_list(struct Node_list *node_list)
{
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("free_node_list start");
    if (node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("free_node_list: get a NULL ptr");
        return;
    }
    for (int i = 0; i < node_list->size; i++)
    {
        if (node_list->node[i] != NULL)
        {
            free_node(node_list->node[i]);
            node_list->node[i] = NULL;
        }
    }
    free(node_list->node);
    free(node_list);
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("free_node_list done");
    return;
}
// return the place of the new node
int node_list_add(struct Node_list *node_list, struct Node *new_node)
{
    if (node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("node_list_add: node_list get a NULL ptr");
        return -1;
    }
    if (new_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("node_list_add: new_node get a NULL ptr");
        return -1;
    }

    // if list is full
    if ((node_list->size + 1) > node_list->capacity)
    {
        struct Node **tmp = calloc(node_list->capacity * 2, sizeof(struct Node *));
        if (tmp == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("node_list_add memory alloc failed");
            return -1;
        }
        for (int i = 0; i < node_list->capacity; i++)
        {
            tmp[i] = node_list->node[i];
        }
        node_list->capacity *= 2;
        free(node_list->node);
        node_list->node = tmp;
    }

    // add new_element to list
    node_list->node[node_list->size] = new_node;
    node_list->size += 1;

    return node_list->size - 1;
}

struct Seen_node_list *new_seen_node_list()
{

    struct Seen_node_list *new_seen_node_list;

    new_seen_node_list = calloc(1, sizeof(struct Seen_node_list));
    if (new_seen_node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_seen_node_list memory alloc failed");
        return NULL;
    }

    new_seen_node_list->capacity = 8;
    new_seen_node_list->size = 0;

    new_seen_node_list->seen_node = calloc(new_seen_node_list->capacity, sizeof(struct Seen_node *));
    if (new_seen_node_list->seen_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("new_seen_node_list memory alloc failed");
        free(new_seen_node_list);
        return NULL;
    }

    return new_seen_node_list;
}

void free_seen_node_list(struct Seen_node_list *seen_node_list)
{
    if (seen_node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("free_seen_node_list(): get NULL ptr");
        return;
    }
    for (int i = 0; i < seen_node_list->size; i++)
    {
        if (seen_node_list->seen_node[i] != NULL)
        {
            free_seen_node(seen_node_list->seen_node[i]);
            seen_node_list->seen_node[i] = NULL;
        }
    }
    free(seen_node_list->seen_node);
    free(seen_node_list);
    return;
}

int seen_node_list_add(struct Seen_node_list *seen_node_list, struct Seen_node *new_seen_node)
{
    if (seen_node_list == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("seen_node_list_add: seen_node_list get a NULL ptr");
        return -1;
    }
    if (new_seen_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("seen_node_list_add: new_seen_node get a NULL ptr");
        return -1;
    }

    // if list is full
    if ((seen_node_list->size + 1) > seen_node_list->capacity)
    {

        struct Seen_node **tmp = calloc(seen_node_list->capacity * 2, sizeof(struct Seen_node *));
        if (tmp == NULL)
        {
            if (nvram_get("cfg_opt_dbg"))
                DBG_LOG("seen_node_list_add() memory alloc failed");
            return -1;
        }
        for (int i = 0; i < seen_node_list->capacity; i++)
        {
            tmp[i] = seen_node_list->seen_node[i];
        }
        seen_node_list->capacity *= 2;
        free(seen_node_list->seen_node);
        seen_node_list->seen_node = tmp;
    }

    // add new_element to list
    seen_node_list->seen_node[seen_node_list->size] = new_seen_node;
    seen_node_list->size += 1;

    return seen_node_list->size - 1;
}

struct Node *find_node_by_unique_mac(char *target_macaddr, struct Node_list *node_list)
{

    for (int i = 0; i < node_list->size; i++)
    {
        // find match mac in any of *unique_mac, *ap2g, *ap5g, *ap5g1, *ap6g

        if (node_list->node[i]->unique_mac != NULL)
            if (strcmp(node_list->node[i]->unique_mac, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
    }
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("Can't find unique_mac %s", target_macaddr);
    return NULL;
}
struct Node *find_node_by_bssid(char *target_macaddr, struct Node_list *node_list)
{

    for (int i = 0; i < node_list->size; i++)
    {
        // find match mac in any of *unique_mac, *ap2g, *ap5g, *ap5g1, *ap6g

        if (node_list->node[i]->unique_mac != NULL)
            if (strcmp(node_list->node[i]->unique_mac, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
        if (node_list->node[i]->ap2g != NULL)
            if (strcmp(node_list->node[i]->ap2g, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
        if (node_list->node[i]->ap5g != NULL)
            if (strcmp(node_list->node[i]->ap5g, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
        if (node_list->node[i]->ap5g1 != NULL)
            if (strcmp(node_list->node[i]->ap5g1, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
        if (node_list->node[i]->ap6g != NULL)
            if (strcmp(node_list->node[i]->ap6g, target_macaddr) == 0)
            {
                return node_list->node[i];
            }
    }
    if (nvram_get("cfg_opt_dbg"))
        DBG_LOG("Can't find bssid %s", target_macaddr);
    return NULL;
}

void print_tree(struct Node *node)
{
    if (nvram_get("cfg_opt_dbg"))
    {

        DBG_LOG("mac: %s", node->unique_mac ?: "");
        if (node->opt_parent)
            DBG_LOG("parent bssid:%s", node->opt_parent->bssid ?: "");
        DBG_LOG("opt_cost:%.2f ", node->opt_cost);
    }
    for (int i = 0; i < node->opt_childs->size; i++)
    {
        print_tree(node->opt_childs->node[i]);
    }
}

// traversal topology tree deep first from cap

json_object *print_tree_to_jso_from_cap(struct Node *cap)
{
    DBG_LOG("print_tree_to_jso_from_cap");
    int sequence;
    sequence = 1;

    json_object *result_jso;
    result_jso = json_object_new_object();

    if (result_jso == NULL)
    {
        DBG_LOG("print_tree_to_jso_from_cap(): json_object_new_object() Memory alloc failed");
        return NULL;
    }

    for (int i = 0; i < cap->opt_childs->size; i++)
    {
        print_tree_to_jso_re(cap->opt_childs->node[i], result_jso, &sequence, 0);
    }
    return result_jso;
}

// recursive traversal all node, deep first
void print_tree_to_jso_re(struct Node *node, json_object *result_jso, int *sequence, int pap_changed)
{
    if (node->opt_parent == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("print_tree_to_jso_re, print_tree_to_jso_re can't find %s parent_node", node->unique_mac);

        return;
    }
    if (node->opt_parent->target_node == NULL)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("print_tree_to_jso_re, print_tree_to_jso_re can't find %s parent_node", node->unique_mac);

        return;
    }
    // if pap node was changed, all child nodes will disconnect, so print to result json
    if (pap_changed)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            // skip add topology info to result json
            DBG_LOG("%s pap topology changed, all child node should out put to result", node->unique_mac);
        }
    }
    // if topology didn't change, new parent is old parent
    if (node->now_parent->target_node == node->opt_parent->target_node)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            // skip add topology info to result json
            DBG_LOG("%s parent node didn't change, skip add topology info to result json", node->unique_mac);
        }
    }
    // if topology changed, this node and all child nodes should output result
    else if (node->now_parent->target_node != node->opt_parent->target_node)
    {
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("%s parent node changed, add topology info to result json", node->unique_mac);
        }
        pap_changed = 1;
    }
    else
    {
        // should not happen
        if (nvram_get("cfg_opt_dbg"))
        {
            DBG_LOG("%s Something wrong", node->unique_mac);
        }
    }

    if (pap_changed)
    {
        // to store the topology of the node
        json_object *node_topology;
        node_topology = json_object_new_object();
        if (node_topology == NULL)
        {
            DBG_LOG("print_tree_to_jso_re: json_object_new_object() Memory alloc failed");
            return;
        }

        // add the topology of the node to jso
        json_object_object_add(node_topology, "target_bssid", json_object_new_string(node->opt_parent->bssid));
        json_object_object_add(node_topology, "seq", json_object_new_int((*sequence)));

        (*sequence)++;
        // add the topology jso  to result jso
        json_object_object_add(result_jso, node->unique_mac, node_topology);
    }

    // traversal all child nodes
    for (int i = 0; i < node->opt_childs->size; i++)
    {
        print_tree_to_jso_re(node->opt_childs->node[i], result_jso, sequence, pap_changed);
    }

    return;
}

int minimum_spanning_tree_now(struct Node_list *node_list)
{
    // use minimun spanning tree algorithm to recontruct the topology using now
    // nodes only have 2g, 5g, 6g pap and eth pap in thier seen node list

    // cap is linked
    int linked_nodes_count = 1;
    float min_connection_cost;
    // store child node of the minimun cost link
    struct Node *min_connection_child = NULL;
    // store the minimun cost link with witch interface using, target node ...
    struct Seen_node *min_connection_parent = NULL;
    struct Seen_node *tmp_seen_node;

    // nodes were init at creation

    // find the lowest cost link from a linked node to a not linked node, and linked these two node
    // until all nodes are linked or can't find any linkable node
    while (linked_nodes_count < node_list->size)
    {
        // init after each connection is add to topology tree
        min_connection_cost = 12345678;
        min_connection_child = NULL;
        min_connection_parent = NULL;

        // start of searching new connection
        // find a node is not linked to topology
        for (int i = 0; i < node_list->size; i++)
        {
            // if the node is linked, skip this
            if (node_list->node[i]->now_linked == 1)
            {
                continue;
            }

            // found one not linked node
            // then find a linked node in child node's seen_node_list
            for (int j = 0; j < node_list->node[i]->now_pap_list->size; j++)
            {
                tmp_seen_node = node_list->node[i]->now_pap_list->seen_node[j];
                // if the end node is not linked, skip this
                if (tmp_seen_node->target_node->now_linked == 0)
                {
                    continue;
                }

                // update min connection if new connection is better
                if ((tmp_seen_node->cost + tmp_seen_node->target_node->now_cost) < min_connection_cost)
                {
                    min_connection_cost = (tmp_seen_node->cost + tmp_seen_node->target_node->now_cost);
                    // store child node and parent node
                    min_connection_child = node_list->node[i];
                    min_connection_parent = tmp_seen_node;
                }
            }
        }
        // end of searching new connection

        // if can't find any available link
        // return the number of node can't add into topology
        if (min_connection_cost == 12345678)
        {
            return node_list->size - linked_nodes_count;
        }
        // if can't find new connection should return at previous if
        // something bad happen if going into this if
        if ((min_connection_parent == NULL) || (min_connection_child == NULL))
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("something bad happen");
                DBG_LOG("%d %d", node_list->size, linked_nodes_count);
            }
            return node_list->size - linked_nodes_count;
        }

        // a new node is connect to the topology tree
        linked_nodes_count++;

        // (min_connection_parent->target_node) is the parent node
        // add child node to parent node's opt_childs list
        node_list_add((min_connection_parent->target_node)->now_childs, min_connection_child);

        // update child node's parent
        min_connection_child->now_parent = min_connection_parent;
        min_connection_child->now_cost = min_connection_cost;
        min_connection_child->now_linked = 1;
    }
    // if all node is add to topology
    return 0;
}

int minimum_spanning_tree_opt(struct Node_list *node_list)
{
    // use minimun spanning tree algorithm to find the best topology

    // cap is linked
    int linked_nodes_count = 1;
    float min_connection_cost;
    // store child node of the minimun cost link
    struct Node *min_connection_child = NULL;
    // store the minimun cost link with witch interface using, target node ...
    struct Seen_node *min_connection_parent = NULL;
    struct Seen_node *tmp_seen_node;
    struct Node *tmp_node;
    // assume any seen node original cost can't be higher than 1M
    // so add 1M cost equal to dealing this type of seen node with higher priority
    // prefer > others > non-prefer in a node with prefer
    // with this rule we can guarantee prefer first, but also avoid prefer loop
    // likes: cap =/=  A -> B -> C -> A

    // add additional cost to all seen nodes to deal with prefer
    // prefer seen node have highest priority, so add 0 to cost
    // if a node with no prefer node, than add 1M cost to all its seen node
    // if a node has prefer node, add 2k cost to all non-prefer seen node

    for (int i = 0; i < node_list->size; i++)
    {
        tmp_node = node_list->node[i];
        if (tmp_node->has_prefer)
            for (int j = 0; j < tmp_node->seen_node_list->size; j++)
            {
                if (tmp_node->seen_node_list->seen_node[j]->prefer == 0)
                    tmp_node->seen_node_list->seen_node[j]->cost += 200000;
            }
        else
            for (int j = 0; j < tmp_node->seen_node_list->size; j++)
            {
                tmp_node->seen_node_list->seen_node[j]->cost += 100000;
            }
    }
    // after adding cost, use normal minimum spanning tree to get opt topology
    // find the lowest cost link from a linked node to a not linked node, and linked these two node
    // until all nodes are linked or can't find any linkable node
    while (linked_nodes_count < node_list->size)
    {
        // init after each connection is add to topology tree
        min_connection_cost = 12345678;
        min_connection_child = NULL;
        min_connection_parent = NULL;

        // start of searching new connection
        // find a node is not linked to topology
        for (int i = 0; i < node_list->size; i++)
        {
            // if the node is linked, skip this
            if (node_list->node[i]->opt_linked == 1)
            {
                continue;
            }

            // found one not linked node
            // then find a linked node in child node's seen_node_list
            for (int j = 0; j < node_list->node[i]->seen_node_list->size; j++)
            {
                tmp_seen_node = node_list->node[i]->seen_node_list->seen_node[j];
                // if the end node is not linked, skip this
                if (tmp_seen_node->target_node->opt_linked == 0)
                {
                    continue;
                }

                // update min connection if new connection is better
                if ((tmp_seen_node->cost + tmp_seen_node->target_node->opt_cost) < min_connection_cost)
                {
                    min_connection_cost = (tmp_seen_node->cost + tmp_seen_node->target_node->opt_cost);
                    min_connection_child = node_list->node[i];
                    min_connection_parent = tmp_seen_node;
                }
            }
        }
        // end of searching new connection

        // can't find any available link
        // return the number of node can't add into topology
        if (min_connection_cost == 12345678)
        {
            return node_list->size - linked_nodes_count;
        }
        // something bad happen
        if ((min_connection_parent == NULL) || (min_connection_child == NULL))
        {
            if (nvram_get("cfg_opt_dbg"))
            {
                DBG_LOG("something bad happen");
                DBG_LOG("%d %d", node_list->size, linked_nodes_count);
            }
            return node_list->size - linked_nodes_count;
        }

        // a new node is connect to the topology
        linked_nodes_count++;

        // (min_connection_parent->target_node) is the parent node
        // add child node to parent node's opt_childs list
        node_list_add((min_connection_parent->target_node)->opt_childs, min_connection_child);

        // update child node's parent
        min_connection_child->opt_parent = min_connection_parent;
        // remove the cost added before, restore it to original cost
        while (min_connection_cost >= 100000)
            min_connection_cost -= 100000;
        min_connection_child->opt_cost = min_connection_cost;
        min_connection_child->opt_linked = 1;
    }
    // if all node is add to topology
    return 0;
}

void print_node_list(struct Node_list *node_list)
{
    for (int i = 0; i < node_list->size; i++)
    {
        DBG_LOG("node: %s, now_cost:%.2f, opt_cost:%.2f", node_list->node[i]->unique_mac, node_list->node[i]->now_cost, node_list->node[i]->opt_cost);
        if (node_list->node[i]->now_parent)
            DBG_LOG("\tnow_parent: %s", node_list->node[i]->now_parent->bssid);
        if (node_list->node[i]->opt_parent)
            DBG_LOG("\topt_parent: %s", node_list->node[i]->opt_parent->bssid);
        DBG_LOG("\tseen_node_list:");
        print_seen_node_list(node_list->node[i]->seen_node_list);
        DBG_LOG("\tnow_pap_list:");
        print_seen_node_list(node_list->node[i]->now_pap_list);
        DBG_LOG(" ");
    }
}
void print_seen_node_list(struct Seen_node_list *seen_node_list)
{
    for (int i = 0; i < seen_node_list->size; i++)
    {
        if (seen_node_list->seen_node[i]->target_node)
            DBG_LOG("\t\ttarget node mac: %s,cost %f, bssid: %s, rssi: %d", seen_node_list->seen_node[i]->target_node->unique_mac, seen_node_list->seen_node[i]->cost, seen_node_list->seen_node[i]->bssid, seen_node_list->seen_node[i]->rssi);
        else
            DBG_LOG("\t\tthis seen node has no target node");
    }
}

float rssi_score(struct Seen_node *seen_node)
{

    float rssi_score, cost;
    // 6G PF not implement

    // if using ether
    // TODO: add cost if eth link rate is less than 10M
    if (seen_node->rssi == 0)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("rssi == 0, using ether, opt_cost = 0");
        return 0;
    }
    // -999 is init value when creating seen node, meaning something wrong there, skip it
    else if (seen_node->rssi == -999)
    {
        if (nvram_get("cfg_opt_dbg"))
            DBG_LOG("rssi == -999, something wrong happened");
        return 12345678;
    }
    // should convert to float before bandwidth/80 or antenna_num/4
    // or will only get a int result
    rssi_score = (float)seen_node->rssi + 10 * (float)log(((float)seen_node->antenna_num / (float)4)) + 10 * (float)log(((float)seen_node->bandwidth / (float)80));

    cost = calculate_cost_by_rssi(rssi_score, seen_node->rssi);

    // if using 2.4G, cost += 16
    if (seen_node->band == 2)
    {
        cost += 16;
    }
    if (nvram_get("cfg_opt_dbg"))
    {
        DBG_LOG("Target info: rssi = %d, antenna_num = %d, bandwidth = %d", seen_node->rssi, seen_node->antenna_num, seen_node->bandwidth);
        DBG_LOG("rssi_score = %f, cost = %f", rssi_score, cost);
    }
    return cost;
}
float calculate_cost_by_rssi(float rssi_score, int rssi)
{
    // calculate cost by rssi and rssi score
    // add .0 to use float
    if (rssi_score > -60)
    {
        return 1.0;
    }
    else if (rssi_score > -70)
    {
        return (1.0 + 1.0 * ((-60.0 - rssi_score) / 10.0));
    }
    else if (rssi_score > -80)
    {
        return (2.0 + 4.0 * ((-70.0 - rssi_score) / 10.0));
    }
    else
    {
        return (6.0 + 10.0 * ((-80.0 - rssi_score) / 10.0));
    }
}