#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_string.h"
#include "cfg_mtlan.h"

int get_vlanid_by_idx(int idx, VLAN_T *lst, size_t lst_sz)
{
	int i;
	int ret = -1;

	if (!lst){
		return -1;
	}
	for (i = 0; i < lst_sz; i++) {
		if (lst[i].idx == idx) {
			ret = lst[i].vid;
			return ret;
		}
	}
	return ret;
}

int get_vid_from_vlan_rl(int unit) 
{
	MTLAN_T *p_mtlan = NULL;   
    size_t mtlan_sz = 0;
	int ret = -1;

	if (!(p_mtlan = (MTLAN_T *)INIT_MTLAN(sizeof(MTLAN_T))))
		return -1;

	if (get_mtlan_by_idx(SDNFT_TYPE_APG, unit, p_mtlan, &mtlan_sz) && mtlan_sz > 0) 
		ret = p_mtlan->vid;
	
	FREE_MTLAN((void*)p_mtlan);
	return ret;
}

APG_DUT_LIST_T *get_apg_dut_list_info(APG_DUT_LIST_T *apglst, size_t *sz,int unit)
{
	char *nv = NULL, *nvp = NULL, *b;
	char *dev_mac, *wifiband_id, *lanport_id;
	char apg_name[14];
	size_t cnt = 0;

	if (sz)
		*sz = 0;
	
	memset(apg_name, 0, sizeof(apg_name));
	snprintf(apg_name, sizeof(apg_name), "apg%d_dut_list",unit);
	
	if (!(nv = nvp = strdup(nvram_safe_get(apg_name))))
		return NULL;

	while ((b = strsep(&nvp, "<")) != NULL) {
		if (vstrsep(b, ">", &dev_mac, &wifiband_id ,&lanport_id) <2)
			continue;

		if (cnt >= APG_MAXINUM)
			break;

		if (dev_mac && *dev_mac)
			strlcpy(apglst[cnt].dev_mac , dev_mac, sizeof(apglst[cnt].dev_mac));
		if (wifiband_id && *wifiband_id)
			apglst[cnt].wifiband_id = strtol(wifiband_id, NULL, 10);
		if (lanport_id && *lanport_id)
			strlcpy(apglst[cnt].lanport_id , lanport_id, sizeof(apglst[cnt].lanport_id ));

		cnt++;
	}

	*sz = cnt;

	free(nv);
	return apglst;
}

int *get_apg_wifiband(char *mac, int unit)
{
	int i;
	size_t apg_sz = 0;
	int  apg_wifibandtype=-1;
	
	APG_DUT_LIST_T *apg_dut_list_info = (APG_DUT_LIST_T *)INIT_MTLAN(sizeof(APG_DUT_LIST_T));
	if (!get_apg_dut_list_info(apg_dut_list_info, &apg_sz,unit)) {
		FREE_MTLAN((void *)apg_dut_list_info);
		return -1;
	}

	for (i = 0; i < apg_sz; i++) {
		if (!strcmp(mac, apg_dut_list_info[i].dev_mac)) {
			apg_wifibandtype = apg_dut_list_info[i].wifiband_id;
			FREE_MTLAN((void *)apg_dut_list_info);
			return apg_wifibandtype;
		}
	}

	FREE_MTLAN((void *)apg_dut_list_info);
	return -1;

}

char *get_apg_lanport(char *mac, int unit)
{
	int i;
	size_t apg_sz = 0;
	static char apg_lanport[32];
	memset(apg_lanport, 0, sizeof(apg_lanport));

	APG_DUT_LIST_T *apg_dut_list_info = (APG_DUT_LIST_T *)INIT_MTLAN(sizeof(APG_DUT_LIST_T));
	if (!get_apg_dut_list_info(apg_dut_list_info, &apg_sz,unit)) {
		FREE_MTLAN((void *)apg_dut_list_info);
		return NULL;
	}
	
	for (i = 0; i < apg_sz; i++) {
		if (!strcmp(mac, apg_dut_list_info[i].dev_mac)) {
			snprintf(apg_lanport, sizeof(apg_lanport), "%s", apg_dut_list_info[i].lanport_id);
			FREE_MTLAN((void *)apg_dut_list_info);
			return apg_lanport;
		}
	}
	
	FREE_MTLAN((void *)apg_dut_list_info);
	return NULL;

}

char *match_wifiband_from_dutlist(char *mac, int unit, char *ret_buf, size_t ret_bsize)
{
	char ifnames[256];
	char ifname[65];
	char *ptr = NULL;
	char *end = NULL;
	char word[64];
	char *next = NULL;

	if (!mac || strlen(mac) <= 0 || !ret_buf || ret_bsize <= 0)
		return NULL;

	memset(ret_buf, 0, ret_bsize);
	ptr = &ret_buf[0];
	end = ptr + ret_bsize;	

	memset(ifnames, 0, sizeof(ifnames));
	if (!get_ifnames_used_by_sdn_vid(mac, get_vid_from_vlan_rl(unit), get_sdn_idx(unit), ifnames, sizeof(ifnames)-1)) 
		return NULL;

	foreach (word, ifnames, next) {
		memset(ifname, 0, sizeof(ifname));
		if (!get_wificap_ifname_from_wlprefix(mac, word, ifname, sizeof(ifname)-1))
			continue;
		ptr += snprintf(ptr, end-ptr, "%s,", ifname);
	}

	if (strlen(ret_buf) > 0 && ret_buf[strlen(ret_buf)-1] == ',')
		ret_buf[strlen(ret_buf)-1] = '\0';

	return (strlen(ret_buf) > 0) ? ret_buf : NULL;

}

char *match_lanports_from_dutlist(char *mac, json_object *capabilityObj, int unit, char *ret_buf, size_t ret_bsize)
{
	char apg_lan_ifnames[128];
	char apg_lan_ifnames_for[128];
	char apg_lan_ifnames_tmp[32];
	char apg_lan_id_tmp[8];
	char *get_lanport; 
	char s1[80];
	json_object *c = NULL;
	json_object *lanportObj = NULL;
	json_object *lanportinfoObj = NULL;
	json_object *lanportsubinfoObj = NULL;
	json_object *lanportifnameObj = NULL;

	if (!mac || strlen(mac) <= 0 || !capabilityObj || !ret_buf || ret_bsize <= 0)
		return NULL;

	memset(ret_buf, 0, ret_bsize);
	memset(apg_lan_ifnames, 0, sizeof(apg_lan_ifnames));
	memset(apg_lan_id_tmp, 0, sizeof(apg_lan_id_tmp));
	get_lanport = get_apg_lanport(mac,unit);
	if(get_lanport)
	{
		memset(s1, 0, sizeof(s1));
		snprintf(s1, sizeof(s1), "%d", LAN_PORT_CAP);
		json_object_object_get_ex(capabilityObj, s1, &lanportObj);
		if(lanportObj==NULL){
			return NULL;
		}
		else{
			json_object_object_get_ex(lanportObj, "lan_port", &lanportinfoObj);
		}
		  char *p; 
		  p = strtok(get_lanport, ",");
		  while(p)
		  {  
		    if(lanportinfoObj)
		    {
		    	snprintf(apg_lan_id_tmp, sizeof(apg_lan_id_tmp), "lan%s", p);
		    	json_object_object_get_ex(lanportinfoObj, apg_lan_id_tmp, &lanportsubinfoObj);
		    	if(lanportsubinfoObj)
		    	{
		    		json_object_object_get_ex(lanportsubinfoObj, "ifname", &lanportifnameObj);
		    		if(lanportifnameObj)
		    		{
		    			memset(apg_lan_ifnames_tmp, 0, sizeof(apg_lan_ifnames_tmp));
		    			snprintf(apg_lan_ifnames_tmp, sizeof(apg_lan_ifnames_tmp), "%s", json_object_get_string(lanportifnameObj));
		    			if(strlen(apg_lan_ifnames)>0)
		    			{
		    				memset(apg_lan_ifnames_for, 0, sizeof(apg_lan_ifnames_for));
		    				snprintf(apg_lan_ifnames_for, sizeof(apg_lan_ifnames_for), "%s", apg_lan_ifnames);	
		    				snprintf(apg_lan_ifnames, sizeof(apg_lan_ifnames), "%s,%s", apg_lan_ifnames_for,apg_lan_ifnames_tmp);
		    			}
		    			else
		    			{
		    				snprintf(apg_lan_ifnames, sizeof(apg_lan_ifnames), "%s", apg_lan_ifnames_tmp);
		    			}
		    		}
		    	
		    	}
		    }
		    else{
		    	return NULL;
		    }
		    p = strtok(NULL, ",");  
		  }
		  
		  if (strlen(apg_lan_ifnames)>0) {
          	strlcpy(ret_buf, apg_lan_ifnames, ret_bsize);
 			return ret_buf;
		  }
		  else {
          	return NULL;
		  }
	}
	else
		return NULL;
}

char *get_lanport_cap_ifname(json_object *capabilityObj, int portIndex, char *ret_ifname, int bsize)
{
	json_object *lanportObj = NULL;
	json_object *laninfoObj = NULL;
	json_object *lansubinfoObj = NULL;
	json_object *lanifnameObj = NULL;
	char s[81];
	
	if (ret_ifname && bsize > 0)
		memset(ret_ifname, 0, bsize);
	else  
		return NULL;
		
	if (!capabilityObj)
		return NULL;
		
	memset(s, 0, sizeof(s));
	snprintf(s, sizeof(s), "%d", LAN_PORT_CAP);
	json_object_object_get_ex(capabilityObj, s, &lanportObj);
	if (!lanportObj)
		return NULL;
		
	json_object_object_get_ex(lanportObj, "lan_port", &laninfoObj);	
		
	if (!laninfoObj) 
		return NULL;
	
	memset(s, 0, sizeof(s));
	snprintf(s, sizeof(s), "lan%d", portIndex);
	json_object_object_get_ex(laninfoObj, s, &lansubinfoObj);
	if (!lansubinfoObj)
		return NULL; 
		
	json_object_object_get_ex(lansubinfoObj, "ifname", &lanifnameObj);
	if (!lanifnameObj) 
		return NULL;
		
	strlcpy(ret_ifname, json_object_get_string(lanifnameObj), bsize);
	return (strlen(ret_ifname) > 0) ? ret_ifname : NULL;
}

char *create_vlan_trunk_rulelist(char *mac, json_object *capabilityObj, char *buffer, int bsize)
{
#define NV_VLAN_TRUNKLIST	"vlan_trunklist"
	char *nvp = NULL;
	char *nv = NULL;
	char *b = NULL;
    char *bb = NULL;
	char *portidx = NULL;
    char *vids = NULL;
	char *ptr = NULL;
	char *end = NULL;
	char s[MAX_MAC_STR_LEN+1];
	char ifname[MAX_IFNAME_STR_LEN+1];
	char *ptr2 = NULL;
	char *end2 = NULL;
	char tmp_str[1025];
	
	MTLAN_T *p_mtlan = NULL, *pp = NULL;
	size_t mtlan_sz = 0;
	
	int i;
	int y;

	if (buffer && bsize > 0)
		memset(buffer, 0, bsize);
	else
		return NULL;
	
	if (!mac || !capabilityObj)
		return NULL;
	
	ptr = &buffer[0];
	end = ptr + bsize;
	
	nv = nvp = strdup(nvram_safe_get(NV_VLAN_TRUNKLIST));
    if (nv == NULL)
        return NULL;

	while ((b = strsep(&nvp, "<")) != NULL) {
        i=0;
        while ((bb = strsep(&b, ">")) != NULL) {
            if (!bb || strlen(bb) <= 0)
                break;
            if (i==0) {
				i++;
				memset(s, 0, sizeof(s));
				strlcpy(s, bb, MAX_MAC_STR_LEN);
				if (strcmp(mac, s) != 0)
					break;
            }
            else { 
                if (vstrsep(bb, "#", &portidx, &vids) != 2)
                    continue;
				if (!portidx || strlen(portidx) <= 0)
                   	continue;
                if (!vids || strlen(vids) <= 0)
                    continue;
				memset(ifname, 0, sizeof(ifname));
				if (!get_lanport_cap_ifname(capabilityObj, atoi(portidx), ifname, MAX_IFNAME_STR_LEN))
					continue;

				if (strstr(lowerCase(vids), "all")) {
					mtlan_sz = 0;
					if (!(p_mtlan = (MTLAN_T *)INIT_MTLAN(sizeof(MTLAN_T))))
						continue;
					if (!get_mtlan(p_mtlan, &mtlan_sz) || mtlan_sz <= 0) {
						FREE_MTLAN((void*)p_mtlan);
						continue;
					}

					memset(tmp_str, 0, sizeof(tmp_str));
					ptr2 = &tmp_str[0];
					end2 = ptr2 + sizeof(tmp_str)-1;
					for (pp=p_mtlan, y=0; y<mtlan_sz && pp!=NULL; y++, pp++) {
						if (!pp->enable || pp->vid <= 0)
							continue;
						ptr2 += snprintf(ptr2, end2-ptr2, "%d,", pp->vid);
					}	
					
					if (strlen(tmp_str) > 0 && tmp_str[strlen(tmp_str)-1] == ',')
						tmp_str[strlen(tmp_str)-1] = '\0';

					FREE_MTLAN((void*)p_mtlan);
					vids = &tmp_str[0];
				}

				ptr += snprintf(ptr, end-ptr, "<%s>%s", ifname, vids);				
            }
        }
    }

	free(nv);
	return (strlen(buffer) > 1) ? buffer : NULL;
}

char* create_wgn_vlan_rl(char *mac, char *ret_buf, size_t ret_bsize)
{
	int i, j, x;
	int wlset = 0;
	int found = 0;
	unsigned int sdn_vid = 0;
	apg_rule_st apg_rule;
	char *b = NULL;
	size_t total = 0;
	struct wgn_vlan_rule_t vlan_list[WGN_MAXINUM_VLAN_RULELIST], *p = NULL;
	unsigned short used_band = 0;
	unsigned short wifi_band = 0;

	if (!mac || strlen(mac) <= 0 || !ret_buf || ret_bsize <= 0)
		return NULL;

	memset(ret_buf, 0, ret_bsize);
	if (!(b = nvram_default_get(WGN_VLAN_RULE_NVRAM)))
		return NULL;

	memset(vlan_list, 0, sizeof(struct wgn_vlan_rule_t) * WGN_MAXINUM_VLAN_RULELIST);
    if (!wgn_vlan_list_get_from_content(b, vlan_list, WGN_MAXINUM_VLAN_RULELIST, &total, WGN_GET_CFG_TYPE_WGN_ONLY) || total <= 0)
		return NULL;

	for (i=1; i<APG_MAXINUM; i++) {
		memset(&apg_rule, 0, sizeof(apg_rule));
		get_apg_rule_by_idx(i, &apg_rule);
		sdn_vid = get_sdn_vid_by_apg_rule(&apg_rule);
		if ((!get_mtlan_enable_by_vid(sdn_vid) || apg_rule.enable == 0) && find_mtvlan(sdn_vid)) 
			continue;

		for (j=0; j<apg_rule.dut_list_size; j++) {
			if (strcmp(mac, apg_rule.dut_list[j].mac))
				continue;
			wifi_band = 0;
			if ((apg_rule.dut_list[j].wifi_band & WIFI_BAND_2G) == WIFI_BAND_2G && (used_band & WIFI_BAND_2G) != WIFI_BAND_2G)
				wifi_band = WIFI_BAND_2G;
			else if (((apg_rule.dut_list[j].wifi_band & WIFI_BAND_5G) == WIFI_BAND_5G || (apg_rule.dut_list[j].wifi_band & WIFI_BAND_5GL) == WIFI_BAND_5GL) && 
					((used_band & WIFI_BAND_5G) != WIFI_BAND_5G && (used_band & WIFI_BAND_5GL) != WIFI_BAND_5GL))
				wifi_band = WIFI_BAND_5G | WIFI_BAND_5GL;
			else if ((apg_rule.dut_list[j].wifi_band & WIFI_BAND_5GH) == WIFI_BAND_5GH && (used_band & WIFI_BAND_5GH) != WIFI_BAND_5GH)
				wifi_band = WIFI_BAND_5GH;
			else if ((apg_rule.dut_list[j].wifi_band & WIFI_BAND_6G) == WIFI_BAND_6G && (used_band & WIFI_BAND_6G) != WIFI_BAND_6G)
				wifi_band = WIFI_BAND_6G;
			else 
				wifi_band = 0;

			if (wifi_band > 0) {
				used_band |= wifi_band;
				for (x=0; x<total; x++) {
					p = &vlan_list[x];
					if (p->wl2gset && strlen(p->wl2gset) == 4 && (wlset = strtoul(p->wl2gset, NULL, 10)) > 0) {	// 2G
						if ((wifi_band & WIFI_BAND_2G) == WIFI_BAND_2G) {
							p->vid = sdn_vid;
							break;
						}
					}
					else if (p->wl5gset && strlen(p->wl5gset) == 4 && (wlset = strtoul(p->wl5gset,  NULL, 10)) > 0) { // 5G
						if ((wifi_band & WIFI_BAND_5G) == WIFI_BAND_5G || (wifi_band & WIFI_BAND_5GL) == WIFI_BAND_5GL) {
							p->vid = sdn_vid;
							break;
						}
					}
					else if (p->wl5gset && strlen(p->wl5gset) == 8 && (wlset = strtoul(&p->wl5gset[4], NULL, 10)) > 0) { // 5GH
						if ((wifi_band & WIFI_BAND_5GH) == WIFI_BAND_5GH) {
							p->vid = sdn_vid;
							break;
						}
					}
					else if (p->wl5gset && strlen(p->wl5gset) == 12 && (wlset = strtoul(&p->wl5gset[8], NULL, 10)) > 0) { // 6G
						if ((wifi_band & WIFI_BAND_6G) == WIFI_BAND_6G) {
							p->vid = sdn_vid;
							break;
						}
					}
					else {
						// do nothing
					}
				}

				break;
			}			
		}
	}

	return (wgn_vlan_list_set_to_buffer(vlan_list, total, ret_buf, ret_bsize)) ? ret_buf : NULL;
}

char* create_ap_wifi_rl(char *mac, char *ret_buf, size_t ret_bsize)
{
	int i;
	unsigned int sdn_vid = 0;
	apg_rule_st apg_rule;
	char *ptr = NULL;
	char *end = NULL;
	char nv[81];
	char str[256], *s = NULL;

	if (!mac || strlen(mac) <= 0 || !ret_buf || ret_bsize <= 0)
		return NULL;

	memset(ret_buf, 0, ret_bsize);
	ptr = &ret_buf[0];
	end = ptr + ret_bsize;

	for (i=1; i<APG_MAXINUM; i++) {
		memset(&apg_rule, 0, sizeof(apg_rule));
		get_apg_rule_by_idx(i, &apg_rule);
		sdn_vid = get_sdn_vid_by_apg_rule(&apg_rule);
		if ((!get_mtlan_enable_by_vid(sdn_vid) || apg_rule.enable == 0) && find_mtvlan(sdn_vid)) 
			continue;

		memset(nv, 0, sizeof(nv));
		snprintf(nv, sizeof(nv), "apg%d_dut_list", i);
		if (!strstr(nvram_safe_get(nv), mac))
			continue;

		memset(str, 0, sizeof(str));
		if (!(s = match_wifiband_from_dutlist(mac, i, str, sizeof(str)-1)) || strlen(s) <= 0)
			continue;

		ptr += snprintf(ptr, end-ptr, "<%d>%s>", sdn_vid, s);
	}

	if (strlen(ret_buf) > 0 && ret_buf[strlen(ret_buf)-1] == '>')
		ret_buf[strlen(ret_buf)-1] = '\0';

	return (strlen(ret_buf) > 0) ? ret_buf : NULL;
}

char* create_ap_lanif_rl(char *mac, json_object *capabilityObj, char *ret_buf, size_t ret_bsize)
{
	int i;
	unsigned int sdn_vid = 0;
	apg_rule_st apg_rule;
	char *ptr = NULL;
	char *end = NULL;
	char nv[81];
	char str[256], *s = NULL;

	if (!capabilityObj || !mac || strlen(mac) <= 0 || !ret_buf || ret_bsize <= 0)
		return NULL;

	memset(ret_buf, 0, ret_bsize);
	ptr = &ret_buf[0];
	end = ptr + ret_bsize;

	for (i=1; i<APG_MAXINUM; i++) {
		memset(&apg_rule, 0, sizeof(apg_rule));
		get_apg_rule_by_idx(i, &apg_rule);
		sdn_vid = get_sdn_vid_by_apg_rule(&apg_rule);
		if ((!get_mtlan_enable_by_vid(sdn_vid) || apg_rule.enable == 0) && find_mtvlan(sdn_vid)) 
			continue;

		memset(nv, 0, sizeof(nv));
		snprintf(nv, sizeof(nv), "apg%d_dut_list", i);
		if (!strstr(nvram_safe_get(nv), mac))
			continue;

		memset(str, 0, sizeof(str));
		if (!(s = match_lanports_from_dutlist(mac, capabilityObj, i, str, sizeof(str)-1)) || strlen(s) <= 0)
			continue;

		ptr += snprintf(ptr, end-ptr, "<%d>%s>", sdn_vid, s);
	}

	if (strlen(ret_buf) > 0 && ret_buf[strlen(ret_buf)-1] == '>')
		ret_buf[strlen(ret_buf)-1] = '\0';

	return (strlen(ret_buf) > 0) ? ret_buf : NULL;
}

char* max_of_mssid_ifnames(int unit, char *ret_ifnames, int buffer_size) 
{
	int subunit = 0, size = 0;
	char *ptr = NULL;
	char *end = NULL;
	char str[81];

	if (unit < 0 || !ret_ifnames || buffer_size <= 0)
		return NULL;

	memset(ret_ifnames, 0, buffer_size);
	ptr = &ret_ifnames[0];
	end = ptr + buffer_size;

	for (subunit=0; subunit<8; subunit++) {
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "wl%d.%d", unit, subunit+1);
		if (size >= buffer_size || (size + strlen(str)+1) >= buffer_size) {
			memset(ret_ifnames, 0, buffer_size);
			break;
		}

		ptr += snprintf(ptr, end-ptr, "%s ", str);
		size += strlen(str)+1;
	}

	if (strlen(ret_ifnames) > 0 && ret_ifnames[strlen(ret_ifnames)-1] == ' ') 
		 ret_ifnames[strlen(ret_ifnames)-1] = '\0';

	return ret_ifnames;	
}

int is_wl_if(char *ifname)
{
    int unit = 0;
    char nv[81];
    char word[64], *next = NULL;
    char word2[64], *next2 = NULL;
    char wlifnames[128];
    char vifnames[128];

    if (!ifname || strlen(ifname) <= 0)
        return 0;

    memset(wlifnames, 0, sizeof(wlifnames));
    strlcpy(wlifnames, nvram_safe_get("wl_ifnames"), sizeof(wlifnames));
    foreach (word, wlifnames, next) {
        SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
        if (!strncmp(word, ifname, strlen(ifname)))
            return 1;

        memset(nv, 0, sizeof(nv));
        snprintf(nv, sizeof(nv), "wl%d_vifnames", unit);
        memset(vifnames, 0, sizeof(vifnames));
        strlcpy(vifnames, nvram_safe_get(nv), sizeof(vifnames));
        foreach (word2, vifnames, next2) {
            if (!strncmp(word2, ifname, strlen(ifname)))
                return 1;
        }

        unit++;
    }

    return 0;
}

int check_apg_vif_type(json_object *wifiBandCapObj, unsigned short band, int subunit, unsigned long type) 
{
	json_object *root = NULL;
	json_object *bandType = NULL;
	json_object *vifObj = NULL;
	json_object *wlprefix = NULL;
	json_object *vifType = NULL;
	int unit = 0, sunit = 0;
	
	if (!wifiBandCapObj || band <= 0 || subunit <= 0)
		return 0;
	
	if (json_object_object_get_ex(wifiBandCapObj, "wifi_band", &root) == FALSE)
		return 0;
	
	json_object_object_foreach(root, k1, v1) {
		if (json_object_object_get_ex(v1, "band", &bandType) == FALSE) 
			continue;
		if ((json_object_get_int64(bandType) & band) != band) 
			continue;
		if (json_object_object_get_ex(v1, "vif", &vifObj) == FALSE)
			vifObj = NULL;
		break;
	}

	if (vifObj) {
		json_object_object_foreach(vifObj, k2, v2) {
			if (json_object_object_get_ex(v2, "prefix", &wlprefix) == FALSE)
				continue;
			unit = sunit = -1;
			sscanf(json_object_get_string(wlprefix), "wl%d.%d_%*s", &unit, &sunit);
			if (unit < 0 || sunit != subunit)
				continue;
			if (json_object_object_get_ex(v2, "type", &vifType) == FALSE)
				vifType = NULL;
			break;		
		}
	}

	return (vifType && ((json_object_get_int64(vifType) & type) == type)) ? 1 : 0;
}

unsigned long get_apg_vif_type(json_object *wifiBandCapObj, unsigned short band, int subunit) 
{
	json_object *root = NULL;
	json_object *bandType = NULL;
	json_object *vifObj = NULL;
	json_object *wlprefix = NULL;
	json_object *vifType = NULL;
	int unit = 0, sunit = 0;
	
	if (!wifiBandCapObj || band <= 0 || subunit <= 0)
		return 0;
	
	if (json_object_object_get_ex(wifiBandCapObj, "wifi_band", &root) == FALSE)
		return 0;
	
	json_object_object_foreach(root, k1, v1) {
		if (json_object_object_get_ex(v1, "band", &bandType) == FALSE) 
			continue;
		if ((json_object_get_int64(bandType) & band) != band) 
			continue;
		if (json_object_object_get_ex(v1, "vif", &vifObj) == FALSE)
			vifObj = NULL;
		break;
	}

	if (vifObj) {
		json_object_object_foreach(vifObj, k2, v2) {
			if (json_object_object_get_ex(v2, "prefix", &wlprefix) == FALSE)
				continue;
			unit = sunit = -1;
			sscanf(json_object_get_string(wlprefix), "wl%d.%d_%*s", &unit, &sunit);
			if (unit < 0 || sunit != subunit)
				continue;
			if (json_object_object_get_ex(v2, "type", &vifType) == FALSE)
				vifType = NULL;
			break;		
		}
	}	
	
	return (unsigned long) (vifType==NULL) ? 0 : json_object_get_int64(vifType);
}


int get_apg_vif_status(json_object *wifiBandCapObj, unsigned short wifi_band, int subunit, unsigned long *ret_status_bits)
{
	json_object *in = wifiBandCapObj;
	json_object *root = NULL;
	json_object *bandType = NULL;
	json_object *bandObj = NULL;
	json_object *vifObj = NULL;
	json_object *wlObj = NULL;
	json_object *wlprefix = NULL;
	json_object *vifStatus = NULL;
	int unit = 0, sunit = 0;

	if (ret_status_bits) 
		*(ret_status_bits) = 0;

	if (!wifiBandCapObj || !wifiBandCapObj || subunit <= 0)
		return -1;

	if (json_object_object_get_ex(in, "wifi_band", &root) == FALSE)
		return -1;

	json_object_object_foreach(root, k1, v1) {
		bandObj = v1;
		if (json_object_object_get_ex(bandObj, "band", &bandType) == FALSE)
			continue;
		if ((json_object_get_int64(bandType) & wifi_band) != wifi_band)
			continue;
		if (json_object_object_get_ex(bandObj, "vif", &vifObj) == FALSE)
			vifObj = NULL;
		break;	
	}
	if (!vifObj) {
		return -1;
	}

	json_object_object_foreach(vifObj, k2, v2) {
		wlObj = v2;
		if (json_object_object_get_ex(wlObj, "prefix", &wlprefix) == FALSE)
			continue;
		unit = sunit = -1;
		sscanf(json_object_get_string(wlprefix), "wl%d.%d_%*s", &unit, &sunit);
		if (unit < 0 || sunit != subunit)
			continue;
		if (json_object_object_get_ex(wlObj, "type", &vifStatus) == FALSE)
			vifStatus = NULL;
		break;
	}

	if (!vifStatus)
		return -1;

	if (ret_status_bits)
		*(ret_status_bits) = (unsigned long)json_object_get_int64(vifStatus);

	return 0;
}

json_object* gen_wifi_band_cap(json_object *root) 
{
	json_object *out = NULL;   
	json_object *wifiObj = NULL;
	json_object *bandObj = NULL; 
	json_object *vifObj = NULL; 
	json_object *ifaceObj = NULL;

	wifi_band_cap_st cap[MAX_BAND_CAP_LIST_SIZE], *p = NULL;
	struct _vif_cap *pp = NULL; 
	int i, j, total = 0;
	char str[64];

	if (!(out = root)) 
		return NULL; 

	if (!(wifiObj = json_object_new_object())) 
		return NULL;

	memset(cap, 0, (sizeof(wifi_band_cap_st)*MAX_BAND_CAP_LIST_SIZE));
	if (!get_wifi_band_cap(cap, MAX_BAND_CAP_LIST_SIZE, &total))
		return NULL;

	if (total <= 0)
		return NULL; 

    for (p=&cap[0], i=0; i<total; i++, p++) {
		if (!(bandObj = json_object_new_object()))
			continue;

		if (!(vifObj = json_object_new_object())) {
			json_object_put(bandObj);
			continue;
		}

		for (pp=&p->vif_cap[0], j=0; j<p->vif_count; j++, pp++) {
			if (!(ifaceObj = json_object_new_object()))
				continue;

			// type
			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "%d", pp->type);
			json_object_object_add(ifaceObj, "type", json_object_new_string(str));

			// prefix
			json_object_object_add(ifaceObj, "prefix", json_object_new_string(pp->prefix));

			//ifname
			//json_object_object_add(vifObj, pp->ifname, ifaceObj);
			json_object_object_add(vifObj, pp->prefix, ifaceObj);
		}

		if (p->vif_count > 0) {
			// band type
			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "%d", p->band_type);
			json_object_object_add(bandObj, "band", json_object_new_string(str));

			// vif count
			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "%d", p->vif_count);
			json_object_object_add(bandObj, "count", json_object_new_string(str));

			// add vif object to band object
			json_object_object_add(bandObj, "vif", vifObj);

			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "band%d", i+1);
			json_object_object_add(wifiObj, str, bandObj);
		}
		else {
			json_object_put(bandObj);
			json_object_put(vifObj);
		}
	}

	json_object_object_add(out, "wifi_band", wifiObj);
	return out;
}

json_object* gen_wan_port_cap(json_object *root) 
{
	json_object *out = NULL;
	json_object *wanportObj = NULL;
	json_object *ifaceObj = NULL;

	int i, total = 0;
	char str[128];
	eth_port_cap_st cap[MAX_ETH_CAP_LIST_SIZE], *p = NULL;
	
	if (!(out = root)) 
		return NULL;
	
	if (!(wanportObj = json_object_new_object()))
		return NULL;

	memset(cap, 0, (sizeof(eth_port_cap_st)*MAX_ETH_CAP_LIST_SIZE));
	if (!get_eth_port_cap(PHY_PORT_CAP_WAN, cap, MAX_ETH_CAP_LIST_SIZE, &total)) {
		json_object_put(wanportObj);
		return NULL;
	}
	
	if (total <= 0)
		return NULL; 

	for (p=&cap[0], i=0; i<total; i++, p++) {
		if (!(ifaceObj = json_object_new_object())) 
			continue;

		// index
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->index);
		json_object_object_add(ifaceObj, "index", json_object_new_string(str));

		// ifname
		json_object_object_add(ifaceObj, "ifname", json_object_new_string(p->ifname));

		// phy_port_id
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->phy_port_id);
		json_object_object_add(ifaceObj, "phy_port_id", json_object_new_string(str));

		// label_name
		json_object_object_add(ifaceObj, "label_name", json_object_new_string(p->label_name));

		// max_rate
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->max_rate);
		json_object_object_add(ifaceObj, "max_rate", json_object_new_string(str));

		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str)-1, "wan%d", p->index);
		json_object_object_add(wanportObj, str, ifaceObj);
	}

	json_object_object_add(out, "wan_port", wanportObj);
	return out;
}

json_object* gen_lan_port_cap(json_object *root) 
{
	json_object *out = NULL;
	json_object *lanportObj = NULL;
	json_object *ifaceObj = NULL;

	int i, total = 0;
	char str[128];
	eth_port_cap_st cap[MAX_ETH_CAP_LIST_SIZE], *p = NULL;

	if (!(out = root)) 
		return NULL;
	
	if (!(lanportObj = json_object_new_object()))
		return NULL;

	memset(cap, 0, (sizeof(eth_port_cap_st)*MAX_ETH_CAP_LIST_SIZE));
	if (!get_eth_port_cap(PHY_PORT_CAP_LAN, cap, MAX_ETH_CAP_LIST_SIZE, &total)) {
		json_object_put(lanportObj);
		return NULL;
	}
	
	if (total <= 0)
		return NULL; 

	for (p=&cap[0], i=0; i<total; i++, p++) {
		if (!(ifaceObj = json_object_new_object())) 
			continue;

		// index
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->index);
		json_object_object_add(ifaceObj, "index", json_object_new_string(str));

		// ifname
		json_object_object_add(ifaceObj, "ifname", json_object_new_string(p->ifname));

		// phy_port_id
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->phy_port_id);
		json_object_object_add(ifaceObj, "phy_port_id", json_object_new_string(str));

		// label_name
		json_object_object_add(ifaceObj, "label_name", json_object_new_string(p->label_name));

		// max_rate
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%d", p->max_rate);
		json_object_object_add(ifaceObj, "max_rate", json_object_new_string(str));
	
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str)-1, "lan%d", p->index);
		json_object_object_add(lanportObj, str, ifaceObj);
	}

	json_object_object_add(out, "lan_port", lanportObj);
	return out;

}

int update_apg_ifnames_used(int action, char *dut_mac, int sdn_vid, int sdn_idx, unsigned short wifi_band, char *ifname)
{
// action: 0:Del, 1:Add
    int remove_dut = 0;
    int remove_sdn = 0;
    int new_obj = 0;
    int found = 0;
	int i = 0;
	int arraylen = 0;
    json_object *root = NULL;
    json_object *ifusedObj = NULL;
    json_object *dutObj = NULL;
    json_object *sdnObj = NULL;
	json_object *bandObj = NULL;
	json_object *wifibandObj = NULL;
	json_object *prefixObj = NULL;
    json_object *ifnamesObj = NULL;
	json_object *sdn_vlanid = NULL;
	json_object *sdn_index = NULL;
	json_object *jvalObj = NULL;
	json_object *arrayObj = NULL;
    char ifnames[1025], wifi_band_str[33], sdn_vid_str[33], sdn_idx_str[33], str[133];
	char *s = NULL;
    char *ptr = NULL, *end = NULL;
    char word[64], *next = NULL;

    if (!dut_mac || strlen(dut_mac) <= 0)
        goto update_apg_ifnames_used_fail;

    if (action == 0) {
        if (!ifname || strlen(ifname) <= 0) {
            if (sdn_vid >= 0 && sdn_idx >= 0)
                remove_sdn = 1;
            else
                remove_dut = 1;
        }
    }
    else if (action == 1) {
        if (!ifname || strlen(ifname) <= 0)
            goto update_apg_ifnames_used_fail;
    }
    else {
        goto update_apg_ifnames_used_fail;
    }

    if ((root = json_object_from_file(APG_IFNAMES_USED_FILE))) {
        if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
            ifusedObj = NULL;
    }

    if (!ifusedObj) {
        if (action == 0)
            goto update_apg_ifnames_used_fail;
        else {
            new_obj = 1;
            ifusedObj = json_object_new_object();
            if (!root)
                root = json_object_new_object();
        }
    }

    memset(wifi_band_str, 0, sizeof(wifi_band_str));
    snprintf(wifi_band_str, sizeof(wifi_band_str), "%d", wifi_band);

    memset(sdn_vid_str, 0, sizeof(sdn_vid_str));
    snprintf(sdn_vid_str, sizeof(sdn_vid_str), "%d", sdn_vid);

	memset(sdn_idx_str, 0, sizeof(sdn_idx_str));
	snprintf(sdn_idx_str, sizeof(sdn_idx_str), "%d", sdn_idx);

    json_object_object_foreach(ifusedObj, k1, v1) {
        if (strcmp(k1, dut_mac) != 0)
            continue;
        dutObj = v1;
        break;
    }

	if (dutObj) {
		if (json_object_get_type(dutObj) == json_type_array) {
			arraylen = json_object_array_length(dutObj);
			if (action == 0 && (remove_dut == 1 || remove_sdn == 1)) {
				if (remove_dut == 1) 
					json_object_object_del(ifusedObj, dut_mac);
				else {
					if (arraylen <= 0)
						goto update_apg_ifnames_used_fail;
					else if (arraylen == 1) {
						if (!(sdnObj = json_object_array_get_idx(dutObj, 0)))
							goto update_apg_ifnames_used_fail;
						if (!(sdn_vlanid = json_object_object_get(sdnObj, "sdn_vid")) || !(sdn_index = json_object_object_get(sdnObj, "sdn_idx")))
							goto update_apg_ifnames_used_fail;
						if (json_object_get_int(sdn_vlanid) != sdn_vid || json_object_get_int(sdn_index) != sdn_idx)
							goto update_apg_ifnames_used_fail;
						json_object_object_del(ifusedObj, dut_mac);
					}
					else {
						if (!(arrayObj = json_object_new_array()))
							goto update_apg_ifnames_used_fail;
						else {
							for (i=0; i<arraylen; i++) {
								if (!(sdnObj = json_object_array_get_idx(dutObj, i))) 
									continue;
								if (!(sdn_vlanid = json_object_object_get(sdnObj, "sdn_vid")) || !(sdn_index = json_object_object_get(sdnObj, "sdn_idx")))
									continue;
								if (json_object_get_int(sdn_vlanid) == sdn_vid && json_object_get_int(sdn_index) == sdn_idx)
									continue;
								json_object_array_add(arrayObj, json_tokener_parse(json_object_to_json_string(sdnObj)));
							}
							if (json_object_array_length(arrayObj) <= 0)
								json_object_put(arrayObj);
							else
								json_object_object_add(ifusedObj, dut_mac, arrayObj);
						}
 					}
				}
			}
			else {
				for (i=0; i<arraylen; i++) {
					if (!(sdnObj = json_object_array_get_idx(dutObj, i))) 
						continue;
					if (!(sdn_vlanid = json_object_object_get(sdnObj, "sdn_vid")) || !(sdn_index = json_object_object_get(sdnObj, "sdn_idx"))) {
						sdnObj = NULL;
						continue;
					}
					if (json_object_get_int(sdn_vlanid) != sdn_vid || json_object_get_int(sdn_index) != sdn_idx) {
						sdnObj = NULL;
						continue;
					}
					break;
				}

				if (sdnObj) {
					bandObj = json_object_object_get(sdnObj, "sdn_band");
					if (bandObj && json_object_get_type(bandObj) == json_type_array && (arraylen = json_object_array_length(bandObj)) > 0) {
						for (i=0; i<arraylen; i++) {
							if (!(wifibandObj = json_object_array_get_idx(bandObj, i))) 
								continue;
							if ((jvalObj = json_object_object_get(wifibandObj, "band_idx")) && json_object_get_int(jvalObj) == wifi_band)
								break;
							else 
								wifibandObj = NULL;
						}
						if (wifibandObj) {			
							if ((prefixObj = json_object_object_get(wifibandObj, "wl_prefix"))) {
								if (action == 1) {
									if (strcmp(json_object_get_string(prefixObj), ifname) != 0) {
										memset(str, 0, sizeof(str));
										s = get_wificap_ifname_from_wlprefix(dut_mac, ifname, str, sizeof(str)-1);
										json_object_object_add(wifibandObj, "wl_prefix", json_object_new_string(ifname));
										json_object_object_add(wifibandObj, "wl_ifname", json_object_new_string((s==NULL)?"":s));
									}
								}
								else {
									if (strcmp(json_object_get_string(prefixObj), ifname) == 0) {
										if (!(arrayObj = json_object_new_array()))
											goto update_apg_ifnames_used_fail;
										else {
											if (json_object_array_length(bandObj) > 0) {
												if (json_object_array_length(bandObj) == 1) {
													if (!(arrayObj = json_object_new_array()))
														goto update_apg_ifnames_used_fail;
													else {
														for (i=0; i<arraylen; i++) {
															if (!(sdnObj = json_object_array_get_idx(dutObj, i))) 
																continue;
															if (!(sdn_vlanid = json_object_object_get(sdnObj, "sdn_vid")) || !(sdn_index = json_object_object_get(sdnObj, "sdn_idx")))
																continue;
															if (json_object_get_int(sdn_vlanid) == sdn_vid && json_object_get_int(sdn_index) == sdn_idx)
																continue;
															json_object_array_add(arrayObj, json_tokener_parse(json_object_to_json_string(sdnObj)));
														}
														if (json_object_array_length(arrayObj) <= 0)
															json_object_put(arrayObj);
														else
															json_object_object_add(ifusedObj, dut_mac, arrayObj);
													}
												}
												else {
													for (i=0; i<json_object_array_length(bandObj); i++) {
														if (!(wifibandObj = json_object_array_get_idx(bandObj, i)))
															continue;
														if ((jvalObj = json_object_object_get(wifibandObj, "band_idx")) && json_object_get_int(jvalObj) == wifi_band)
															continue;
														json_object_array_add(arrayObj, json_tokener_parse(json_object_to_json_string(wifibandObj)));
													}
													if (json_object_array_length(arrayObj) > 0)
														json_object_object_add(sdnObj, "sdn_band", arrayObj);
													else 
														json_object_put(arrayObj);
												}
											}
										}
									}
								}
							}
						}
						
						else {
							if (action == 0)
								goto update_apg_ifnames_used_fail;
							else {
								if (!(wifibandObj = json_object_new_object()))
									goto update_apg_ifnames_used_fail;
								else {
									memset(str, 0, sizeof(str));
									s = get_wificap_ifname_from_wlprefix(dut_mac, ifname, str, sizeof(str)-1);
									json_object_object_add(wifibandObj, "band_idx", json_object_new_string(wifi_band_str));
									json_object_object_add(wifibandObj, "wl_prefix", json_object_new_string(ifname));
									json_object_object_add(wifibandObj, "wl_ifname", json_object_new_string((s==NULL)?"":s));
									json_object_array_add(bandObj, wifibandObj);
								}
							}				
						}
				   	}
					else {
						if (action == 0)
							goto update_apg_ifnames_used_fail;
						else {
							if ((bandObj = json_object_new_array()) && (wifibandObj = json_object_new_object())) {
								memset(str, 0, sizeof(str));
								s = get_wificap_ifname_from_wlprefix(dut_mac, ifname, str, sizeof(str)-1);
								json_object_object_add(wifibandObj, "band_idx", json_object_new_string(wifi_band_str));
								json_object_object_add(wifibandObj, "wl_prefix", json_object_new_string(ifname));
								json_object_object_add(wifibandObj, "wl_ifname", json_object_new_string((s==NULL)?"":s));
								json_object_array_add(bandObj, wifibandObj);
								json_object_object_add(sdnObj, "sdn_band", bandObj);
							}
							else {
								if (bandObj) json_object_put(bandObj);
								if (wifibandObj) json_object_put(wifibandObj);
								goto update_apg_ifnames_used_fail;
							}
						}
					} 					
				}
				else {
					if (action == 0)
						goto update_apg_ifnames_used_fail;
					else {
						if ((sdnObj = json_object_new_object()) && (bandObj = json_object_new_array()) && (wifibandObj = json_object_new_object())) {
							memset(str, 0, sizeof(str));
							s = get_wificap_ifname_from_wlprefix(dut_mac, ifname, str, sizeof(str)-1); 
							json_object_object_add(wifibandObj, "band_idx", json_object_new_string(wifi_band_str));
							json_object_object_add(wifibandObj, "wl_prefix", json_object_new_string(ifname));
							json_object_object_add(wifibandObj, "wl_ifname", json_object_new_string((s==NULL)?"":s));
							json_object_array_add(bandObj, wifibandObj);
							json_object_object_add(sdnObj, "sdn_idx", json_object_new_string(sdn_idx_str));
							json_object_object_add(sdnObj, "sdn_vid", json_object_new_string(sdn_vid_str));
							json_object_object_add(sdnObj, "sdn_band", bandObj);
							json_object_array_add(dutObj, sdnObj);
						}
						else {
							if (bandObj) json_object_put(bandObj);
							if (wifibandObj) json_object_put(wifibandObj);
							if (sdnObj) json_object_put(sdnObj);
							goto update_apg_ifnames_used_fail;
						}
					}
				}
			}
		}
		else {
			goto update_apg_ifnames_used_fail;
		}
	}
	else {
		if (action == 0)
			goto update_apg_ifnames_used_fail;
		else {
			if ((dutObj = json_object_new_array()) && (sdnObj = json_object_new_object()) && (bandObj = json_object_new_array()) && (wifibandObj = json_object_new_object())) {
				memset(str, 0, sizeof(str));
				s = get_wificap_ifname_from_wlprefix(dut_mac, ifname, str, sizeof(str)-1);
				json_object_object_add(wifibandObj, "band_idx", json_object_new_string(wifi_band_str));
				json_object_object_add(wifibandObj, "wl_prefix", json_object_new_string(ifname));
				json_object_object_add(wifibandObj, "wl_ifname", json_object_new_string((s==NULL)?"":s));
				json_object_array_add(bandObj, wifibandObj);
				json_object_object_add(sdnObj, "sdn_idx", json_object_new_string(sdn_idx_str));
				json_object_object_add(sdnObj, "sdn_vid", json_object_new_string(sdn_vid_str));
				json_object_object_add(sdnObj, "sdn_band", bandObj);
				json_object_array_add(dutObj, sdnObj);
				json_object_object_add(ifusedObj, dut_mac, dutObj);
			}
			else {
				if (bandObj) json_object_put(bandObj);
				if (wifibandObj) json_object_put(wifibandObj);
				if (sdnObj) json_object_put(sdnObj);
				if (dutObj) json_object_put(dutObj);
				goto update_apg_ifnames_used_fail;
			}
		}
	}

	if (new_obj) 
		json_object_object_add(root, "vif_used", ifusedObj);

    json_object_to_file(APG_IFNAMES_USED_FILE, root);
	json_object_put(root);
    return 0;

update_apg_ifnames_used_fail:
    if (root) json_object_put(root);
	if (new_obj == 1 && ifusedObj) json_object_put(ifusedObj);
    return -1;
}

char* get_wificap_ifname_from_wlprefix(char *dut_mac, char *wlprefix, char *ret_ifname, size_t ifname_bsize)
{
	json_object *in = NULL;
	json_object *wifiBandCapObj = NULL;
	json_object *root = NULL;
	json_object *vifObj = NULL;
	json_object *prefixObj = NULL;
	char *str = NULL;
	char filePath[64];
	char s[81];
	int found = 0;

	if (!dut_mac || strlen(dut_mac) <= 0)
		goto get_wificap_ifname_from_wlprefix_fail;

	if (!ret_ifname || ifname_bsize <= 0)
		goto get_wificap_ifname_from_wlprefix_fail;

	memset(ret_ifname, 0, ifname_bsize);
	if (!strcmp(dut_mac, get_own_mac())) {
		if (!(in = json_object_new_object())) 
			goto get_wificap_ifname_from_wlprefix_fail;

		if (!(wifiBandCapObj = json_object_new_object())) 
			goto get_wificap_ifname_from_wlprefix_fail;

		if (!gen_wifi_band_cap(wifiBandCapObj)) {
			json_object_put(wifiBandCapObj);
			goto get_wificap_ifname_from_wlprefix_fail;
		}
		
		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s)-1, "%d", WIFI_BAND_CAP);
		json_object_object_add(in, s, wifiBandCapObj);
	}
	else {
		memset(filePath, 0, sizeof(filePath));
		snprintf(filePath, sizeof(filePath), "%s/%s.cap", TEMP_ROOT_PATH, dut_mac);

		if (!(in = json_object_from_file(filePath)))
			goto get_wificap_ifname_from_wlprefix_fail;

		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s), "%d", WIFI_BAND_CAP);
		if (json_object_object_get_ex(in, s, &wifiBandCapObj) == FALSE) 
			goto get_wificap_ifname_from_wlprefix_fail;
	}

	if (json_object_object_get_ex(wifiBandCapObj, "wifi_band", &root) == FALSE)
		goto get_wificap_ifname_from_wlprefix_fail;

	json_object_object_foreach(root, k1, v1) {
		if (json_object_object_get_ex(v1, "vif", &vifObj) == FALSE) 
			continue;
		if (!vifObj) 
			continue;
		found = 0;
		json_object_object_foreach(vifObj, k2, v2) {
			if (json_object_object_get_ex(v2, "prefix", &prefixObj) == FALSE)
				continue;
			if (!(str = json_object_get_string(prefixObj)))
				continue;
			if ((found = (strcmp(str, wlprefix)==0))) {
				strlcpy(ret_ifname, k2, ifname_bsize);
				break;
			}
		}
	
		if (found)
			break;
	}

	json_object_put(in);
	return (strlen(ret_ifname) > 0) ? ret_ifname : NULL;

get_wificap_ifname_from_wlprefix_fail:
	if (in) json_object_put(in);
	return NULL;
}

char* get_lancap_ifname_from_portindex(char *dut_mac, int port_index, char *ret_ifname, size_t ifname_bsize)
{
	json_object *in = NULL;
	json_object *lanCapObj = NULL;
	json_object *root = NULL;
	json_object *lanInfoObj = NULL;
	json_object *portIdxObj = NULL;
	json_object *ifnameObj = NULL;
	char *str = NULL;
	char filePath[64];
	char s[81];
	int found = 0;

	if (!dut_mac || strlen(dut_mac) <= 0)
		goto get_lancap_ifname_from_portindex_fail;

	if (!ret_ifname || ifname_bsize <= 0)
		goto get_lancap_ifname_from_portindex_fail;

	memset(ret_ifname, 0, ifname_bsize);
	if (!strcmp(dut_mac, get_own_mac())) {
		if (!(in = json_object_new_object())) 
			goto get_lancap_ifname_from_portindex_fail;

		if (!(lanCapObj = json_object_new_object())) 
			goto get_lancap_ifname_from_portindex_fail;

		if (!gen_lan_port_cap(lanCapObj)) {
			json_object_put(lanCapObj);
			goto get_lancap_ifname_from_portindex_fail;
		}
		
		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s)-1, "%d", LAN_PORT_CAP);
		json_object_object_add(in, s, lanCapObj);
	}
	else {
		memset(filePath, 0, sizeof(filePath));
		snprintf(filePath, sizeof(filePath), "%s/%s.cap", TEMP_ROOT_PATH, dut_mac);
		if (!(in = json_object_from_file(filePath)))
			goto get_lancap_ifname_from_portindex_fail;

		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s), "%d", LAN_PORT_CAP);
		if (json_object_object_get_ex(in, s, &lanCapObj) == FALSE) 
			goto get_lancap_ifname_from_portindex_fail;
	}

	if (json_object_object_get_ex(lanCapObj, "lan_port", &root) == FALSE)
		goto get_lancap_ifname_from_portindex_fail;

	json_object_object_foreach(root, k1, v1) {
		lanInfoObj = v1;
		if (json_object_object_get_ex(lanInfoObj, "index", &portIdxObj) == FALSE)
			continue;
		if (portIdxObj == NULL) 
			continue;
		if (json_object_get_int(portIdxObj) != port_index)
			continue;
		if (json_object_object_get_ex(lanInfoObj, "ifname", &ifnameObj) == FALSE)
			continue;
		if (ifnameObj == NULL)
			continue;
		if (!(str = json_object_get_string(ifnameObj)))
			continue;
		strlcpy(ret_ifname, str, ifname_bsize);
		found = 1;
		break;
	}

	json_object_put(in);
	return (found==1) ? ret_ifname : NULL;

get_lancap_ifname_from_portindex_fail:
	if (in) json_object_put(in);
	return NULL;
}

char* get_wificap_ifnames(char *dut_mac, unsigned short wifi_band, unsigned long type, char *ret_ifnames, size_t ifnames_bsize, int get_prefix) 
{
	json_object *in = NULL;
	json_object *wifiBandCapObj = NULL;
	json_object *root = NULL;
	json_object *bandType = NULL;
	json_object *bandObj = NULL;
	json_object *vifObj = NULL;
	json_object *vifStatus = NULL;
	json_object *prefixObj = NULL;
	char *ptr = NULL;
	char *end = NULL;
	char *str = NULL;
	char filePath[64];
	char s[81];
	int prefix = 0;

	if (!ret_ifnames || ifnames_bsize <= 0)
		goto get_wifi_band_cap_ifnames_fail;

	memset(ret_ifnames, 0, ifnames_bsize);
	ptr = &ret_ifnames[0];
	end = ptr + ifnames_bsize;

	if (!dut_mac || strlen(dut_mac) <= 0)
		goto get_wifi_band_cap_ifnames_fail;

	prefix = (get_prefix==1) ? 1 : 0;
	if (!strcmp(dut_mac, get_own_mac())) {
		if (!(in = json_object_new_object())) 
			goto get_wifi_band_cap_ifnames_fail;

		if (!(wifiBandCapObj = json_object_new_object())) 
			goto get_wifi_band_cap_ifnames_fail;

		if (!gen_wifi_band_cap(wifiBandCapObj)) {
			json_object_put(wifiBandCapObj);
			goto get_wifi_band_cap_ifnames_fail;
		}
		
		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s)-1, "%d", WIFI_BAND_CAP);
		json_object_object_add(in, s, wifiBandCapObj);
	}
	else {
		memset(filePath, 0, sizeof(filePath));
		snprintf(filePath, sizeof(filePath), "%s/%s.cap", TEMP_ROOT_PATH, dut_mac);
		if (!(in = json_object_from_file(filePath)))
			goto get_wifi_band_cap_ifnames_fail;

		memset(s, 0, sizeof(s));
		snprintf(s, sizeof(s), "%d", WIFI_BAND_CAP);
		if (json_object_object_get_ex(in, s, &wifiBandCapObj) == FALSE) 
			goto get_wifi_band_cap_ifnames_fail;
	}

	if (json_object_object_get_ex(wifiBandCapObj, "wifi_band", &root) == FALSE)
		goto get_wifi_band_cap_ifnames_fail;

	json_object_object_foreach(root, k1, v1) {
		bandObj = v1;
		if (json_object_object_get_ex(bandObj, "band", &bandType) == FALSE)
			continue;
		if ((json_object_get_int64(bandType) & wifi_band) != wifi_band)
			continue;
		if (json_object_object_get_ex(bandObj, "vif", &vifObj) == FALSE)
			vifObj = NULL;
		break;
	}

	if (!vifObj)
		goto get_wifi_band_cap_ifnames_fail;

	json_object_object_foreach(vifObj, k2, v2) {
		if (json_object_object_get_ex(v2, "type", &vifStatus) == FALSE)
			continue;
		if ((unsigned long)json_object_get_int64(vifStatus) != type)
			continue;
		if (!prefix)
			str = k2;
		else {
			if (json_object_object_get_ex(v2, "prefix", &prefixObj) == FALSE)
				continue;
			str = json_object_get_string(prefixObj);
		} 

		if (!str) 
			continue;

		ptr += snprintf(ptr, end-ptr, "%s ", str);
	}

	if (strlen(ret_ifnames) > 0 && ret_ifnames[strlen(ret_ifnames)-1] == ' ')
		ret_ifnames[strlen(ret_ifnames)-1] = '\0';

	json_object_put(in);
	return (strlen(ret_ifnames) > 0) ? ret_ifnames : NULL;

get_wifi_band_cap_ifnames_fail:
	if (in) json_object_put(in);
	return NULL;
}

char* get_wificap_all_ifnames(char *dut_mac, unsigned long type, char *ret_ifnames, size_t ifnames_bsize, int get_prefix)
{
	int i;
	char *ptr = NULL;
	char *end = NULL;
	char ifnames[513];

	if (!dut_mac || strlen(dut_mac) <= 0 || !ret_ifnames || ifnames_bsize <= 0)
		return NULL;

	memset(ret_ifnames, 0, ifnames_bsize);
	ptr = &ret_ifnames[0];
	end = ptr + ifnames_bsize;

	for (i=0; i<WIFI_BAND_ARRAY_SIZE; i++) {
		memset(ifnames, 0, sizeof(ifnames));
		if (get_wificap_ifnames(dut_mac, WIFI_BAND_ARRAY[i], type, ifnames, sizeof(ifnames)-1, get_prefix))
			ptr += snprintf(ptr, end-ptr, "%s ", ifnames);
	}

	if (strlen(ret_ifnames) > 0 && ret_ifnames[strlen(ret_ifnames)-1] == ' ')
		ret_ifnames[strlen(ret_ifnames)-1] = '\0';

	return (strlen(ret_ifnames) > 0) ? ret_ifnames : NULL;
}

char *get_used_vid_by_dut_mac(char *dut_mac, char *ret_buffer, size_t buffer_size) 
{
    json_object *root = NULL;
    json_object *ifusedObj = NULL;
    json_object *dutObj = NULL;
	json_object *sdnObj = NULL;
	json_object *sdnVidObj = NULL;
	json_object *sdnIdxObj = NULL;

	char *ptr = NULL;
	char *end = NULL;

	int arraylen = 0;
	int i;

	if (!ret_buffer || buffer_size <= 0) 
		goto get_vid_used_by_dut_mac_fail;
	else {
		memset(ret_buffer, 0, buffer_size);
		ptr = &ret_buffer[0];
		end = ptr + buffer_size;
	}

    if (!dut_mac || strlen(dut_mac) <= 0)
        goto get_vid_used_by_dut_mac_fail;
    
    if (!(root = json_object_from_file(APG_IFNAMES_USED_FILE)))
        goto get_vid_used_by_dut_mac_fail;
    
    if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
        goto get_vid_used_by_dut_mac_fail;
    
    if (!ifusedObj)
        goto get_vid_used_by_dut_mac_fail;

    json_object_object_foreach(ifusedObj, k1, v1) {
        if (strcmp(k1, dut_mac) != 0)
            continue;
        dutObj = v1;
        break;
    }

	if (!dutObj || json_object_get_type(dutObj) != json_type_array || (arraylen = json_object_array_length(dutObj)) <= 0)
        goto get_vid_used_by_dut_mac_fail;

	for (i=0; i<arraylen; i++) {
		if (!(sdnObj = json_object_array_get_idx(dutObj, i)))
			continue;
		if (!(sdnVidObj = json_object_object_get(sdnObj, "sdn_vid")))
			continue;
		if (!(sdnIdxObj = json_object_object_get(sdnObj, "sdn_idx")))
			continue;
		ptr += snprintf(ptr, end-ptr, "%d,%d ", json_object_get_int(sdnVidObj), json_object_get_int(sdnIdxObj));
	}

    if (strlen(ret_buffer) > 0 && ret_buffer[strlen(ret_buffer)-1] == ' ')
        ret_buffer[strlen(ret_buffer)-1] = '\0';

    json_object_put(root);
    return strlen(ret_buffer) > 0 ? ret_buffer : NULL;

get_vid_used_by_dut_mac_fail:
    if (root) json_object_put(root);
    return NULL;
}

char *get_ifnames_used_by_sdn_vid(char *dut_mac, int sdn_vid, int sdn_idx, char *ret_ifnames, size_t ifnames_bsize)
{
	json_object *root = NULL;
	json_object *ifusedObj = NULL;
	json_object *dutObj = NULL;
	json_object *sdnObj = NULL;
	json_object *sdnBandObj = NULL;
	json_object *sdnVidObj = NULL;
	json_object *sdnIdxObj = NULL;
	json_object *wlprefixObj = NULL;
	json_object *jsonObj = NULL;

	char *ptr = NULL;
	char *end = NULL;
	char *p = NULL;

	int arraylen = 0;
	int i=0;
	int sdnBandArrayLen = 0;

	if (!ret_ifnames || ifnames_bsize <= 0)
		goto get_ifnames_used_by_sdn_vid_fail;
	else {
		memset(ret_ifnames, 0, ifnames_bsize);
		ptr = &ret_ifnames[0];
		end = ptr + ifnames_bsize;
	}

	if (!dut_mac || strlen(dut_mac) <= 0)
		goto get_ifnames_used_by_sdn_vid_fail;

	if (!(root = json_object_from_file(APG_IFNAMES_USED_FILE)))
		goto get_ifnames_used_by_sdn_vid_fail;

	if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
		goto get_ifnames_used_by_sdn_vid_fail;

	if (!ifusedObj)
		goto get_ifnames_used_by_sdn_vid_fail;

	json_object_object_foreach(ifusedObj, k1, v1) {
		if (strcmp(k1, dut_mac) != 0)
			continue;
		dutObj = v1;
		break;
	}

	if (!dutObj || json_object_get_type(dutObj) != json_type_array || (arraylen = json_object_array_length(dutObj)) <= 0)
		goto get_ifnames_used_by_sdn_vid_fail;

	for (i=0; i<arraylen; i++) {
		if (!(sdnObj = json_object_array_get_idx(dutObj, i)))
			continue;
		if (!(sdnVidObj = json_object_object_get(sdnObj, "sdn_vid")) || !(sdnIdxObj = json_object_object_get(sdnObj, "sdn_idx"))) {
			sdnObj = NULL;
			continue;
		}
		if (json_object_get_int(sdnVidObj) != sdn_vid || json_object_get_int(sdnIdxObj) != sdn_idx) {
			sdnObj = NULL;
			continue;
		}
		break;
	}

	if (!sdnObj)
		goto get_ifnames_used_by_sdn_vid_fail;

	if (!(sdnBandObj = json_object_object_get(sdnObj, "sdn_band")) || json_object_get_type(sdnBandObj) != json_type_array || (sdnBandArrayLen = json_object_array_length(sdnBandObj)) <= 0)
		goto get_ifnames_used_by_sdn_vid_fail;

	for (i=0; i<sdnBandArrayLen; i++) {
		if (!(jsonObj = json_object_array_get_idx(sdnBandObj, i)))
			continue;
		if (!(wlprefixObj = json_object_object_get(jsonObj, "wl_prefix")))
			continue;
		if (!(p = json_object_get_string(wlprefixObj)))
			continue;
		ptr += snprintf(ptr, end-ptr, "%s ", p);
	}

	if (strlen(ret_ifnames) > 0 && ret_ifnames[strlen(ret_ifnames)-1] == ' ')
		ret_ifnames[strlen(ret_ifnames)-1] = '\0';

	json_object_put(root);
	return strlen(ret_ifnames) > 0 ? ret_ifnames : NULL;

get_ifnames_used_by_sdn_vid_fail:
	if (root) json_object_put(root);
	return NULL;
}

int get_sdn_vid_by_ifname_used(char *dut_mac, char *ifname)
{
	json_object *root = NULL;
	json_object *ifusedObj = NULL;
	json_object *dutObj = NULL;
	json_object *sdnObj = NULL;
	json_object *ifnamesObj = NULL;
	
	json_object *sdnVidObj = NULL;
	json_object *sdnBandObj = NULL;
	json_object *bandObj = NULL;
	json_object *wlprefixObj = NULL;

	char word[64];
	char *next = NULL;

	int sdn_vid = -1;
	int found = 0;
	int arraylen = 0;
	int sdnBandArraylen = 0;
	int i, j;


	if (!dut_mac || strlen(dut_mac) <= 0)
		goto get_sdn_vid_by_ifname_used_exit;

	if (!ifname || strlen(ifname) <= 0)
		goto get_sdn_vid_by_ifname_used_exit;

	if (!(root = json_object_from_file(APG_IFNAMES_USED_FILE)))
		goto get_sdn_vid_by_ifname_used_exit;

	if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
		goto get_sdn_vid_by_ifname_used_exit;

	if (!ifusedObj)
		goto get_sdn_vid_by_ifname_used_exit;

	json_object_object_foreach(ifusedObj, k1, v1) {
		if (strcmp(k1, dut_mac) != 0)
			continue;
		dutObj = v1;
		break;
	}

	if (!dutObj || json_object_get_type(dutObj) != json_type_array || (arraylen = json_object_array_length(dutObj)) <= 0)
		goto get_sdn_vid_by_ifname_used_exit;

	for (i=0; i<arraylen; i++) {
		if (!(sdnObj = json_object_array_get_idx(dutObj, i)))
			continue;
		if (!(sdnVidObj = json_object_object_get(sdnObj, "sdn_vid")))
			continue;
		if (!(sdnBandObj = json_object_object_get(sdnObj, "sdn_band")) || json_object_get_type(sdnBandObj) != json_type_array || (sdnBandArraylen = json_object_array_length(sdnBandObj)) <= 0)
			continue;
		for (j=0; j<sdnBandArraylen; j++) {
			if (!(bandObj = json_object_array_get_idx(sdnBandObj, j)))
				continue;
			if (!(wlprefixObj = json_object_object_get(bandObj, "wl_prefix")))
				continue;
			if ((found = strcmp(json_object_get_string(wlprefixObj), ifname)==0)) {
				sdn_vid = json_object_get_int(sdnVidObj);
				break;
			}
		}

		if (found)
			break;
	}

	json_object_put(root);
	return sdn_vid;

get_sdn_vid_by_ifname_used_exit:
	if (root)
		json_object_put(root);
	return -1;
}

char* get_unused_ifname_by_dut(char *dut_mac, unsigned short wifi_band, char *ret_ifname, size_t ret_ifname_bsize)
{
	int i;
	char ifnames[512];
	char word[64], *next = NULL;
	
	if (!dut_mac || strlen(dut_mac) <= 0)
		return NULL;

	if (ret_ifname && ret_ifname_bsize > 0)
		memset(ret_ifname, 0, ret_ifname_bsize);
	else 
		return NULL;

	memset(ifnames, 0, sizeof(ifnames));
	if (!get_wificap_ifnames(dut_mac, wifi_band, VIF_TYPE_NO_USED, ifnames, sizeof(ifnames)-1, 0))
		return NULL;

	foreach (word, ifnames, next) {
		if (get_sdn_vid_by_ifname_used(dut_mac, word) < 0) {
			strlcpy(ret_ifname, word, ret_ifname_bsize);
			break;
		}
	}
			
	return (strlen(ret_ifname) > 0) ? ret_ifname : NULL;
}


int num_of_no_used_vif_from_wificap(char *dut_mac, unsigned short wifi_band)
{
	char ifnames[513];
	char word[64];
	char *next;
	int result = 0;

	memset(ifnames, 0, sizeof(ifnames));
	if (!get_wificap_ifnames(dut_mac, wifi_band, VIF_TYPE_NO_USED, ifnames, sizeof(ifnames)-1, 0))
		return 0;

	foreach (word, ifnames, next)
		result++;

	return result;
}

char* get_ifname_used_by_band(char *dut_mac, int sdn_vid, int sdn_idx, unsigned short wifi_band, char *ret_ifname, size_t ret_ifname_bsize) 
{
	json_object *root = NULL;
	json_object *ifusedObj = NULL;
	json_object *dutObj = NULL;
	json_object *sdnObj = NULL;
	json_object *ifnamesObj = NULL;

	json_object *jsonObj = NULL;
	json_object *bandIdxObj = NULL;
	json_object *sdnBandObj = NULL;
	json_object *sdnVidObj = NULL;
	json_object *sdnIdxObj = NULL;
	json_object *wlprefixObj = NULL;

	int found = 0;
	int i;
	int dutArrayLen = 0;
	int sdnBandArrayLen = 0;

	char *p = NULL;

	if (!dut_mac || strlen(dut_mac) <= 0)
		return NULL;

	if (!ret_ifname || ret_ifname_bsize <= 0)
		return NULL;

	memset(ret_ifname, 0, ret_ifname_bsize);
	if (!(root = json_object_from_file(APG_IFNAMES_USED_FILE)))
		goto get_ifname_used_by_band_exit;

	if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
		goto get_ifname_used_by_band_exit;

	if (!ifusedObj)
		goto get_ifname_used_by_band_exit;

	json_object_object_foreach(ifusedObj, k1, v1) {
		if (strcmp(k1, dut_mac) != 0)
			continue;
		dutObj = v1;
		break;
	}

	if (!dutObj || json_object_get_type(dutObj) != json_type_array || (dutArrayLen = json_object_array_length(dutObj)) <= 0)
		goto get_ifname_used_by_band_exit;

	for (i=0; i<dutArrayLen; i++) {
		if (!(sdnObj = json_object_array_get_idx(dutObj, i)))
			continue;
		if (!(sdnVidObj = json_object_object_get(sdnObj, "sdn_vid")) || !(sdnIdxObj = json_object_object_get(sdnObj, "sdn_idx"))) {
			sdnObj = NULL;
			continue;
		}
		if (json_object_get_int(sdnVidObj) != sdn_vid || json_object_get_int(sdnIdxObj) != sdn_idx) {
			sdnObj = NULL;
			continue;
		}
		break;
	}

	if (!sdnObj)
		goto get_ifname_used_by_band_exit;

	if (!(sdnBandObj = json_object_object_get(sdnObj, "sdn_band")) || json_object_get_type(sdnBandObj) != json_type_array || (sdnBandArrayLen = json_object_array_length(sdnBandObj)) <= 0)
		goto get_ifname_used_by_band_exit;

	for (i=0; i<sdnBandArrayLen; i++) {
		if (!(jsonObj = json_object_array_get_idx(sdnBandObj, i)))
			continue;
		if (!(bandIdxObj = json_object_object_get(jsonObj, "band_idx")) || json_object_get_int(bandIdxObj) != wifi_band)
			continue;
		if (!(wlprefixObj = json_object_object_get(jsonObj, "wl_prefix")))
			continue;
		if (!(p = json_object_get_string(wlprefixObj)))
			continue;
		strlcpy(ret_ifname, p, ret_ifname_bsize);
		found = 1;
		break;
	}
	json_object_put(root);
	return (!found) ? NULL : ret_ifname;

get_ifname_used_by_band_exit:
	if (root) json_object_put(root);
	return NULL;
}

unsigned short get_wifi_band_for_wgn(char *dut_mac) 
{
	unsigned short result = 0;
   	int total = 0;
   	int i, j;
	
	char apg_value[512];
   	char nv[81];
   	struct _dutlist_t dutlist[MAX_DUT_LIST_SIZE];
	apg_rule_st apg_rule, *p_apg_rule = NULL;

   	if (!dut_mac || strlen(dut_mac) <= 0)
       	return 0;

	for (i=0; i<APG_MAXINUM; i++) {
       	if (!get_mtlan_enable_by_idx(i)) continue;
       	memset(nv, 0, sizeof(nv));
       	snprintf(nv, sizeof(nv), NV_APG_X_ENABLE, i);
       	if (nvram_get_int(nv) == 0) continue;
		memset(&apg_rule, 0, sizeof(apg_rule));
		if (!(p_apg_rule = get_apg_rule_by_idx(i, &apg_rule))) continue;
       	memset(dutlist, 0, (sizeof(struct _dutlist_t) * MAX_DUT_LIST_SIZE));
       	if (!get_apg_dutlist(i, dutlist, MAX_DUT_LIST_SIZE, &total) || total <= 0) continue;
		for (j=0; j<total; j++) {
			if (strcmp(dutlist[j].mac, dut_mac) == 0) {
				if ((dutlist[j].wifi_band & WIFI_BAND_2G) == WIFI_BAND_2G && (result & WIFI_BAND_2G) == 0) {
					memset(apg_value, 0, sizeof(apg_value));
					if (get_apg_value(p_apg_rule, WIFI_BAND_2G, "auth_mode_x", apg_value, sizeof(apg_value)-1) && is_wgn_auth_mode_supported(apg_value))				
						result |= WIFI_BAND_2G;
				}
				else if ((dutlist[j].wifi_band & WIFI_BAND_5G) == WIFI_BAND_5G && (result & WIFI_BAND_5G) == 0) {
					memset(apg_value, 0, sizeof(apg_value));
					if (get_apg_value(p_apg_rule, WIFI_BAND_5G, "auth_mode_x", apg_value, sizeof(apg_value)-1) && is_wgn_auth_mode_supported(apg_value))				
						result |= WIFI_BAND_5G;
				}
				else if ((dutlist[j].wifi_band & WIFI_BAND_5GL) == WIFI_BAND_5GL && (result & WIFI_BAND_5GL) == 0) {
					memset(apg_value, 0, sizeof(apg_value));
					if (get_apg_value(p_apg_rule, WIFI_BAND_5GL, "auth_mode_x", apg_value, sizeof(apg_value)-1) && is_wgn_auth_mode_supported(apg_value))				
						result |= WIFI_BAND_5GL;
				}
				else if ((dutlist[j].wifi_band & WIFI_BAND_5GH) == WIFI_BAND_5GH && (result & WIFI_BAND_5GH) == 0) {
					memset(apg_value, 0, sizeof(apg_value));
					if (get_apg_value(p_apg_rule, WIFI_BAND_5GH, "auth_mode_x", apg_value, sizeof(apg_value)-1) && is_wgn_auth_mode_supported(apg_value))				
						result |= WIFI_BAND_5GH;
				}
				else if ((dutlist[j].wifi_band & WIFI_BAND_6G) == WIFI_BAND_6G && (result & WIFI_BAND_6G) == 0) {
					memset(apg_value, 0, sizeof(apg_value));
					if (get_apg_value(p_apg_rule, WIFI_BAND_6G, "auth_mode_x", apg_value, sizeof(apg_value)-1) && is_wgn_auth_mode_supported(apg_value))				
						result |= WIFI_BAND_6G;
				}
				break;
			}
		}
	}

   	return result;
}

int num_of_wifi_band(char *dut_mac, unsigned short wifi_band) 
{
	int result = 0;
	int total = 0;
	int i, j;

	char nv[81];
	struct _dutlist_t dutlist[MAX_DUT_LIST_SIZE];

	if (!dut_mac || strlen(dut_mac) <= 0)
		return 0;

	for (i=0; i<APG_MAXINUM; i++) {
		if (!get_mtlan_enable_by_idx(i)) continue;
		memset(nv, 0, sizeof(nv));
		snprintf(nv, sizeof(nv), NV_APG_X_ENABLE, i);
		if (nvram_get_int(nv) == 0) continue;
		memset(dutlist, 0, (sizeof(struct _dutlist_t) * MAX_DUT_LIST_SIZE));
		if (!get_apg_dutlist(i, dutlist, MAX_DUT_LIST_SIZE, &total) || total <= 0) continue;
		for (j=0; j<total; j++) {
			if (strcmp(dutlist[j].mac, dut_mac) == 0 && (dutlist[j].wifi_band & wifi_band) == wifi_band) {
				result++;
				break;
			}
		}
	}

	return result;
}

int is_sdn_supported(char *mac)
{
   int have_wifi_band_cap = 0;
   char s[64];
   char capabilityFilePath[128];
   json_object *capabilityObj = NULL;
   json_object *wifiBandCapObj = NULL;

   if (!mac || strlen(mac) <= 0)
       return 0;

   memset(capabilityFilePath, 0, sizeof(capabilityFilePath));
   snprintf(capabilityFilePath, sizeof(capabilityFilePath), "%s/%s.cap", TEMP_ROOT_PATH, mac);
   if ((capabilityObj = json_object_from_file(capabilityFilePath))) {
       memset(s, 0, sizeof(s));
       snprintf(s, sizeof(s), "%d", WIFI_BAND_CAP);
       have_wifi_band_cap = (json_object_object_get_ex(capabilityObj, s, &wifiBandCapObj) == TRUE) ? 1 : 0;
       json_object_put(capabilityObj);
   }

   return (have_wifi_band_cap == 1) ? 1 : 0;
}

char* get_wgn_ifnames(int band, int total, char *ret_ifnames, size_t ret_bsize)
{
	if (!ret_ifnames || ret_bsize <= 0)
		return NULL;

	memset(ret_ifnames, 0, ret_bsize);
   	if (nvram_get_int("re_mode") == 0)   
		snprintf(ret_ifnames, ret_bsize, "wl%d.1", band);
	else 
		snprintf(ret_ifnames, ret_bsize, "wl%d.2", band);
   	return ret_ifnames;
}

char* get_wgn_ifnames_by_band(char dut_mac, unsigned short band, char *ret_ifnames, size_t ret_bsize)
{
   char s[64];
   char capabilityFilePath[128];
   char *ptr = NULL;
   char *end = NULL;
   json_object *capabilityObj = NULL;
   json_object *cfgGuestNetworkNo = NULL;
   int guest_ifcount = 0;
   int i;

   	if (!ret_ifnames || ret_bsize <= 0)
       return NULL;

   	memset(ret_ifnames, 0, ret_bsize);
   	ptr = &ret_ifnames[0];
   	end = ptr + ret_bsize;

   	if (!dut_mac || strlen(dut_mac) <= 0)
       return NULL;

   memset(capabilityFilePath, 0, sizeof(capabilityFilePath));
   snprintf(capabilityFilePath, sizeof(capabilityFilePath), "%s/%s.cap", TEMP_ROOT_PATH, dut_mac);
   	if (!(capabilityObj = json_object_from_file(capabilityFilePath)))
       return NULL;

   	memset(s, 0, sizeof(s));
   	switch (band) {
       case WIFI_BAND_2G:
           snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_2G);
           break;
       case WIFI_BAND_5G:
       case WIFI_BAND_5GL: 
           snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_5G);
           break;
       case WIFI_BAND_5GH: 
           snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_5GH);
           break;
       case WIFI_BAND_6G:
           snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_6G);
           break;
       default:
           goto get_wgn_ifnames_by_band_exit;
   	}

	json_object_object_get_ex(capabilityObj, s, &cfgGuestNetworkNo);
   	if (!cfgGuestNetworkNo) 
    	goto get_wgn_ifnames_by_band_exit;

   	if (json_object_get_int64(cfgGuestNetworkNo) == ONE_GUEST_NETWORK)
       	guest_ifcount = 1;
   	else if (json_object_get_int64(cfgGuestNetworkNo) == TWO_GUEST_NETWORK)
       	guest_ifcount = 2;
   	else if (json_object_get_int64(cfgGuestNetworkNo) == THREE_GUEST_NETWORK)
       	guest_ifcount = 3;
   	else
       goto get_wgn_ifnames_by_band_exit;

   for (i=0; i<guest_ifcount; i++)
       ptr += snprintf(ptr, end-ptr, "wl%d.%d ", get_unit_by_band(band), i+1);
   
   	if (strlen(ret_ifnames) > 0 && ret_ifnames[strlen(ret_ifnames)-1] == ' ')
       ret_ifnames[strlen(ret_ifnames)-1] = '\0';

   	json_object_put(capabilityObj);
   	return (strlen(ret_ifnames) > 0) ? ret_ifnames : NULL;

get_wgn_ifnames_by_band_exit:
   	if (capabilityObj) json_object_put(capabilityObj);
   	return NULL;
}

char* get_wgn_all_ifnames(char dut_mac, char *ret_ifnames, size_t ret_bsize)
{
   char b[1025];
   char *ptr = NULL;
   char *end = NULL;
   int i;

   if (!ret_ifnames || ret_bsize <= 0)
       return NULL;

   memset(ret_ifnames, 0, ret_bsize);
   ptr = &ret_ifnames[0];
   end = ptr + ret_bsize;

   for (i=0; i<WIFI_BAND_ARRAY_SIZE; i++) {
       memset(b, 0, sizeof(b));
       if (get_wgn_ifnames_by_band(dut_mac, WIFI_BAND_ARRAY[i], b, sizeof(b)-1) && strlen(b) > 0) 
           ptr += snprintf(ptr, end-ptr, "%s ", b);
   }

   if (strlen(ret_ifnames) > 0 && b[strlen(ret_ifnames)-1] == ' ')
       ret_ifnames[strlen(ret_ifnames)-1] = '\0';

   return (strlen(ret_ifnames) > 0) ? ret_ifnames : NULL;
}

char *get_wgn_vlan_rl(char *ifnames, char *ret_vlans, size_t vlans_bsize)
{
	int unit = -1, subunit = -1, unit2 = -1, subunit2 = -1;
	char word[64], *next = NULL;
	size_t i = 0, offset = 0;

	struct wgn_vlan_rule_t vlan_list[WGN_MAXINUM_VLAN_RULELIST];
	size_t vlan_total = 0;

	char s[33];
	char *b = NULL;

	if (!ifnames || !ret_vlans || vlans_bsize <= 0)
		return NULL;

	if (!(b = nvram_default_get(WGN_VLAN_RULE_NVRAM)))
		return NULL;

	memset(ret_vlans, 0, vlans_bsize);
	memset(vlan_list, 0, sizeof(struct wgn_vlan_rule_t) * WGN_MAXINUM_VLAN_RULELIST);
	if (!wgn_vlan_list_get_from_content(b, vlan_list, WGN_MAXINUM_VLAN_RULELIST, &vlan_total, WGN_GET_CFG_TYPE_WGN_ONLY))
		return NULL;

	if (vlan_total > 0)
	{
		foreach(word, ifnames, next)
		{
			unit = subunit = -1;
			sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
			if (unit < 0 || subunit <= 0)
				continue;
			for (i=0, offset=0; i<vlan_total && offset<vlans_bsize; i++)
			{
				unit2 = subunit2 = -1;
				wgn_get_wl_unit(&unit2,&subunit2,&vlan_list[i]);
				if (unit == unit2 && subunit == subunit2)
				{
					memset(s, 0, sizeof(s));
					snprintf(s, sizeof(s), "%d ", vlan_list[i].vid);
					strlcat(ret_vlans, s, vlans_bsize);
					offset += strlen(s);
					break;					
				}
			}
		}
	}

	if (strlen(ret_vlans) > 0)
		ret_vlans[strlen(ret_vlans) - 1] = '\0';

	return (offset > 0 && offset <= vlans_bsize) ? ret_vlans : NULL;
}


int num_of_vif_used(char *dut_mac, unsigned short wifi_band)
{
	json_object *root = NULL;
	json_object *ifusedObj = NULL;
	json_object *dutObj = NULL;
	json_object *sdnObj = NULL;
	json_object *sdnBandObj = NULL;
	json_object *bandObj = NULL;
	json_object *bandIdxObj = NULL;
	json_object *wlprefixObj = NULL;

	int result = 0;
	int dutArrayLen = 0;
	int sdnBandArrayLen = 0;
	int i, j = 0;

	char *p = NULL;


	if (!(root = json_object_from_file(APG_IFNAMES_USED_FILE)))
		goto num_band_used_exit;

	if (json_object_object_get_ex(root, "vif_used", &ifusedObj) == FALSE)
		goto num_band_used_exit;

	if (!ifusedObj)
		goto num_band_used_exit;

	json_object_object_foreach(ifusedObj, k1, v1) {
		if (strcmp(k1, dut_mac) != 0)
			continue;
		dutObj = v1;
		break;
	}

	if (!dutObj || json_object_get_type(dutObj) != json_type_array || (dutArrayLen = json_object_array_length(dutObj)) <= 0)
		goto num_band_used_exit;

	for (i=0; i<dutArrayLen; i++) {
		if (!(sdnObj = json_object_array_get_idx(dutObj, i)))
			continue;
		if (!(sdnBandObj = json_object_object_get(sdnObj, "sdn_band")) || json_object_get_type(sdnBandObj) != json_type_array || (sdnBandArrayLen = json_object_array_length(sdnBandObj)) <= 0)
			continue;
		for (j=0; j<sdnBandArrayLen; j++) {
			if (!(bandObj = json_object_array_get_idx(sdnBandObj, j)))
				continue;
			if (!(bandIdxObj = json_object_object_get(bandObj, "band_idx")))
				continue;
			if (json_object_get_int(bandIdxObj) != wifi_band)
				continue;
			if (!(wlprefixObj = json_object_object_get(bandObj, "wl_prefix")))
				continue;
			if (!(p = json_object_get_string(wlprefixObj)))
				continue;
			if (strlen(p) > 0)
				result++;
		}
	}

	json_object_put(root);
	return result;

num_band_used_exit:
	if (root) json_object_put(root);
	return 0;
}

int sync_apgx_to_wlunit(void) 
{
	json_object *in = NULL, *lanCapObj = NULL;
	int i, j, x, sunit = 0, bss_enabled = 0, sdn_vid = 0, nvram_changed = 0;
	char *unique_mac = NULL, nv[81], nv1[81], vifnames[512], apg_value[2048], str[128];
	char vlan_trunk_rulelist[512], *vlan_trunk_rl = NULL;
	char wifi_set[1024], *wifi_set_ptr = NULL, *wifi_set_end = NULL;
	char lan_set[1024], *lan_set_ptr = NULL, *lan_set_end = NULL;
	char ap_wifi_rl[2048], *ap_wifi_rl_ptr = NULL, *ap_wifi_rl_end = NULL;
	char ap_lanif_rl[2048], *ap_lanif_rl_ptr = NULL, *ap_lanif_rl_end = NULL;
	char word[64], *next = NULL;
	char word1[64], *next1 = NULL;
	apg_rule_st *p_apg_rule = NULL;
	apg_rule_st apg_rule;

	if (!(unique_mac = get_own_mac()))
		return -1;

	if(!check_if_dir_exist(CFG_MNT_FOLDER))
		mkdir(CFG_MNT_FOLDER, 0755);

	update_apg_ifnames_used(0, unique_mac, -1, -1, 0, NULL);
	for (i=0; i<WIFI_BAND_ARRAY_SIZE; i++) {
		memset(vifnames, 0, sizeof(vifnames));
		if (!get_wificap_ifnames(unique_mac, WIFI_BAND_ARRAY[i], VIF_TYPE_NO_USED, vifnames, sizeof(vifnames)-1, 0)) 
			continue;
		foreach (word, vifnames, next) {
			memset(nv, 0, sizeof(nv));
			snprintf(nv, sizeof(nv), "%s_bss_enabled", word);
			if (nvram_get_int(nv) == 1) {
				nvram_set_int(nv, 0);					
				nvram_changed = 1;
			}
		}
	}

	memset(ap_wifi_rl, 0, sizeof(ap_wifi_rl));
	ap_wifi_rl_ptr = &ap_wifi_rl[0];
	ap_wifi_rl_end = ap_wifi_rl_ptr + sizeof(ap_wifi_rl)-1;

	memset(ap_lanif_rl, 0, sizeof(ap_lanif_rl));
	ap_lanif_rl_ptr = &ap_lanif_rl[0];
	ap_lanif_rl_end = ap_lanif_rl_ptr + sizeof(ap_lanif_rl)-1;

	for (i=1; i<APG_MAXINUM; i++) {
		if (!get_mtlan_enable_by_idx(i))
			continue;
		memset(&apg_rule, 0, sizeof(apg_rule));
		if (!(p_apg_rule = get_apg_rule_by_idx(i, &apg_rule))) 
			continue;

		// wifi band
		memset(wifi_set, 0, sizeof(wifi_set));
		wifi_set_ptr = &wifi_set[0];
		wifi_set_end = wifi_set_ptr + sizeof(wifi_set) - 1;
		// lan port
		memset(lan_set, 0, sizeof(lan_set));
		lan_set_ptr = &lan_set[0];
		lan_set_end = lan_set_ptr + sizeof(lan_set) - 1;
		for (j=0; j<p_apg_rule->dut_list_size; j++) {
			if (strcmp(p_apg_rule->dut_list[j].mac, unique_mac) != 0)
				continue;

			for (x=0; x<WIFI_BAND_ARRAY_SIZE; x++) {
				if ((p_apg_rule->dut_list[j].wifi_band & WIFI_BAND_ARRAY[x]) != WIFI_BAND_ARRAY[x])
					continue;

				memset(vifnames, 0, sizeof(vifnames));
				if (!get_wificap_ifnames(unique_mac, WIFI_BAND_ARRAY[x], VIF_TYPE_NO_USED, vifnames, sizeof(vifnames)-1, 0))
					continue;

				foreach (word, vifnames, next) {
					bss_enabled = 0;
					memset(nv, 0, sizeof(nv));
					snprintf(nv, sizeof(nv), "%s_bss_enabled", word);
					if (nvram_get_int(nv) != 0)
						continue;

					foreach_44 (word1, NV_APG_X_SUFFIX, next1) {
						memset(apg_value, 0, sizeof(apg_value));
						if (get_apg_value(p_apg_rule, WIFI_BAND_ARRAY[x], word1, apg_value, sizeof(apg_value)-1) && strlen(apg_value) > 0) {
							memset(nv, 0, sizeof(nv));
							snprintf(nv, sizeof(nv), "%s_%s", word, word1);
							nvram_set(nv, apg_value);
							bss_enabled = 1;
							nvram_changed = 1;
						}
					}

					if (bss_enabled == 1) {
						memset(str, 0, sizeof(str));
						if (get_wificap_ifname_from_wlprefix(unique_mac, word, str, sizeof(str)-1)) {
							wifi_set_ptr += snprintf(wifi_set_ptr, wifi_set_end-wifi_set_ptr, "%s,", str);
							memset(nv, 0, sizeof(nv));
							snprintf(nv, sizeof(nv), "%s_bss_enabled", word);
							nvram_set_int(nv, 1);
							nvram_changed = 1;
							update_apg_ifnames_used(1, unique_mac, get_sdn_vid_by_apg_rule(p_apg_rule), get_sdn_idx(p_apg_rule->index), WIFI_BAND_ARRAY[x], word);
							break;
						}
					} 							
				}
			}

			if (strlen(wifi_set) > 0 && wifi_set[strlen(wifi_set)-1] == ',')
				wifi_set[strlen(wifi_set)-1] = '\0';

			foreach_44 (word, p_apg_rule->dut_list[j].lan_port_index, next) {
				memset(str, 0, sizeof(str));
				if (!get_lancap_ifname_from_portindex(unique_mac, atoi(word), str, sizeof(str)-1))
					continue;
				lan_set_ptr += snprintf(lan_set_ptr, lan_set_end-lan_set_ptr, "%s,", str);
			} 

			if (strlen(lan_set) > 0 && lan_set[strlen(lan_set)-1] == ',')
				lan_set[strlen(lan_set)-1] = '\0';

			break; // DUT completes the setting, exit the loop
		}

		if ((sdn_vid = get_sdn_vid_by_apg_rule(p_apg_rule)) >= 0) {
			// ap_wifi_rl
			if (strlen(wifi_set) > 0)
				ap_wifi_rl_ptr += snprintf(ap_wifi_rl_ptr, ap_wifi_rl_end-ap_wifi_rl_ptr, "<%d>%s", sdn_vid, wifi_set);
			// ap_lanif_rl
			if (strlen(lan_set) > 0)
				ap_lanif_rl_ptr += snprintf(ap_lanif_rl_ptr, ap_lanif_rl_end-ap_lanif_rl_ptr, "<%d>%s", sdn_vid, lan_set);
		}
	}

	// ap_wifi_rl
	if (!nvram_match(NV_AP_WIFI_RL, ap_wifi_rl)) {
		nvram_set(NV_AP_WIFI_RL, ap_wifi_rl);
		nvram_changed = 1;
	}

	// ap_lanif_rl
	if (!nvram_match(NV_AP_LANIF_RL, ap_lanif_rl)) {
		nvram_set(NV_AP_LANIF_RL, ap_lanif_rl);
		nvram_changed = 1;
	}

	// vlan_trunk_rulelist 
	if ((in = json_object_new_object())) {
		if ((lanCapObj = json_object_new_object())) {
			if (gen_lan_port_cap(lanCapObj)) {
				memset(str, 0, sizeof(str));
				snprintf(str, sizeof(str)-1, "%d", LAN_PORT_CAP);
				json_object_object_add(in, str, lanCapObj);
			}
			else {
				json_object_put(lanCapObj);
				json_object_put(in);
				in = NULL;
			}
		}
		else {
			json_object_put(in);
			in = NULL;
		}
	}

	if (in) {
		memset(vlan_trunk_rulelist, 0, sizeof(vlan_trunk_rulelist));
		vlan_trunk_rl = create_vlan_trunk_rulelist(unique_mac, in, vlan_trunk_rulelist, sizeof(vlan_trunk_rulelist)-1);
		nvram_set(NV_VLAN_TRUNK_RULE, (vlan_trunk_rl==NULL)?"":vlan_trunk_rulelist);
		json_object_put(in);
	}

	if (nvram_changed)
		nvram_commit();

	return 0;
}

unsigned short get_wifi_band_by_ifname(char *dut_mac, char *ifname) 
{
	int i=0, found = 0;
	char ifnames[512];
	char word[64], *next = NULL;
	unsigned short result = 0;

	if (!dut_mac || strlen(dut_mac) <= 0)
		return 0;

	if (!ifname || strlen(ifname) <= 0)
		return 0;

	for (found=0, i=0; i<WIFI_BAND_ARRAY_SIZE; i++) {
		memset(ifnames, 0, sizeof(ifnames));
		if (!get_wificap_ifnames(dut_mac, WIFI_BAND_ARRAY[i], VIF_TYPE_NO_USED, ifnames, sizeof(ifnames)-1, 0))
			continue;
		foreach (word, ifnames, next) {
			if ((found = (!strcmp(ifname, word))))
				break;
		}

		if (found) {
			result = WIFI_BAND_ARRAY[i];
			break;
		}
	}

	return result;
}

void check_apg_ifnames_used_dir(char *path)
{
    char jffs_sys[] = {"/jffs/.sys/\0"};

    if (path && strlen(path) > 0 && strstr(path, jffs_sys)) {
        if (!check_if_dir_exist(jffs_sys))
            mkdir(jffs_sys, 0755);
    }
    
    return;
}

int get_sdn_idx(const unsigned int apg_idx)
{
	int result = 0;
	MTLAN_T *p_mtlan = NULL;
	size_t mtlan_sz = 0;

	if ((p_mtlan = (MTLAN_T *)INIT_MTLAN(sizeof(MTLAN_T)))) {
		if (get_mtlan_by_idx(SDNFT_TYPE_APG, apg_idx, p_mtlan, &mtlan_sz) && mtlan_sz > 0) 
			result = p_mtlan->sdn_t.sdn_idx;
		FREE_MTLAN((void*)p_mtlan);
	}

	return result;
}

int is_wgn_auth_mode_supported(char *auth_mode)
{
// Open System : "open"
// WPA2-Presonal : "psk2"
// WPA3-Presonal : "sae"
// WPA/WPA2-Presonal : "pskpsk2"
// WPA2/WPA3-Personal : "psk2sae"

const static char WGN_AUTH_MODE_X[] = {
	"open,"\
	"psk2,"\
	"sae,"\
	"pskpsk2,"\
	"psk2sae"\
};

	char word[64];
	char *next = NULL;
	int found = 0;

	if (!auth_mode || strlen(auth_mode) <= 0)
		return 0;

	foreach_44(word, WGN_AUTH_MODE_X, next) {
		if ((found = (!strcmp(auth_mode, word))))
			break;
	}

	return found;
}

