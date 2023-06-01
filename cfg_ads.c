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
#include "chmgmt.h"
#include "cfg_ads.h"
#include "cfg_optimization.h"

/*
========================================================================
Routine Description:
	Process diversity state result report.

Arguments:
	clientIP		- client's IP
	cleintMac		- client's MAC
	uniqueMac		- unique Mac
	data            - data

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processAdsDsResultReport(char *clientIP, char *clientMac, char *uniqueMac, unsigned char *data)
{
	json_object *root = json_tokener_parse((char *)data), *seqObj = NULL;
	char filePath[64];
	int ret = 0;

	if (root) {
		json_object_object_get_ex(root, CFG_STR_SEQUENCE, &seqObj);
		if (seqObj) {
			snprintf(filePath, sizeof(filePath), TEMP_CFG_MNT_PATH"/%s.dsr%d", uniqueMac, json_object_get_int(seqObj));
			json_object_to_file(filePath, root);
		}

		json_object_put(root);
		ret = 1;
	}

	return ret;
} /* End of cm_processAdsDsResultReport */

/*
========================================================================
Routine Description:
	Process diversity state result report.

Arguments:
	clientIP		- client's IP
	cleintMac		- client's MAC
	uniqueMac		- unique Mac
	data			- data

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processAdsDsStaDisconn(char *clientIP, char *clientMac, char *uniqueMac, unsigned char *data)
{
	json_object *root = json_tokener_parse((char *)data), *seqObj = NULL;
	char filePath[64];
	int ret = 0;

	if (root) {
		json_object_object_get_ex(root, CFG_STR_SEQUENCE, &seqObj);
		if (seqObj) {
			snprintf(filePath, sizeof(filePath), TEMP_CFG_MNT_PATH"/%s.dssd%d", uniqueMac, json_object_get_int(seqObj));
			f_write_string(filePath, "", 0, 0);
		}

		json_object_put(root);
		ret = 1;
	}

	return ret;
} /* End of cm_processAdsDsStaDisconn */

/*
========================================================================
Routine Description:
	Get antenna diversity state capability by band index.

Arguments:
	unit		- band unit

Return Value:
	None

========================================================================
*/
int cm_getAdsDsCapByUnit(int unit)
{
	int adsCap = -1;

	if (unit == 0)
		adsCap = DIVERSITY_PORT_STATE_BAND0;
	else if (unit == 1)
		adsCap = DIVERSITY_PORT_STATE_BAND1;
	else if (unit == 2)
		adsCap = DIVERSITY_PORT_STATE_BAND2;
	else if (unit == 3)
		adsCap = DIVERSITY_PORT_STATE_BAND3;

	return adsCap;
}  /* End of cm_getAdsDsCapByUnit */

/*
========================================================================
Routine Description:
	Get the band index by wlc band and use

Arguments:
	mac		- RE's mac
    band		- band for compare

Return Value:
	bnad unit

Note:
========================================================================
*/
int cm_getUnitByWlcBandUse(char *mac, int band)
{
	int unit = -1;
	json_object *fileRoot = NULL, *bandObj = NULL, *useObj = NULL, *unitObj = NULL;
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
					json_object_object_get_ex(val, CFG_STR_UNIT, &unitObj);
					if (unitObj)
					{
						unit = json_object_get_int(unitObj);
						break;
					}
				}
			}
		}
	}

	json_object_put(fileRoot);

	return unit;
} /* End of cm_getUnitByWlcBandUse */

/*
========================================================================
Routine Description:
	Get the band index by wlc band and use

Arguments:
	mac		- RE's mac
	band		- band
	index		- index

Return Value:
	bnad unit

Note:
========================================================================
*/
int cm_getUnitByWlcBandIndex(char *mac, int band, int index)
{
	int unit = -1;
	json_object *fileRoot = NULL, *bandObj = NULL, *indexObj = NULL, *unitObj = NULL;
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
				json_object_object_get_ex(val, CFG_STR_INDEX, &indexObj);
				/* check use */
				if (indexObj && index == json_object_get_int(indexObj))
				{
					json_object_object_get_ex(val, CFG_STR_UNIT, &unitObj);
					if (unitObj)
					{
						unit = json_object_get_int(unitObj);
						break;
					}
				}
			}
		}
	}

	json_object_put(fileRoot);

	return unit;
} /* End of cm_getUnitByWlcBandIndex */

/*
========================================================================
Routine Description:
	Get the band index by wlc band and use

Arguments:
	bssid		- CAP's/RE's ap mac

Return Value:
	bnad unit

Note:
========================================================================
*/
int cm_getCapUnitByBandBssid(char *bssid)
{
	int unit = 0;
	char wlIfnames[64], word[64], *next = NULL, prefix[sizeof("wlXXXXX_")], tmp[64];

	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (strcmp(bssid, nvram_safe_get(strcat_r(prefix, "hwaddr", tmp))) == 0)
			break;

		unit++;
	}

	return unit;
} /* End of cm_getCapUnitByBandBssid */

/*
========================================================================
Routine Description:
	Insert a ads pair to ads pairt list.

Arguments:
	adsPairHead		- ads pair list head
	adsPair		- new ads pair

Return Value:
	None

Note:
========================================================================
*/
void cm_insertAdsPairList(ads_pair_s **adsPairHead, ads_pair_s *adsPair)
{
	ads_pair_s *adsPairTmp = NULL;

	if (*adsPairHead == NULL) {
		*adsPairHead = adsPair;
	}
	else {
		adsPairTmp = *adsPairHead;
		while (adsPairTmp) {
			if (adsPairTmp->next == NULL) {
				adsPairTmp->next = adsPair;
				break;
			}
			adsPairTmp = adsPairTmp->next;
		}
	}
} /* End of cm_insertAdsPairList */

/*
========================================================================
Routine Description:
	Insert a ads pair to ads pairt list by cost sorted.

Arguments:
	adsPairHead		- ads pair list head
	adsPair		- new ads pair

Return Value:
	None

Note:
========================================================================
*/
void cm_insertAdsPairListByCost(ads_pair_s **adsPairHead, ads_pair_s *adsPair)
{
	ads_pair_s *adsPairCurr;

	if (*adsPairHead == NULL || (*adsPairHead)->cost < adsPair->cost) {
		adsPair->next = *adsPairHead;
		*adsPairHead = adsPair;
	} else {
		adsPairCurr = *adsPairHead;
		while (adsPairCurr->next != NULL && adsPairCurr->next->cost >= adsPair->cost) {
			adsPairCurr = adsPairCurr->next;
		}
		adsPair->next = adsPairCurr->next;
		adsPairCurr->next = adsPair;
	}
} /* End of cm_insertAdsPairListByCost */

/*
========================================================================
Routine Description:
	Free ads pairt list.

Arguments:
	adsPairHead		- ads pair list

Return Value:
	None

Note:
========================================================================
*/
void cm_freeAdsPairList(ads_pair_s **adsPair)
{
	ads_pair_s *adsPairTmp;

	while (*adsPair != NULL) {
		adsPairTmp = *adsPair;
		*adsPair = (*adsPair)->next;
		free(adsPairTmp);
	}
	*adsPair = NULL;
} /* End of cm_freeAdsPairList */

/*
========================================================================
Routine Description:
	Sort ads pairt list.

Arguments:
	adsPairHead		- ads pair list head
	adsPair		- new ads pair

Return Value:
	None

Note:
========================================================================
*/
void cm_sortAdsPairList(ads_pair_s **adsPairHead, ads_pair_s *adsPair)
{
    ads_pair_s *adsPairCurr;

	if (*adsPairHead == NULL || (*adsPairHead)->rssi5g > adsPair->rssi5g) {
		adsPair->next = *adsPairHead;
		*adsPairHead = adsPair;
	} else {
		adsPairCurr = *adsPairHead;
		while (adsPairCurr->next != NULL && adsPairCurr->next->rssi5g <= adsPair->rssi5g) {
			adsPairCurr = adsPairCurr->next;
		}
		adsPair->next = adsPairCurr->next;
		adsPairCurr->next = adsPair;
	}
} /* End of cm_sortAdsPairList */

/*
========================================================================
Routine Description:
	Find the pairs of antenna diversity selection.

Arguments:
	timestamp	- timestamp
	p_client_tb	- client table
	optTrigger	- opt trigger
	nMac	- mac for notifiying optimization

Return Value:
	None

Note:
========================================================================
*/
json_object *cm_findAdsPair(unsigned int timestamp, CM_CLIENT_TABLE *p_client_tbl, int optTrigger, char *nMac)
{
	char cMac[18], ip[18], pMac[18], ap5g[18], ap5g1[18], pap5g[18], cModelName[33], pModelName[33];
	int i = 0, j = 0, rssi5g = 0, haveAdsPair = 0, cost = 0;
	int wiredPath = ETH | ETH_2 | ETH_3 | ETH_4;
	int adsDbg = nvram_get_int("cfg_ads_dbg");
	ads_pair_s *adsPairList = NULL, *adsPair = NULL, *adsPairCurr = NULL, *adsPairNext = NULL, *adsPairTmp = NULL;
	json_object *adsPairListObj = NULL, *adsPairObj = NULL;
	int pUnit5g = 0, cUnit5g = 0, pAdsCap = 0, cAdsCap = 0, isPairDone = 0;
    unsigned char nullMAC[MAC_LEN] = {0};

	if ((adsPairListObj = json_object_new_array()) == NULL) {
		DBG_LOG("[%d] adsPairListObj is NULL", timestamp);
		return NULL;
	}

	/* find ads pair and add to list */
	for (i = 1; i < p_client_tbl->count; i++) {
		snprintf(cMac, sizeof(cMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		strlcpy(cModelName, p_client_tbl->modelName[i], sizeof(cModelName));

		cUnit5g = cm_getUnitByWlcBandUse(cMac, 5);
		cAdsCap = cm_getAdsDsCapByUnit(cUnit5g);
		if (adsDbg)
			DBG_LOG("[%d] cUnit5g(%d), cAdsCap(%d)", timestamp, cUnit5g, cAdsCap);
		if (cm_isCapSupported(cMac, cAdsCap, 0) != 1) {
			DBG_LOG("[%d] RE (%s) doesn't support antenna diversity selection, pass",
				timestamp, cMac);
			continue;
		}

		if (p_client_tbl->activePath[i] & wiredPath) {
			DBG_LOG("[%d] RE (%s) is ethernet backhaul, pass", timestamp, cMac);
			continue;
		}

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_LOG("[%d] RE (%s, %s) is offline, pass", timestamp, cMac, ip);
			continue;
		}

		if (!(p_client_tbl->activePath[i] & (WL5G1_U | WL5G2_U))
			&& !(p_client_tbl->activePath[i] & (WL_5G | WL_5G_1))) {
			DBG_LOG("[%d] RE (%s, %s) is not 5G backhaul, pass", timestamp, cMac, ip);
			continue;
		}

		if (!memcmp(p_client_tbl->pap5g[i], nullMAC, sizeof(nullMAC))) {
			DBG_LOG("[%d] RE (%s, %s) 5G is disconnected, pass", timestamp, cMac, ip);
			continue;
		}

		snprintf(pap5g, sizeof(pap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->pap5g[i][0], p_client_tbl->pap5g[i][1],
			p_client_tbl->pap5g[i][2], p_client_tbl->pap5g[i][3],
			p_client_tbl->pap5g[i][4], p_client_tbl->pap5g[i][5]);

		rssi5g = p_client_tbl->rssi5g[i];
		cost = p_client_tbl->cost[i];

		if (adsDbg)
			DBG_LOG("[%d] cMac(%s), pap5g(%s), rssi5g(%d)", timestamp, cMac, pap5g, rssi5g);

		for (j = 0; j < p_client_tbl->count; j++) {
			snprintf(pMac, sizeof(pMac), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
				p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
				p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

			snprintf(ap5g, sizeof(ap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g[j][0], p_client_tbl->ap5g[j][1],
				p_client_tbl->ap5g[j][2], p_client_tbl->ap5g[j][3],
				p_client_tbl->ap5g[j][4], p_client_tbl->ap5g[j][5]);

			snprintf(ap5g1, sizeof(ap5g1), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g1[j][0], p_client_tbl->ap5g1[j][1],
				p_client_tbl->ap5g1[j][2], p_client_tbl->ap5g1[j][3],
				p_client_tbl->ap5g1[j][4], p_client_tbl->ap5g1[j][5]);

			strlcpy(pModelName, p_client_tbl->modelName[i], sizeof(pModelName));

			if (strcmp(pMac, cMac) == 0) {
				if (adsDbg)
					DBG_LOG("[%d] pMac(%s) is same as cMac(%s), pass", timestamp, pMac, cMac);
				continue;
			}

			if (adsDbg)
				DBG_LOG("[%d] ap5g(%s), ap5g1(%s)", timestamp, ap5g, ap5g1);

			if (strcmp(ap5g, pap5g) == 0 || strcmp(ap5g1, pap5g) == 0) {
				pUnit5g = -1;
				pAdsCap = 0;
				if (j == 0) {	/* for CAP */
					pUnit5g = cm_getCapUnitByBandBssid(pap5g);
					pAdsCap = cm_getAdsDsCapByUnit(pUnit5g);
				}
				else	/* for RE */
				{
					if (strcmp(ap5g, pap5g) == 0)
						pUnit5g = cm_getUnitByWlcBandIndex(pMac, 5, 1);
					else if (strcmp(ap5g1, pap5g) == 0)
						pUnit5g = cm_getUnitByWlcBandIndex(pMac, 5, 2);
					pAdsCap = cm_getAdsDsCapByUnit(pUnit5g);
				}

				if (adsDbg)
					DBG_LOG("[%d] j(%d), pUnit5g(%d), pAdsCap(%d)", timestamp, j, pUnit5g, pAdsCap);

				if (cm_isCapSupported(pMac, pAdsCap, 0) != 1) {
					DBG_LOG("[%d] %s (%s) doesn't support antenna diversity selection, pass",
						timestamp, j == 0 ? "CAP": "RE", pMac);
					continue;
				}

				/* check pair done or not */
				if ((optTrigger != OPT_TRIGGER_UI && optTrigger != OPT_TRIGGER_ADS_FIXED_TIME)
					&& cm_isAdsPairDone(timestamp, pMac, pUnit5g, cMac, cUnit5g)) {
					isPairDone = 1;
					if (optTrigger == OPT_TRIGGER_NOTIFY || optTrigger == OPT_TRIGGER_5G_RSSI_DIFF_12DBM) {
						DBG_LOG("[%d] do ads pair (%s,%d - %s,%d)", timestamp, pMac, pUnit5g, cMac, cUnit5g);
						isPairDone = 0;
					}
					
					if (isPairDone) {
						if (optTrigger != OPT_TRIGGER_PERIODIC_TIME)
							DBG_LOG("[%d] pair (%s,%d - %s,%d) is done, pass", timestamp, pMac, pUnit5g, cMac, cUnit5g);
						continue;
					}
				}				

				adsPair = (ads_pair_s *)calloc(1, sizeof(ads_pair_s));

				if (adsPair) {
					strlcpy(adsPair->pMac, pMac, sizeof(adsPair->pMac));
					strlcpy(adsPair->pModelName, pModelName, sizeof(adsPair->pModelName));
					strlcpy(adsPair->cMac, cMac, sizeof(adsPair->cMac));
					strlcpy(adsPair->cModelName, cModelName, sizeof(adsPair->cModelName));
					adsPair->rssi5g = rssi5g;
					adsPair->cost = cost;

					//cm_insertAdsPairList(&adsPairList, adsPair);
					cm_insertAdsPairListByCost(&adsPairList, adsPair);
					adsPair = NULL;
					haveAdsPair = 1;
				}
			}
		}
	}

	/* sort ads pair */
	if (haveAdsPair) {
		adsPairCurr = adsPairList;
		adsPairTmp = NULL;

		while (adsPairCurr != NULL) {
			adsPairNext = adsPairCurr->next;
			cm_sortAdsPairList(&adsPairTmp, adsPairCurr);
			adsPairCurr = adsPairNext;
		}
		adsPairList = adsPairTmp;

		adsPairCurr = adsPairList;
		while (adsPairCurr != NULL) {
			if (adsDbg)
				DBG_LOG("[%d] pMac(%s), cMac(%s), rssi5g(%d), cost(%d)",
					timestamp, adsPairCurr->pMac, adsPairCurr->cMac, adsPairCurr->rssi5g, adsPairCurr->cost);
			if ((adsPairObj = json_object_new_object())) {
				json_object_object_add(adsPairObj, CFG_STR_PARENT_MAC, json_object_new_string(adsPairCurr->pMac));
				json_object_object_add(adsPairObj, CFG_STR_PARENT_MODEL_NAME,
					json_object_new_string(adsPairCurr->pModelName));
				json_object_object_add(adsPairObj, CFG_STR_CHILD_MAC, json_object_new_string(adsPairCurr->cMac));
				json_object_object_add(adsPairObj, CFG_STR_CHILD_MODEL_NAME,
					json_object_new_string(adsPairCurr->cModelName));
				json_object_object_add(adsPairObj, CFG_STR_RSSI5G, json_object_new_int(adsPairCurr->rssi5g));
				json_object_object_add(adsPairObj, CFG_STR_COST, json_object_new_int(adsPairCurr->cost));
				json_object_array_add(adsPairListObj, adsPairObj);
			}
			adsPairCurr = adsPairCurr->next;
		}

		cm_freeAdsPairList(&adsPairList);
	}
	else
	{
		if (optTrigger != OPT_TRIGGER_PERIODIC_TIME)
			DBG_LOG("[%d] no any ADS pair need to do", timestamp);
		json_object_put(adsPairListObj);
		adsPairListObj = NULL;
	}

	return adsPairListObj;
} /* End of cm_findAdsPair */

/*
========================================================================
Routine Description:
	Get re path by RE's mac.

Arguments:
	p_client_tb	- client table
	reMac		- RE's mac

Return Value:
	RE path

Note:
========================================================================
*/
int cm_getRePathByMac(CM_CLIENT_TABLE *p_client_tbl, char *reMac)
{
	char mac[18];
	int i = 0, rePath = 0;

	/* find ads pair and add to list */
	for (i = 1; i < p_client_tbl->count; i++) {
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		if (strcmp(mac, reMac) == 0) {
			rePath = p_client_tbl->activePath[i];
			break;
		}
	}

	return rePath;
} /* End of cm_getRePathByMac */

/*
========================================================================
Routine Description:
	Get pair related information.

Arguments:
	p_client_tb	- client table
	pMac		- mac for parent (CAP/RE)
	cMac		- mac for child (RE)
	pCap		- is CAP for parent
	pUnit5g		- unit for parent (CAP/RE)
	cUnit5g		- unit for child (RE)
	cTblIndex	- the index of client table for child (RE)
	cSTaMac		- sta mac for RE
	cStaMacLen		- the length of sta mac for RE

Return Value:
	0		- no info
	1		- have info

Note:
========================================================================
*/
int cm_getPairRelatedInfo(CM_CLIENT_TABLE *p_client_tbl, char *pMac, char *cMac, int pCap, int *pUnit5g, int *cUnit5g, int *cTblIndex, char *cStaMac, int cStaMacLen)
{
	char mac[18], pap5g[18] = {0}, ap5g[18] = {0}, ap5g1[18] = {0};
	int i = 0, ret = 0;

	/* find ads pair and add to list */
	for (i = 0; i < p_client_tbl->count; i++) {
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		/* ap5g and ap5g1 for parent mac */
		if (strcmp(mac, pMac) == 0) {
			snprintf(ap5g, sizeof(ap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g[i][0], p_client_tbl->ap5g[i][1],
				p_client_tbl->ap5g[i][2], p_client_tbl->ap5g[i][3],
				p_client_tbl->ap5g[i][4], p_client_tbl->ap5g[i][5]);

			snprintf(ap5g1, sizeof(ap5g1), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g1[i][0], p_client_tbl->ap5g1[i][1],
				p_client_tbl->ap5g1[i][2], p_client_tbl->ap5g1[i][3],
				p_client_tbl->ap5g1[i][4], p_client_tbl->ap5g1[i][5]);
		}

		/* ap5g and ap5g1 for child mac */
		if (strcmp(mac, cMac) == 0) {
			snprintf(pap5g, sizeof(pap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->pap5g[i][0], p_client_tbl->pap5g[i][1],
				p_client_tbl->pap5g[i][2], p_client_tbl->pap5g[i][3],
				p_client_tbl->pap5g[i][4], p_client_tbl->pap5g[i][5]);

			snprintf(cStaMac, cStaMacLen, "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->sta5g[i][0], p_client_tbl->sta5g[i][1],
				p_client_tbl->sta5g[i][2], p_client_tbl->sta5g[i][3],
				p_client_tbl->sta5g[i][4], p_client_tbl->sta5g[i][5]);

			*cTblIndex = i;
		}
	}

	if (strlen(pap5g) && strlen(ap5g) && strlen(ap5g1)) {
		if (strcmp(ap5g, pap5g) == 0) {
			if (pCap)
				*pUnit5g = chmgmt_get_5g_unit();
			else
				*pUnit5g = cm_getUnitByWlcBandIndex(pMac, 5, 1);
			*cUnit5g = cm_getUnitByWlcBandIndex(cMac, 5, 1);
			ret = 1;
		}
		else if (strcmp(ap5g1, pap5g) == 0)
		{
			if (pCap)
				*pUnit5g = chmgmt_get_5g_unit();
			else
				*pUnit5g = cm_getUnitByWlcBandIndex(pMac, 5, 2);
			*cUnit5g = cm_getUnitByWlcBandIndex(cMac, 5, 2);
			ret = 1;
		}
	}

	return ret;
} /* End of cm_getPairRelatedInfo */

/*
========================================================================
Routine Description:
	Create diversity port state combination.

Arguments:
	timestamp	- timestamp
	mac		- mac
	adsCap	- value of ads capability
	bandUnit	- band unit
	dpNum		- diversity port number
	dpsTotalCombNum		- total number of diversity port state combination

Return Value:
	diversity port state combination

Note:
========================================================================
*/
json_object *cm_createDpsCombination(unsigned int timestamp, char *mac, int adsCap, int bandUnit, int *dpNum, int *dpsCombNum)
{
	int i = 0, j = 0, k = 0, s = 0, c = 0, dps = 0, dsNum = 0, dpNumLen = 0, totalDsComb = 1, totalDsCombTmp = 1;
	int loopCount = 0, adsDbg = nvram_get_int("cfg_ads_dbg");
	json_object *dpNumArrayObj = NULL, *dsNumEntry = NULL, *dpsCombObj = NULL, *seqObj = NULL;
	json_object *resultObj = NULL, *macObj = NULL, *bandUnitObj = NULL;
	char dsPortStr[8], seqStr[8], bandUnitStr[8];
	int dpsVal = 0;

	if (adsDbg)
		DBG_LOG("[%d] adsCap(%d)", timestamp, adsCap);

	dpsVal = cm_getCapabilityIntValue(mac, adsCap);

	if ((dpsCombObj = json_object_new_object()) == NULL) {
		DBG_LOG("[%d] dpsCombObj is NULL", timestamp);
		return NULL;
	}

	if (dpsVal > 0) {
		if ((dpNumArrayObj = json_object_new_array()) == NULL) {
			DBG_LOG("[%d] dpNumArrayObj is NULL", timestamp);
			json_object_put(dpsCombObj);
			return NULL;
		}

		while (dpsVal) {
			dps = dpsVal & 0xF;
			json_object_array_add(dpNumArrayObj, json_object_new_int(dps));
			dpsVal = dpsVal >> 4;
		}

		dpNumLen = json_object_array_length(dpNumArrayObj);
		*dpNum = dpNumLen;

		/* check ds result */
		if ((resultObj = json_object_from_file(DS_SWITCH_RESULT_FILE))) {
			snprintf(bandUnitStr, sizeof(bandUnitStr), "%d", bandUnit);
			json_object_object_get_ex(resultObj, mac, &macObj);
			json_object_object_get_ex(macObj, bandUnitStr, &bandUnitObj);
		}

		if (bandUnitObj) {	/* have ds switch result */
			*dpsCombNum = 1;
			if ((seqObj = json_object_new_object())) {
				snprintf(seqStr, sizeof(seqStr), "%d", 1);
				json_object_object_foreach(bandUnitObj, key, val)
					json_object_object_add(seqObj, key, json_object_new_int(json_object_get_int(val)));
				json_object_object_add(dpsCombObj, seqStr, seqObj);
			}
		}
		else	/* no ds switch result */
		{
			/* compute total number of combination */
			for (i = 0; i < dpNumLen; i++) {
				if ((dsNumEntry = json_object_array_get_idx(dpNumArrayObj, i))) {
					totalDsComb *= json_object_get_int(dsNumEntry);
				}
			}

			/* create ds combination */
			*dpsCombNum = totalDsComb;
			totalDsCombTmp = totalDsComb;
			for (i = 0; i < dpNumLen; i++) {
				if ((dsNumEntry = json_object_array_get_idx(dpNumArrayObj, i))) {
					dsNum = json_object_get_int(dsNumEntry);
					totalDsCombTmp /= dsNum;
					s = 1;
					snprintf(dsPortStr, sizeof(dsPortStr), "p%d", i);
					loopCount = totalDsComb / (dsNum * totalDsCombTmp);
					if (adsDbg)
						DBG_LOG("[%d] dsNum(%d), totalDsCombTmp(%d), loopCount(%d)",
							timestamp, dsNum, totalDsCombTmp, loopCount);
					for (c = 0; c < loopCount; c++) {
						for (j = 0; j < dsNum; j++) {
							for (k = 0; k < totalDsCombTmp; k++) {
								snprintf(seqStr, sizeof(seqStr), "%d", s);
								json_object_object_get_ex(dpsCombObj, seqStr, &seqObj);
								if (seqObj) {
									json_object_object_add(seqObj, dsPortStr, json_object_new_int(j));
								}
								else
								{
									if ((seqObj = json_object_new_object())) {
										json_object_object_add(seqObj, dsPortStr, json_object_new_int(j));
										json_object_object_add(dpsCombObj, seqStr, seqObj);
									}
								}
								s++;
							}
						}
					}
				}
			}
		}

		json_object_put(dpNumArrayObj);
		json_object_put(resultObj);
	}

	return dpsCombObj;
} /* End of cm_createDpsCombination */

/*
========================================================================
Routine Description:
	Upate the stage of antenna diversity selection.

Arguments:
	timestamp	- timestamp
	resultFile		- result file path
	seq		- the sequence for ds combination
	pDsObj		- diversity state for parent
	cDsObj		- diversity state for child

Return Value:
	None

Note:
========================================================================
*/
void cm_updateDsToResult(unsigned int timestamp, char *resultFile, int seq, json_object *pDsObj, json_object *cDsObj)
{
	json_object *resultObj = NULL, *dsObj = NULL;
	int update = 0;

	if (!pDsObj && !cDsObj) {
		DBG_LOG("pDsObj & cDsObj are NULL");
		return;
	}

	if ((resultObj = json_object_from_file(resultFile))) {
		/* update ds for parent */
		if ((dsObj = json_object_new_object())) {
			json_object_object_foreach(pDsObj, pDsKey, pDsVal)
				json_object_object_add(dsObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
			json_object_object_add(resultObj, CFG_STR_PARENT_DS, dsObj);
			update = 1;
		}

		/* update ds for child */
		if ((dsObj = json_object_new_object())) {
			json_object_object_foreach(cDsObj, cDsKey, cDsVal)
				json_object_object_add(dsObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
			json_object_object_add(resultObj, CFG_STR_CHILD_DS, dsObj);
			update = 1;
		}

		DBG_LOG("[%d] sequecne (%d) for diversity state result (%s)",
			timestamp, seq, json_object_to_json_string_ext(resultObj, 0));

		/* update to file */
		if (update)
			json_object_to_file(resultFile, resultObj);
	}

	json_object_put(resultObj);
} /* End of cm_updateDsToResult */

/*
========================================================================
Routine Description:
	Update unavailable diversity state to file.

Arguments:
	timestamp	- timestamp
	pMac		- mac for parent
	pUnit		- band unit for parent
	pDsObj		- diversity state for parent
	cMac		- mac for child
	cUnit		- band unit for child
	cDsObj		- diversity state for child

Return Value:
	None

Note:
========================================================================
*/
void cm_updateUnavailableDsToFile(unsigned int timestamp, char *pMac, int pUnit, json_object *pDsObj, char *cMac, int cUnit, json_object *cDsObj)
{
	json_object *fileObj = NULL, *pDsTempObj = NULL, *cDsTempObj = NULL, *dsObj = NULL, *dsNumObj = NULL;
	json_object *pMacObj = NULL, *pUnitObj = NULL, *cMacObj = NULL, *cUnitObj = NULL;
	int update = 0, dsNum = 0, i = 0, found = 0;
	char unitStr[8], dsStr[8];

	if (!pDsObj && !cDsObj) {
		DBG_LOG("pDsObj & cDsObj are NULL");
		return;
	}

	/* {"20:CF:30:00:AA:00":{"1":{"20:CF:30:00:BB:00":{"1":{"ds1":{"pds":{"p0":1},"cds":{"p0":1}},"ds_num":1}}}}} */
	if ((fileObj = json_object_from_file(DS_UNAVAILABLE_FILE))) {
		json_object_object_get_ex(fileObj, pMac, &pMacObj);
		if (pMacObj) {
			snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
			json_object_object_get_ex(pMacObj, unitStr, &pUnitObj);

			if (pUnitObj) {
				cMacObj = NULL;
				json_object_object_foreach(pUnitObj, macKey, macVal) {
					if (strcmp(macKey, cMac) == 0) {
						cMacObj = macVal;
						break;
					}
				}

				if (cMacObj) {
					snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
					json_object_object_get_ex(cMacObj, unitStr, &cUnitObj);

					if (cUnitObj) {
						json_object_object_get_ex(cUnitObj, CFG_STR_DS_NUM, &dsNumObj);
						if (dsNumObj) {
							dsNum = json_object_get_int(dsNumObj);
							found = 0;
							for (i = 1; i <= dsNum; i++) {
								snprintf(dsStr, sizeof(dsStr), "ds%d", i);
								json_object_object_get_ex(cUnitObj, dsStr, &dsObj);
								if (dsObj) {
									json_object_object_get_ex(dsObj, CFG_STR_PARENT_DS, &pDsTempObj);
									json_object_object_get_ex(dsObj, CFG_STR_CHILD_DS, &cDsTempObj);
									if (pDsTempObj && cDsTempObj) {
										if (strcmp(json_object_get_string(pDsTempObj), json_object_get_string(pDsObj)) == 0
											&& strcmp(json_object_get_string(cDsTempObj), json_object_get_string(cDsObj)) == 0)
										{
											found = 1;
											break;
										}
									}
								}
							}

							if (!found) {
								if ((dsObj = json_object_new_object())) {
									if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
										json_object_object_del(cUnitObj, CFG_STR_DS_NUM);

										json_object_object_foreach(pDsObj, pDsKey, pDsVal)
											json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
										json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

										json_object_object_foreach(cDsObj, cDsKey, cDsVal)
											json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
										json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

										dsNum++;
										snprintf(dsStr, sizeof(dsStr), "ds%d", dsNum);
										json_object_object_add(cUnitObj, dsStr, dsObj);
										json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(dsNum));

										update = 1;
									}
									else
									{
										json_object_put(pDsTempObj);
										json_object_put(cDsTempObj);
										json_object_put(dsObj);
									}
								}
							}
						}
						else
						{
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
								}
							}
						}
					}
					else
					{
						if ((cUnitObj = json_object_new_object())) {
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));
									snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
									json_object_object_add(cMacObj, unitStr, cUnitObj);

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
									json_object_put(cUnitObj);
								}
							}
							else
							{
								json_object_put(cUnitObj);
							}
						}
					}
				}
				else
				{
					if ((cMacObj = json_object_new_object())) {
						if ((cUnitObj = json_object_new_object())) {
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));
									snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
									json_object_object_add(cMacObj, unitStr, cUnitObj);
									json_object_object_add(pUnitObj, cMac, cMacObj);

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
									json_object_put(cUnitObj);
									json_object_put(cMacObj);
								}
							}
							else
							{
								json_object_put(cUnitObj);
								json_object_put(cMacObj);
							}
						}
						else
						{
							json_object_put(cMacObj);
						}
					}
				}
			}
			else
			{
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						if ((cUnitObj = json_object_new_object())) {
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));
									snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
									json_object_object_add(cMacObj, unitStr, cUnitObj);
									json_object_object_add(pUnitObj, cMac, cMacObj);
									snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
									json_object_object_add(pMacObj, unitStr, pUnitObj);

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
									json_object_put(cUnitObj);
									json_object_put(cMacObj);
									json_object_put(pUnitObj);
								}
							}
							else
							{
								json_object_put(cUnitObj);
								json_object_put(cMacObj);
								json_object_put(pUnitObj);
							}
						}
						else
						{
							json_object_put(cMacObj);
							json_object_put(pUnitObj);
						}
					}
					else
					{
						json_object_put(pUnitObj);
					}
				}
			}
		}
		else
		{
			if ((pMacObj = json_object_new_object())) {
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						if ((cUnitObj = json_object_new_object())) {
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));
									snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
									json_object_object_add(cMacObj, unitStr, cUnitObj);
									json_object_object_add(pUnitObj, cMac, cMacObj);
									snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
									json_object_object_add(pMacObj, unitStr, pUnitObj);
									json_object_object_add(fileObj, pMac, pMacObj);

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
									json_object_put(cUnitObj);
									json_object_put(cMacObj);
									json_object_put(pUnitObj);
									json_object_put(pMacObj);
								}
							}
							else
							{
								json_object_put(cUnitObj);
								json_object_put(cMacObj);
								json_object_put(pUnitObj);
								json_object_put(pMacObj);
							}
						}
						else
						{
							json_object_put(cMacObj);
							json_object_put(pUnitObj);
							json_object_put(pMacObj);
						}
					}
					else
					{
						json_object_put(pUnitObj);
						json_object_put(pMacObj);
					}
				}
				else
				{
					json_object_put(pMacObj);
				}
			}
		}
	}
	else
	{
		if ((fileObj = json_object_new_object())) {
			if ((pMacObj = json_object_new_object())) {
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						if ((cUnitObj = json_object_new_object())) {
							if ((dsObj = json_object_new_object())) {
								if ((pDsTempObj = json_object_new_object()) && (cDsTempObj = json_object_new_object())) {
									json_object_object_foreach(pDsObj, pDsKey, pDsVal)
										json_object_object_add(pDsTempObj, pDsKey, json_object_new_int(json_object_get_int(pDsVal)));
									json_object_object_add(dsObj, CFG_STR_PARENT_DS, pDsTempObj);

									json_object_object_foreach(cDsObj, cDsKey, cDsVal)
										json_object_object_add(cDsTempObj, cDsKey, json_object_new_int(json_object_get_int(cDsVal)));
									json_object_object_add(dsObj, CFG_STR_CHILD_DS, cDsTempObj);

									json_object_object_add(cUnitObj, "ds1", dsObj);
									json_object_object_add(cUnitObj, CFG_STR_DS_NUM, json_object_new_int(1));
									snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
									json_object_object_add(cMacObj, unitStr, cUnitObj);
									json_object_object_add(pUnitObj, cMac, cMacObj);
									snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
									json_object_object_add(pMacObj, unitStr, pUnitObj);
									json_object_object_add(fileObj, pMac, pMacObj);

									update = 1;
								}
								else
								{
									json_object_put(pDsTempObj);
									json_object_put(cDsTempObj);
									json_object_put(dsObj);
									json_object_put(cUnitObj);
									json_object_put(cMacObj);
									json_object_put(pUnitObj);
									json_object_put(pMacObj);
								}
							}
							else
							{
								json_object_put(cUnitObj);
								json_object_put(cMacObj);
								json_object_put(pUnitObj);
								json_object_put(pMacObj);
							}
						}
						else
						{
							json_object_put(cMacObj);
							json_object_put(pUnitObj);
							json_object_put(pMacObj);
						}
					}
					else
					{
						json_object_put(pUnitObj);
						json_object_put(pMacObj);
					}
				}
				else
				{
					json_object_put(pMacObj);
				}
			}
		}
	}

	/* update to file */
	if (update)
		json_object_to_file(DS_UNAVAILABLE_FILE, fileObj);

	json_object_put(fileObj);
} /* End of cm_updateUnavailableDsToFile */

/*
========================================================================
Routine Description:
	Check unavailable ds or not.

Arguments:
	timestamp	- timestamp
	pMac		- mac for parent
	pUnit		- band unit for parent
	pDsObj		- diversity state for parent
	cMac		- mac for child
	cUnit		- band unit for child
	cDsObj		- diversity state for child

Return Value:
	-1		- error
	0		- is available ds
	1		- is unavailable ds

Note:
========================================================================
*/
int cm_isUnavailableDs(unsigned int timestamp, char *pMac, int pUnit, json_object *pDsObj, char *cMac, int cUnit, json_object *cDsObj)
{
	json_object *fileObj = NULL, *pDsTempObj = NULL, *cDsTempObj = NULL, *dsObj = NULL, *dsNumObj = NULL;
	json_object *pMacObj = NULL, *pUnitObj = NULL, *cMacObj = NULL, *cUnitObj = NULL;
	int dsNum = 0, i = 0, ret = 0;
	char unitStr[8], dsStr[8];

	if (!pDsObj && !cDsObj) {
		DBG_LOG("pDsObj & cDsObj are NULL");
		return -1;
	}

	/* {"20:CF:30:00:AA:00":{"1":{"20:CF:30:00:BB:00":{"1":{"ds1":{"pds":{"p0":1},"cds":{"p0":1}},"ds_num":1}}}}} */
	if ((fileObj = json_object_from_file(DS_UNAVAILABLE_FILE))) {
		json_object_object_get_ex(fileObj, pMac, &pMacObj);
		if (pMacObj) {
			snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
			json_object_object_get_ex(pMacObj, unitStr, &pUnitObj);

			if (pUnitObj) {
				cMacObj = NULL;
				json_object_object_foreach(pUnitObj, macKey, macVal) {
					if (strcmp(macKey, cMac) == 0) {
						cMacObj = macVal;
						break;
					}
				}

				if (cMacObj) {
					snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
					json_object_object_get_ex(cMacObj, unitStr, &cUnitObj);

					if (cUnitObj) {
						json_object_object_get_ex(cUnitObj, CFG_STR_DS_NUM, &dsNumObj);
						if (dsNumObj) {
							dsNum = json_object_get_int(dsNumObj);
							for (i = 1; i <= dsNum; i++) {
								snprintf(dsStr, sizeof(dsStr), "ds%d", i);
								json_object_object_get_ex(cUnitObj, dsStr, &dsObj);
								if (dsObj) {
									json_object_object_get_ex(dsObj, CFG_STR_PARENT_DS, &pDsTempObj);
									json_object_object_get_ex(dsObj, CFG_STR_CHILD_DS, &cDsTempObj);
									if (pDsTempObj && cDsTempObj) {
										if (strcmp(json_object_get_string(pDsTempObj), json_object_get_string(pDsObj)) == 0
											&& strcmp(json_object_get_string(cDsTempObj), json_object_get_string(cDsObj)) == 0)
										{
											ret = 1;
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
	}

	json_object_put(fileObj);

	return ret;
} /* End of cm_isUnavailableDs */

/*
========================================================================
Routine Description:
	Save final diversity state switch to file.

Arguments:
	timestamp	- timestamp
	mac		- mac
	bandUnit		- band unit

Return Value:
	None

Note:
========================================================================
*/
void cm_saveFinalDsSwitch(unsigned int timestamp, char *mac, int bandUnit, json_object *dsObj)
{
	json_object *resultObj = NULL, *macObj = NULL, *dsTmpObj = NULL, *bandUnitObj = NULL;
	int update = 0;
	char bandUnitStr[8] = {0};

	if (!mac) {
		DBG_ERR("[%d] mac is NULL", timestamp);
		return;
	}

	if (!dsObj) {
		DBG_ERR("[%d] dsObj is NULL", timestamp);
		return;
	}

	snprintf(bandUnitStr, sizeof(bandUnitStr), "%d", bandUnit);

	if ((resultObj = json_object_from_file(DS_SWITCH_RESULT_FILE))) {
		json_object_object_get_ex(resultObj, mac, &macObj);
		if (macObj) {
			if ((dsTmpObj = json_object_new_object())) {
				json_object_object_del(macObj, bandUnitStr);
				json_object_object_foreach(dsObj, dsKey, dsVal)
					json_object_object_add(dsTmpObj, dsKey, json_object_new_int(json_object_get_int(dsVal)));
				json_object_object_add(macObj, bandUnitStr, dsTmpObj);
				update = 1;
			}
			else
			{
				DBG_ERR("[%d] dsTmpObj is NULL", timestamp);
				json_object_put(dsTmpObj);
			}
		}
		else
		{
			if ((dsTmpObj = json_object_new_object()) && (bandUnitObj = json_object_new_object())) {
				json_object_object_foreach(dsObj, dsKey, dsVal)
					json_object_object_add(dsTmpObj, dsKey, json_object_new_int(json_object_get_int(dsVal)));
				json_object_object_add(bandUnitObj, bandUnitStr, dsTmpObj);
				json_object_object_add(resultObj, mac, bandUnitObj);
				update = 1;
			}
			else
			{
				DBG_ERR("[%d] dsTmpObj or bandUnitObj is NULL", timestamp);
				json_object_put(dsTmpObj);
				json_object_put(bandUnitObj);
			}
		}
	}
	else
	{
		if ((resultObj = json_object_new_object()) && (dsTmpObj = json_object_new_object())
			&& (bandUnitObj = json_object_new_object())) {
			json_object_object_foreach(dsObj, dsKey, dsVal)
				json_object_object_add(dsTmpObj, dsKey, json_object_new_int(json_object_get_int(dsVal)));
			json_object_object_add(bandUnitObj, bandUnitStr, dsTmpObj);
			json_object_object_add(resultObj, mac, bandUnitObj);
			update = 1;
		}
		else
		{
			DBG_ERR("[%d] resultObj or dsTmpObj or bandUnitObj is NULL", timestamp);
			json_object_put(dsTmpObj);
			json_object_put(bandUnitObj);
		}
	}

	/* update to file */
	if (update)
		json_object_to_file(DS_SWITCH_RESULT_FILE, resultObj);

	json_object_put(resultObj);
} /* End of cm_saveFinalDsSwitch */

/*
========================================================================
Routine Description:
	Revmoe final diversity state from file.

Arguments:
	timestamp	- timestamp
	mac		- mac
	bandUnit		- band unit

Return Value:
	None

Note:
========================================================================
*/
void cm_removeFinalDsFromFile(unsigned int timestamp, char *mac, int bandUnit)
{
	json_object *resultObj = NULL, *macObj = NULL, *bandUnitObj = NULL;
	int update = 0;
	char bandUnitStr[8] = {0};

	if (!mac) {
		DBG_ERR("[%d] mac is NULL", timestamp);
		return;
	}

	snprintf(bandUnitStr, sizeof(bandUnitStr), "%d", bandUnit);

	/* {"20:CF:30:00:AA:00":{"1":{"p0":1}},"20:CF:30:00:BB:00":{"1":{"p0":0}}} */
	if ((resultObj = json_object_from_file(DS_SWITCH_RESULT_FILE))) {
		json_object_object_get_ex(resultObj, mac, &macObj);
		if (macObj) {
			json_object_object_get_ex(macObj, bandUnitStr, &bandUnitObj);
			if (bandUnitObj) {
				DBG_LOG("[%d] remove final ds for %s, %d", timestamp, mac, bandUnit);
				json_object_object_del(macObj, bandUnitStr);
				update = 1;
			}
		}
	}

	/* update to file */
	if (update)
		json_object_to_file(DS_SWITCH_RESULT_FILE, resultObj);

	json_object_put(resultObj);
} /* End of cm_removeFinalDsFromFile */

/*
========================================================================
Routine Description:
	Update ads pair done.

Arguments:
	timestamp	- timestamp
	pMac		- mac for parent
	pUnit		- band unit for parent
	cMac		- mac for child
	cUnit		- band unit for child

Return Value:
	None

Note:
========================================================================
*/
void cm_updateAdsPairDone(unsigned int timestamp, char *pMac, int pUnit, char *cMac, int cUnit)
{
	json_object *fileObj = NULL, *pMacObj = NULL, *pUnitObj = NULL, *cMacObj = NULL, *cUnitObj = NULL;
	int update = 0;
	char unitStr[8];

	/* {"20:CF:30:00:AA:00":{"1":{"20:CF:30:00:BB:00":{"1":1}}}} */
	if ((fileObj = json_object_from_file(ADS_PAIR_DONE_FILE))) {
		json_object_object_get_ex(fileObj, pMac, &pMacObj);
		if (pMacObj) {
			snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
			json_object_object_get_ex(pMacObj, unitStr, &pUnitObj);

			if (pUnitObj) {
				cMacObj = NULL;
				json_object_object_foreach(pUnitObj, macKey, macVal) {
					if (strcmp(macKey, cMac) == 0) {
						cMacObj = macVal;
						break;
					}
				}

				if (cMacObj) {
					snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
					json_object_object_get_ex(cMacObj, unitStr, &cUnitObj);

					if (!cUnitObj) {
						snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
						json_object_object_add(cMacObj, unitStr, json_object_new_int(1));
						update = 1;
					}
				}
				else
				{
					if ((cMacObj = json_object_new_object())) {
						snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
						json_object_object_add(cMacObj, unitStr, json_object_new_int(1));
						json_object_object_add(pUnitObj, cMac, cMacObj);
						update = 1;
					}
				}
			}
			else
			{
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
						json_object_object_add(cMacObj, unitStr, json_object_new_int(1));
						json_object_object_add(pUnitObj, cMac, cMacObj);
						snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
						json_object_object_add(pMacObj, unitStr, pUnitObj);
						update = 1;
					}
					else
					{
						json_object_put(pUnitObj);
					}
				}
			}
		}
		else
		{
			if ((pMacObj = json_object_new_object())) {
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
						json_object_object_add(cMacObj, unitStr, json_object_new_int(1));
						json_object_object_add(pUnitObj, cMac, cMacObj);
						snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
						json_object_object_add(pMacObj, unitStr, pUnitObj);
						json_object_object_add(fileObj, pMac, pMacObj);
						update = 1;
					}
					else
					{
						json_object_put(pUnitObj);
						json_object_put(pMacObj);
					}
				}
				else
				{
					json_object_put(pMacObj);
				}
			}
		}
	}
	else
	{
		if ((fileObj = json_object_new_object())) {
			if ((pMacObj = json_object_new_object())) {
				if ((pUnitObj = json_object_new_object())) {
					if ((cMacObj = json_object_new_object())) {
						snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
						json_object_object_add(cMacObj, unitStr, json_object_new_int(1));
						json_object_object_add(pUnitObj, cMac, cMacObj);
						snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
						json_object_object_add(pMacObj, unitStr, pUnitObj);
						json_object_object_add(fileObj, pMac, pMacObj);
						update = 1;
					}
					else
					{
						json_object_put(pUnitObj);
						json_object_put(pMacObj);
					}
				}
				else
				{
					json_object_put(pMacObj);
				}
			}
		}
	}

	/* update to file */
	if (update)
		json_object_to_file(ADS_PAIR_DONE_FILE, fileObj);

	json_object_put(fileObj);
} /* End of cm_updateAdsPairDone */

/*
========================================================================
Routine Description:
	Check ads pair done ot not.

Arguments:
	timestamp	- timestamp
	pMac		- mac for parent
	pUnit		- band unit for parent
	cMac		- mac for child
	cUnit		- band unit for child

Return Value:
	-1		- error
	0		- is not ads done pair
	1		- is ads done pair

Note:
========================================================================
*/
int cm_isAdsPairDone(unsigned int timestamp, char *pMac, int pUnit, char *cMac, int cUnit)
{
	json_object *fileObj = NULL, *pMacObj = NULL, *pUnitObj = NULL, *cMacObj = NULL, *cUnitObj = NULL;
	int ret = 0;
	char unitStr[8];

	/* {"20:CF:30:00:AA:00":{"1":{"20:CF:30:00:BB:00":{"1":1}}}} */
	if ((fileObj = json_object_from_file(ADS_PAIR_DONE_FILE))) {
		json_object_object_get_ex(fileObj, pMac, &pMacObj);
		if (pMacObj) {
			snprintf(unitStr, sizeof(unitStr), "%d", pUnit);
			json_object_object_get_ex(pMacObj, unitStr, &pUnitObj);

			if (pUnitObj) {
				cMacObj = NULL;
				json_object_object_foreach(pUnitObj, macKey, macVal) {
					if (strcmp(macKey, cMac) == 0) {
						cMacObj = macVal;
						break;
					}
				}

				if (cMacObj) {
					snprintf(unitStr, sizeof(unitStr), "%d", cUnit);
					json_object_object_get_ex(cMacObj, unitStr, &cUnitObj);

					if (cUnitObj) {
						ret = 1;
					}
				}
			}
		}
	}

	json_object_put(fileObj);

	return ret;
} /* End of cm_isAdsPairDone */
