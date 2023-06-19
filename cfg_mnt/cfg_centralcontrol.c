#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_centralcontrol.h"
#include "cfg_param.h"

extern struct nvram_tuple router_defaults[];

/*
========================================================================
Routine Description:
	Get subfeature name by config parameter name.

Arguments:
	param		- config parameter name

Return Value:
	subfeature name
========================================================================
*/
char *cm_getSubfeatureByParam(char *param)
{
	struct param_mapping_s *pParam = NULL;
	struct subfeature_mapping_s *pSubFeature = NULL;
	static char subft[64];

	memset(subft, 0, sizeof(subft));

	for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
		if (strcmp(pParam->param, param) == 0) {
			for (pSubFeature = &subfeature_mapping_list[0]; pSubFeature->index != 0; pSubFeature++) {
				if (pParam->subfeature == pSubFeature->index) {
					strlcpy(subft, pSubFeature->name, sizeof(subft));
					break;
				}
			}
			break;
		}
	}

	return subft;
} /* End of cm_getSubfeatureByParam */

/*
========================================================================
Routine Description:
	Check subfeature exist in feature list or not.

Arguments:
	ft	- feature name
	ftList		- RE's feature list

Return Value:
	0		- doesn't exist in feature list
	1		- exist in feature list
========================================================================
*/
int cm_existInFeatureList(char *ft, json_object *ftList)
{
	int i = 0, ret = 0, ftListLen = 0;
	json_object *ftEntry = NULL;

	if (!ftList) {
		DBG_INFO("ftList is NULL");
		return 0;
	}

	ftListLen = json_object_array_length(ftList);
	for (i = 0; i < ftListLen; i++) {
		ftEntry = json_object_array_get_idx(ftList, i);
		if (ftEntry && strcmp(ft, json_object_get_string(ftEntry)) == 0) {
			ret = 1;
			break;
		}
	}

	return ret;
} /* End of cm_existInFeatureList */

/*
========================================================================
Routine Description:
	Transform cfg object to array obj.

Arguments:
	cfgObj		- config
	arrayObj		- array object

Return Value:
	-1		- error
	0		- not transform
	1		- transform
========================================================================
*/
int cm_transformCfgToArray(json_object *cfgObj, json_object *arrayObj)
{
	int ret = 0;
	json_object *paramObj = NULL;

	if (!cfgObj) {
		DBG_ERR("cfgObj is NULL");
		return -1;
	}

	if (!arrayObj) {
		DBG_ERR("arrayObj is NULL");
		return -1;
	}

	json_object_object_foreach(cfgObj, cfgKey, cfgVal) {
		paramObj = cfgVal;
		json_object_object_foreach(paramObj, paramKey, paramVal) {
			if (strcmp(paramKey, CFG_ACTION_SCRIPT) == 0)
				continue;
			json_object_array_add(arrayObj, json_object_new_string(paramKey));
			ret = 1;
		}
	}

	return ret;
} /* End of cm_transformCfgToArray */

/*
========================================================================
Routine Description:
	Update changed common config to RE's private config.

Arguments:
	mac			- slave's mac
	param		- changed parameter name

Return Value:
	-1		- error
	0               - not upate
	1               - update
========================================================================
*/
int cm_updateCommonConfigToPrivateByMac(char *mac, json_object *cfgObj)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL, *cfgArrayObj = NULL;
	char cfgTmpPath[64] = {0}, cfgMntPath[64] = {0}, param[64], value[128];
	int update = 0;
#ifdef RTCONFIG_AMAS_CAP_CONFIG
	int isCap = is_cap_by_mac(mac);
#endif

	if (!cfgObj) {
		DBG_ERR("cfgObj is NULL");
		return -1;
	}

#ifdef RTCONFIG_AMAS_CAP_CONFIG
	if (isCap == -1) {
		DBG_ERR("error for checking cap by mac");
		return -1;
	}

	if (isCap) {
		snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/cap.json");
		snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"cap.json");
	}
	else
#endif
	{
		snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", mac);
		snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", mac);
	}
	cfgFileObj = json_object_from_file(cfgTmpPath);
	cfgArrayObj = json_object_new_array();
	if (cfgFileObj && cfgArrayObj) {
		json_object_object_foreach(cfgObj, cfgKey, cfgVal) {
			memset(param, 0, sizeof(param));
			memset(value, 0, sizeof(value));
			strlcpy(param, cfgKey, sizeof(param));
			strlcpy(value, json_object_get_string(cfgVal), sizeof(value));
			DBG_INFO("param(%s) value(%s)", param, value);

			json_object_object_foreach(cfgFileObj, cfgFileKey, cfgFileVal) {
				json_object_object_get_ex(cfgFileVal, param, &paramObj);
				/* delete matched parameter first and then add new value */
				if (paramObj) {
					json_object_object_del(cfgFileVal, param);
					json_object_object_add(cfgFileVal, param, json_object_new_string(value));
					json_object_array_add(cfgArrayObj, json_object_new_string(param));
					DBG_INFO("update %s=%s", param, value);
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
#ifdef PRIVATE_SYNC_COMMON
		json_object_to_file(cfgTmpPath, cfgFileObj);
		json_object_to_file(cfgMntPath, cfgFileObj);
#endif
		cm_updatePrivateRuleByMac(mac, cfgArrayObj, FOLLOW_COMMON, RULE_UPDATE);
	}

	json_object_put(cfgFileObj);
	json_object_put(cfgArrayObj);

	return update;
} /* End of cm_updateCommonConfigToPrivateByMac */

/*
========================================================================
Routine Description:
	Update value to RE's private config.

Arguments:
	mac			- slave's mac
	param		- changed parameter name
	value		- changed parameter value

Return Value:
	-1		- error
	0               - not upate
	1               - update
========================================================================
*/
int cm_updateValueToPrivateByMac(char *mac, char *param, char *value)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL, *cfgArrayObj = NULL;
	char cfgTmpPath[64] = {0}, cfgMntPath[64] = {0};
	int update = 0;
#ifdef RTCONFIG_AMAS_CAP_CONFIG
	int isCap = is_cap_by_mac(mac);
#endif

	if (!param) {
		DBG_ERR("param is NULL");
		return -1;
	}

#ifdef RTCONFIG_AMAS_CAP_CONFIG
	if (isCap == -1) {
		DBG_ERR("error for checking cap by mac");
		return -1;
	}

	if (isCap) {
		snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/cap.json");
		snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"cap.json");
	}
	else
#endif
	{
		snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", mac);
		snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", mac);
	}
	cfgFileObj = json_object_from_file(cfgTmpPath);
	cfgArrayObj = json_object_new_array();
	if (cfgFileObj && cfgArrayObj) {
		json_object_object_foreach(cfgFileObj, cfgFileKey, cfgFileVal) {
			json_object_object_get_ex(cfgFileVal, param, &paramObj);
			/* delete matched parameter first and then add new value */
			if (paramObj) {
				json_object_object_del(cfgFileVal, param);
				json_object_object_add(cfgFileVal, param, json_object_new_string(value));
				json_object_array_add(cfgArrayObj, json_object_new_string(param));
				DBG_INFO("update %s=%s", param, value);
				update = 1;
			}
		}
	}

	/* update to file */
	if (update) {
		json_object_to_file(cfgTmpPath, cfgFileObj);
		json_object_to_file(cfgMntPath, cfgFileObj);
		cm_updatePrivateRuleByMac(mac, cfgArrayObj, FOLLOW_PRIVATE, RULE_UPDATE);
	}

	json_object_put(cfgFileObj);
	json_object_put(cfgArrayObj);

	return update;
} /* End of cm_updateValueToPrivateByMac */

/*
========================================================================
Routine Description:
	Update common config to RE's private config if it needed.

Arguments:
	mac		- RE's mac
	ftList		- RE's feature list
	cfgRoot		- json object for config

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_updateCommonToPrivateConfig(char *mac, unsigned char *ftList, json_object *cfgRoot)
{
	json_object *ftListObj = NULL, *ftObj = NULL, *priFtObj = NULL, *cfgObj = NULL;
	char param[64], subft[64];
	int ftExist = 0, subFtExist = 0, update = 0;
#ifdef RTCONFIG_AMAS_CAP_CONFIG
	int isCap = is_cap_by_mac(mac);
#endif
	char valueBuf[VALUE_BUF_MAX];
	json_object *commonObj = NULL;

	if (!ftList || strlen((char *)ftList) == 0) {
		DBG_INFO("ftList is NULL or empty");
		return -1;
	}

	if (!cfgRoot) {
		DBG_INFO("cfgRoot is null");
		return -1;
	}

#ifdef RTCONFIG_AMAS_CAP_CONFIG
	if (isCap == -1) {
		DBG_ERR("error for checking cap by mac");
		return -1;
	}
#endif
	commonObj = cm_getCommonObjFromCommonConfigFile();

	ftListObj = json_tokener_parse((char *)ftList);
	cfgObj = json_object_new_object();

	if (ftListObj && cfgObj && commonObj) {
		json_object_object_get_ex(ftListObj, CFG_STR_FEATURE, &ftObj);
		json_object_object_get_ex(ftListObj, CFG_STR_PRIVATE_FEATURE, &priFtObj);

		if (ftObj)
			DBG_INFO("ftObj(%s)", json_object_to_json_string_ext(ftObj, 0));
		if (priFtObj)
			DBG_INFO("priFtObj(%s)", json_object_to_json_string_ext(priFtObj, 0));

		json_object_object_foreach(cfgRoot, cfgRootKey, cfgRootVal) {
			strlcpy(param, cfgRootKey, sizeof(param));
			ftExist = subFtExist = 0;
			if (strcmp(param, CFG_ACTION_SCRIPT) == 0)
				continue;

			memset(subft, 0, sizeof(subft));
			strlcpy(subft, cm_getSubfeatureByParam(param), sizeof(subft));
			DBG_INFO("subft (%s)", subft);
			if (strlen(subft) > 0) {
				ftExist = cm_existInFeatureList(subft, ftObj);
				DBG_INFO("ftExist(%d)", ftExist);
				if (ftExist
#ifdef RTCONFIG_AMAS_CAP_CONFIG
					|| isCap
#endif
				) {	/* in common feature list */
					subFtExist = cm_existInFeatureList(subft, priFtObj);
					DBG_INFO("subFtExist(%d)", subFtExist);
					if (subFtExist) {	/* in private feature list */
						update = 1;
						json_object_object_add(cfgObj, param,
							json_object_new_string(cm_getStrValueFromCommonObj(commonObj, param, valueBuf, sizeof(valueBuf))));
					}
				}
			}
		}

		if (update)
			cm_updateCommonConfigToPrivateByMac(mac, cfgObj);
	}

	if (cfgObj) json_object_put(cfgObj);
	if (ftListObj) json_object_put(ftListObj);
	if (commonObj) json_object_put(commonObj);

	return update;
} /* End of cm_updateCommonToPrivateConfig */

/*
========================================================================
Routine Description:
	Update RE's private rule.

Arguments:
	mac			- slave's mac
	cfgObj		- config
	follow		- follow rule
	action		- action for rule

Return Value:
	-1		- error
	0		- not upate
	1		- update
========================================================================
*/
int cm_updatePrivateRuleByMac(char *mac, json_object *cfgObj, int follow, int action)
{
	json_object *ruleFileObj = NULL, *cfgEntry = NULL;
	char ruleMntPath[64];
	int update = 0, i = 0, cfgLen = 0;
#ifdef RTCONFIG_AMAS_CAP_CONFIG
	int isCap = is_cap_by_mac(mac);
#endif

	if (!cfgObj) {
		DBG_ERR("cfgObj is NULL");
		return -1;
	}

#ifdef RTCONFIG_AMAS_CAP_CONFIG
	if (isCap == -1) {
		DBG_ERR("error for checking cap by mac");
		return -1;
	}

	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", isCap? "cap": mac);
#else
	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", mac);
#endif
	ruleFileObj = json_object_from_file(ruleMntPath);

	if (ruleFileObj) {
		cfgLen = json_object_array_length(cfgObj);
		for (i = 0; i < cfgLen; i++) {
			if ((cfgEntry = json_object_array_get_idx(cfgObj, i))) {
				json_object_object_del(ruleFileObj, json_object_get_string(cfgEntry));
				if (action == RULE_ADD || action == RULE_UPDATE)
					json_object_object_add(ruleFileObj, json_object_get_string(cfgEntry), json_object_new_int(follow));
				update = 1;
			}
		}
	}
	else
	{
		if ((action == RULE_ADD || action == RULE_UPDATE) &&
			(ruleFileObj = json_object_new_object())) {
			cfgLen = json_object_array_length(cfgObj);
			for (i = 0; i < cfgLen; i++) {
				if ((cfgEntry = json_object_array_get_idx(cfgObj, i))) {
					json_object_object_add(ruleFileObj, json_object_get_string(cfgEntry), json_object_new_int(follow));
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
		json_object_to_file(ruleMntPath, ruleFileObj);
	}

	json_object_put(ruleFileObj);

	return update;
} /* End of cm_updatePrivateRuleByMac */

/*
========================================================================
Routine Description:
	Check the parameter of RE (mac) whether follow rule.

Arguments:
	mac			- RE's mac
	param		- parameter name
	rule		- follow rule
	
Return Value:
	-1		- error
	0		- not follow
	1		- follow
========================================================================
*/
int cm_checkParamFollowRule(char *mac, char *param, int rule)
{
	int ret = 0;
	json_object *ruleFileObj = NULL, *ruleObj = NULL;
	char ruleMntPath[64];
#ifdef RTCONFIG_AMAS_CAP_CONFIG
	int isCap = is_cap_by_mac(mac);

	if (isCap == -1) {
		DBG_ERR("error for checking cap by mac");
		return -1;
	}

	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", isCap? "cap": mac);
#else
	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", mac);
#endif

	if ((ruleFileObj = json_object_from_file(ruleMntPath))) {
		json_object_object_get_ex(ruleFileObj, param, &ruleObj);
		if (ruleObj) {
			if (json_object_get_int(ruleObj) == rule) {
				DBG_INFO("param(%s) match rule(%d) for mac(%s)", param, rule, mac);
				ret = 1;
			}
			else
				DBG_INFO("param(%s) is not match rule(%d) for mac(%s)", param, rule, mac);
		}
		else
			DBG_INFO("no rule on param(%s) for mac", param, mac);

		json_object_put(ruleFileObj);
	}

	return ret;
} /* End of cm_checkParamFollowRule */

/*
========================================================================
Routine Description:
	Update common config.

Arguments:
	
Return Value:
	-1		- error
	0		- not update
	1		- update
========================================================================
*/
int cm_updateCommonConfig()
{
	json_object *cfgFileObj = NULL, *paramObj = NULL, *paramEntry = NULL, *paramListObj = NULL;
	struct param_mapping_s *pParam = NULL;
	char cfgTmpPath[64] = {0}, cfgMntPath[64] = {0}, param[32];
	int i = 0, update = 0, paramLen = 0, needDel = 0, lock = 0;
	int totalBand = num_of_wl_if(), unit = -1, subunit = -1;

	snprintf(cfgTmpPath, sizeof(cfgTmpPath), TEMP_ROOT_PATH"/%s.json", COMMON_CONFIG);
	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", COMMON_CONFIG);

	lock = file_lock(COMMON_CONFIG_FILE_LOCK);
	if (strlen(cfgMntPath)){
		if (check_if_file_exist(cfgMntPath)) {	/* add/del config if needed */
			cfgFileObj = json_object_from_file(cfgMntPath);
			if (cfgFileObj ) {
				DBG_INFO("check & record parameter for add");
				if ((paramListObj = json_object_new_array())) {
					for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {	
						json_object_object_get_ex(cfgFileObj, pParam->param, &paramObj);
						if (!paramObj) {
							/* check wl parameter for valid band */
							if (strncmp(pParam->param, "wl", 2) == 0) {
								unit = subunit = -1;
								if (!strstr(pParam->param, "."))
									sscanf(pParam->param, "wl%d_%*s", &unit);
								else if (strstr(pParam->param, "."))
									sscanf(pParam->param, "wl%d.%d_%*s", &unit, &subunit);

								if (unit <= -1 || unit >= totalBand) {
									DBG_INFO("%s (%d) is invalid wl parameter, don't add", pParam->param, unit);
									continue;
								}
							}

							DBG_INFO("new parameter(%s) for add", pParam->param);
							json_object_array_add(paramListObj, json_object_new_string(pParam->param));
						}
					}

					paramLen = json_object_array_length(paramListObj);
					if (paramLen > 0) {
						for (i = 0; i < paramLen; i++) {
							if ((paramEntry = json_object_array_get_idx(paramListObj, i))) {
								strlcpy(param, json_object_get_string(paramEntry), sizeof(param));
								DBG_INFO("add parameter(%s) in cfgFileObj", param);

								/* update from default */
								for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
									if (strcmp(param, pParam->param) == 0) {
										/* need to get default */
										json_object_object_add(cfgFileObj, param, json_object_new_string(pParam->value));
										update = 1;
										break;
									}
								}

								/* update from nvram */
								if (nvram_get(param)) {
									DBG_INFO("update value from nvram for %s", param);
									json_object_object_add(cfgFileObj, param,
										json_object_new_string(nvram_safe_get(param)));
									update = 1;
								}
							}
						}
					}

					json_object_put(paramListObj);
				}

				DBG_INFO("check & record parameter for delete");
				if ((paramListObj = json_object_new_array())) {
					json_object_object_foreach(cfgFileObj, cfgKey, cfgVal) {
						needDel = 1;
						for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
							if (strcmp(cfgKey, pParam->param) == 0) {
								/* check wl parameter for valid band */
								if (strncmp(pParam->param, "wl", 2) == 0) {
									unit = subunit = -1;
									if (!strstr(pParam->param, "."))
										sscanf(pParam->param, "wl%d_%*s", &unit);
									else if (strstr(pParam->param, "."))
										sscanf(pParam->param, "wl%d.%d_%*s", &unit, &subunit);

									if (unit <= -1 || unit >= totalBand) {
										DBG_INFO("%s (%d) is invalid wl parameter, need delete", pParam->param, unit);
										continue;
									}
								}

								needDel = 0;
								break;
							}
						}

						if (needDel) {
							DBG_INFO("parameter(%s) for delete", cfgKey);
							json_object_array_add(paramListObj, json_object_new_string(cfgKey));
						}
					}

					paramLen = json_object_array_length(paramListObj);
					if (paramLen > 0) {
						for (i = 0; i < paramLen; i++) {
							if ((paramEntry = json_object_array_get_idx(paramListObj, i))) {
								strlcpy(param, json_object_get_string(paramEntry), sizeof(param));
								DBG_INFO("delete parameter(%s) in cfgFileObj", param);
								json_object_object_del(cfgFileObj, param);
								update = 1;
							}
						}
					}

					json_object_put(paramListObj);
				}
			}
		}
		else	/* no common config, need to generate it */
		{
			DBG_INFO("need to generate common config");
			cfgFileObj = json_object_new_object();
			if (cfgFileObj ) {
				for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
					strlcpy(param, pParam->param, sizeof(param));
					/* check wl parameter for valid band */
					if (strncmp(param, "wl", 2) == 0) {
						unit = subunit = -1;
						if (!strstr(param, "."))
							sscanf(param, "wl%d_%*s", &unit);
						else if (strstr(param, "."))
							sscanf(param, "wl%d.%d_%*s", &unit, &subunit);

						if (unit <= -1 || unit >= totalBand) {
							DBG_INFO("%s (%d) is invalid wl parameter, don't update", param, unit);
							continue;
						}
					}

					/* update from default */
					json_object_object_add(cfgFileObj, param, json_object_new_string(pParam->value));

					/* update from nvram */
					if (nvram_get(param)) {
						json_object_object_add(cfgFileObj, param, json_object_new_string(nvram_safe_get(param)));
						update = 1;
					}
				}
			}
			else
			{
				DBG_ERR("cfgFileObj is NULL");
				update = -1;
			}			
		}
	}
	else
	{
		DBG_ERR("cfgMntPath(%s) is invalid", cfgMntPath);
		return - 1;
	}

	/* update to file */
	if (update) {
		json_object_to_file(cfgTmpPath, cfgFileObj);
		json_object_to_file(cfgMntPath, cfgFileObj);
	}

	json_object_put(cfgFileObj);

	file_unlock(lock);

	return update;
} /* End of cm_updateCommonConfig */

#ifdef UPDATE_COMMON_CONFIG
/*
========================================================================
Routine Description:
	Update common config to file.

Arguments:
	cfgRoot		- json object for config

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_updateCommonConfigToFile(json_object *cfgRoot)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL;
	char cfgTmpPath[64], cfgMntPath[64], param[64];
	int update = 0;
	struct param_mapping_s *pParam = NULL;
	int updateFromVal = 0;
	int lock = 0;

	snprintf(cfgTmpPath, sizeof(cfgTmpPath), TEMP_ROOT_PATH"/%s.json", COMMON_CONFIG);
	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", COMMON_CONFIG);


	lock = file_lock(COMMON_CONFIG_FILE_LOCK);
	pthread_mutex_lock(&commonFileLock);
	cfgFileObj = json_object_from_file(cfgTmpPath);
	if (cfgFileObj) {
		if (cfgRoot) {	/* update for special based on cfgRoot */
			DBG_INFO("update for special based on cfgRoot");
			json_object_object_foreach(cfgRoot, cfgKey, cfgVal) {
				strlcpy(param, cfgKey, sizeof(param));
				updateFromVal = 0;
				if (strlen(json_object_get_string(cfgVal)) > 0)
					updateFromVal = 1;
				json_object_object_get_ex(cfgFileObj, param, &paramObj);
				if (paramObj) {
					DBG_INFO("update value(%s) for %s",
						updateFromVal? json_object_get_string(cfgVal): nvram_safe_get(param), param);
					json_object_object_add(cfgFileObj, param,
						json_object_new_string(updateFromVal? json_object_get_string(cfgVal): nvram_safe_get(param)));
					update = 1;
				}
			}
		}
		else	/* update for all */
		{
			DBG_INFO("update for all");
			for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
				strlcpy(param, pParam->param, sizeof(param));
				json_object_object_get_ex(cfgFileObj, param, &paramObj);
				if (paramObj && nvram_get(param) &&
					strcmp(nvram_safe_get(param), json_object_get_string(paramObj)) != 0) {
					DBG_INFO("update value(%s) for %s", nvram_safe_get(param), param);
					json_object_object_add(cfgFileObj, param,
						json_object_new_string(nvram_safe_get(param)));
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
		json_object_to_file(cfgTmpPath, cfgFileObj);
		json_object_to_file(cfgMntPath, cfgFileObj);
	}

	pthread_mutex_unlock(&commonFileLock);
	file_unlock(lock);

	json_object_put(cfgFileObj);

	return update;
} /* End of cm_updateCommonConfigToFile */

/*
========================================================================
Routine Description:
	Update value to common config file.

Arguments:
	param		- parameter name
	value		- parameter value

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_updateValueToConfigFile(char *param, char *value)
{
	json_object *paramObj = NULL;
	int update = 0, isPrivateUpdate = 0;

	if (nvram_get_int("re_mode") == 1)
		return 1;

#ifdef RTCONFIG_AMAS_CAP_CONFIG
	isPrivateUpdate = cm_updateValueToPrivateByMac(get_unique_mac(), param, value);
#endif

	if (isPrivateUpdate != 1) {
		if ((paramObj = json_object_new_object())) {
			json_object_object_add(paramObj, param, json_object_new_string(value));
			update = cm_updateCommonConfigToFile(paramObj);
			json_object_put(paramObj);
		}
	}

	return update;
} /* End of cm_updateValueToCommonConfigFile */
#endif

/*
========================================================================
Routine Description:
	Get value from common config file.

Arguments:
	name	- name
	valueBuf	- value buf
	valueBufLen	- the length of valueBuf buf

Return Value:
	value		- value
========================================================================
*/
char *cm_getValueFromCommonConfig(const char *name, char *valueBuf, int valueBufLen)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL;
	char cfgTmpPath[64];
#ifdef RTCONFIG_NVRAM_ENCRYPT
	struct nvram_tuple *t = NULL;
	char decBuf[NVRAM_ENC_MAXLEN] = {0};
	int decrypted = 0;
#endif
	int lock = 0;

	if (valueBuf == NULL) {
		DBG_ERR("valueBuf is NULL");
		return "";
	}

	memset(valueBuf, 0, valueBufLen);

	lock = file_lock(COMMON_CONFIG_FILE_LOCK);
	pthread_mutex_lock(&commonFileLock);
	snprintf(cfgTmpPath, sizeof(cfgTmpPath), TEMP_ROOT_PATH"/%s.json", COMMON_CONFIG);
	if ((cfgFileObj = json_object_from_file(cfgTmpPath)) != NULL) {
		json_object_object_get_ex(cfgFileObj, name, &paramObj);
		if (paramObj) {
#ifdef RTCONFIG_NVRAM_ENCRYPT
			/* go through each nvram value */
			for (t = router_defaults; t->name; t++) {
				if (strcmp(name, t->name) == 0 && t->enc == CKN_ENC_SVR) {
					pw_dec(json_object_get_string(paramObj), decBuf, sizeof(decBuf), 1);
					decrypted = 1;
					break;
				}
			}

			if (decrypted)
				strlcpy(valueBuf, decBuf, sizeof(valueBuf));
			else
				strlcpy(valueBuf, json_object_get_string(paramObj), sizeof(valueBuf));
#else
			strlcpy(valueBuf, json_object_get_string(paramObj), sizeof(valueBuf));
#endif
		}
		else
			strlcpy(valueBuf, "", sizeof(valueBuf));

		json_object_put(cfgFileObj);
	}

	pthread_mutex_unlock(&commonFileLock);
	file_unlock(lock);

	return valueBuf;
} /* End of cm_getValueFromCommonConfig */

/*
========================================================================
Routine Description:
	Get common object from common config file.

Arguments:
	None

Return Value:
	common object
========================================================================
*/
json_object *cm_getCommonObjFromCommonConfigFile()
{
	json_object *cfgFileObj = NULL;
	char cfgTmpPath[64];
	int lock = 0;

	snprintf(cfgTmpPath, sizeof(cfgTmpPath), TEMP_ROOT_PATH"/%s.json", COMMON_CONFIG);

	lock = file_lock(COMMON_CONFIG_FILE_LOCK);
	pthread_mutex_lock(&commonFileLock);

	cfgFileObj = json_object_from_file(cfgTmpPath);

	pthread_mutex_unlock(&commonFileLock);
	file_unlock(lock);

	return cfgFileObj;
} /* End of cm_getCommonObjFromCommonConfigFile */

/*
========================================================================
Routine Description:
	Get string value from common config of ram.

Arguments:
	commonObj	- json object for common config
	name	- name
	valueBuf	- value buf
	valueBufLen	- the length of valueBuf buf

Return Value:
	string value
========================================================================
*/
char *cm_getStrValueFromCommonObj(json_object *commonObj, const char *name, char *valueBuf, int valueBufLen)
{
	json_object *paramObj = NULL;
#ifdef RTCONFIG_NVRAM_ENCRYPT
	struct nvram_tuple *t = NULL;
	char decBuf[NVRAM_ENC_MAXLEN] = {0};
	int decrypted = 0;
#endif

	if (commonObj != NULL) {
		json_object_object_get_ex(commonObj, name, &paramObj);
		if (paramObj) {
#ifdef RTCONFIG_NVRAM_ENCRYPT
			/* go through each nvram value */
			for (t = router_defaults; t->name; t++) {
				if (strcmp(name, t->name) == 0 && t->enc == CKN_ENC_SVR) {
					pw_dec(json_object_get_string(paramObj), decBuf, sizeof(decBuf), 1);
					decrypted = 1;
					break;
				}
			}

			if (decrypted)
				strlcpy(valueBuf, decBuf, valueBufLen);
			else
				strlcpy(valueBuf, json_object_get_string(paramObj), valueBufLen);
#else
			strlcpy(valueBuf, json_object_get_string(paramObj), valueBufLen);
#endif
		}
		else
			strlcpy(valueBuf, "", valueBufLen);

		return valueBuf;
	}

	return "";
} /* End of cm_getStrValueFromCommonObj */

/*
========================================================================
Routine Description:
	Get integer value from common config of ram.

Arguments:
	commonObj	- json object for common config
	name	- name

Return Value:
	integer value
========================================================================
*/
int cm_getIntValueFromCommonObj(json_object *commonObj, const char *name)
{
	json_object *paramObj = NULL;
	int ret = 0;

	if (commonObj != NULL) {
		json_object_object_get_ex(commonObj, name, &paramObj);
		if (paramObj)
			ret = atoi(json_object_get_string(paramObj));
	}

	return ret;
} /* End of cm_getIntValueFromCommonObj */

/*
========================================================================
Routine Description:
	Check the parameter exist or not from common config of ram.

Arguments:
	commonObj	- json object for common config
	name	- name

Return Value:
	integer value
========================================================================
*/
int cm_isParamExistInCommonObj(json_object *commonObj, const char *name)
{
	json_object *paramObj = NULL;
	int ret = 0;

	if (commonObj != NULL) {
		json_object_object_get_ex(commonObj, name, &paramObj);
		if (paramObj)
			ret = 1;
	}

	return ret;
} /* End of cm_isParamExistInCommonObj */

#ifdef RTCONFIG_AMAS_CAP_CONFIG
/*
========================================================================
Routine Description:
	Add config from common config file by feature list.

Arguments:
	inRoot		- feature list
	outRoot		- the transform value based on feature

Return Value:
	None
========================================================================
*/
void cm_addConfigFromCommonFileByFeature(json_object *inRoot, json_object *outRoot)
{
	struct feature_mapping_s *pFeature = NULL;
	struct subfeature_mapping_s *pSubFeature = NULL;
	struct param_mapping_s *pParam = NULL;
	json_object *ftListObj = NULL, *paramObj = NULL, *ftEntry = NULL;
	int i = 0, ftListLen = 0;
	char valueBuf[VALUE_BUF_MAX];
	json_object *commonObj = NULL;

	json_object_object_get_ex(inRoot, CFG_STR_PRIVATE_FEATURE, &ftListObj);
	if (ftListObj) {
		ftListLen = json_object_array_length(ftListObj);
		commonObj = cm_getCommonObjFromCommonConfigFile();
		for (pFeature = &feature_mapping_list[0]; pFeature->index != 0; pFeature++) {
			paramObj = NULL;

			for (pSubFeature = &subfeature_mapping_list[0]; pSubFeature->index != 0; pSubFeature++) {
				if (pFeature->index == pSubFeature->feature) {
					for (i = 0; i < ftListLen; i++) {
						ftEntry = json_object_array_get_idx(ftListObj, i);

						if (!strcmp(pSubFeature->name, json_object_get_string(ftEntry))) {

							for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
								if (pSubFeature->index == pParam->subfeature) {
									if (!paramObj)
										paramObj = json_object_new_object();

									if (paramObj) {
										json_object_object_add(paramObj, pParam->param,
											json_object_new_string(cm_getStrValueFromCommonObj(commonObj, pParam->param, valueBuf, sizeof(valueBuf))));
									}
								}
							}
						}
					}
				}
			}

			if (paramObj) {
				if (pFeature->service)
					json_object_object_add(paramObj, CFG_ACTION_SCRIPT,
						json_object_new_string(pFeature->service));
				json_object_object_add(outRoot, pFeature->name, paramObj);
			}
		}
	}

	if (commonObj) json_object_put(commonObj);
} /* End of cm_addConfigFromCommonFileByFeature */
#endif
